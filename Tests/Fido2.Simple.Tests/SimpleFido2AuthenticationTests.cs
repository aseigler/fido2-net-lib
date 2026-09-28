using Fido2NetLib.Objects;

using Microsoft.Extensions.DependencyInjection;

using Moq;

namespace Fido2NetLib.Simple.Tests;

/// <summary>
/// Covers <see cref="SimpleFido2Authentication"/>'s own plumbing -- what it calls on <see cref="IFido2"/> and
/// <see cref="ICredentialStore"/>, with what arguments, how it maps results, and its defaults/overrides -- against
/// mocks of both. No real cryptography or storage is involved; that is <see cref="IFido2"/>'s and each
/// <see cref="ICredentialStore"/> implementation's own, separately tested, responsibility.
/// </summary>
public sealed class SimpleFido2AuthenticationTests
{
    private static Fido2User NewUser(string name, byte id) => new() { Name = name, Id = [id], DisplayName = name.ToUpperInvariant() };

    private static StoredCredential NewStoredCredential(byte[]? id = null, byte[]? userHandle = null, uint signCount = 0, bool? backupEligible = null) => new()
    {
        Id = id ?? Guid.NewGuid().ToByteArray(),
        PublicKey = [1, 2, 3],
        SignCount = signCount,
        Transports = [AuthenticatorTransport.Internal],
        UserHandle = userHandle ?? Guid.NewGuid().ToByteArray(),
        AttestationFormat = "none",
        RegDate = DateTimeOffset.UtcNow,
        AaGuid = Guid.NewGuid(),
        IsBackupEligible = backupEligible ?? false,
    };

    private static CredentialCreateOptions NewCredentialCreateOptions(Fido2User user) => new()
    {
        Rp = new PublicKeyCredentialRpEntity("example.com", "Example"),
        User = user,
        Challenge = [1, 2, 3, 4],
        PubKeyCredParams = PubKeyCredParam.Defaults,
    };

    private static RegisteredPublicKeyCredential NewRegistered(byte[] id) => new()
    {
        Id = id,
        RpId = "example.com",
        PublicKey = [9, 8, 7],
        Transports = [AuthenticatorTransport.Internal],
        SignCount = 0,
        UvInitialized = true,
        IsBackupEligible = true,
        IsBackedUp = false,
        AttestationObject = [1],
        AttestationClientDataJson = [2],
        AttestationFormat = "none",
        AaGuid = Guid.NewGuid(),
        User = NewUser("alice", 1),
        AttestationType = "none",
    };

    private static (Mock<IFido2> Fido2, Mock<ICredentialStore> Store, SimpleFido2Authentication Facade) NewSut()
    {
        var fido2 = new Mock<IFido2>();
        var store = new Mock<ICredentialStore>();
        return (fido2, store, new SimpleFido2Authentication(fido2.Object, store.Object));
    }

    // --- InitiateRegistrationAsync ------------------------------------------------------------------------------

    private static void SetupRequestNewCredential(Mock<IFido2> fido2, Action<RequestNewCredentialParams>? capture = null) =>
        fido2.Setup(f => f.RequestNewCredential(It.IsAny<RequestNewCredentialParams>()))
            .Returns((RequestNewCredentialParams p) => { capture?.Invoke(p); return NewCredentialCreateOptions(p.User); });

    [Fact]
    public async Task InitiateRegistrationAsync_RejectsNullOrEmptyUsernameAsync()
    {
        var (_, _, facade) = NewSut();

        await Assert.ThrowsAsync<ArgumentException>(() => facade.InitiateRegistrationAsync(""));
        await Assert.ThrowsAsync<ArgumentNullException>(() => facade.InitiateRegistrationAsync(null!));
    }

    [Fact]
    public async Task InitiateRegistrationAsync_OffersANewUserWithARandomHandleWithoutStoringItYetAsync()
    {
        var (fido2, store, facade) = NewSut();
        store.Setup(s => s.GetUserAsync("alice", It.IsAny<CancellationToken>())).ReturnsAsync((Fido2User?)null);
        RequestNewCredentialParams? captured = null;
        SetupRequestNewCredential(fido2, p => captured = p);

        var options = await facade.InitiateRegistrationAsync("alice", "Alice A.");

        Assert.Equal("alice", options.User.Name);
        Assert.Equal("Alice A.", options.User.DisplayName);
        Assert.Equal(32, options.User.Id.Length);
        Assert.Empty(captured!.ExcludeCredentials);

        // Created by CompleteRegistrationAsync once a credential verifies, so an abandoned sign-up leaves no account.
        store.Verify(s => s.GetOrAddUserAsync(It.IsAny<string>(), It.IsAny<Func<Fido2User>>(), It.IsAny<CancellationToken>()), Times.Never());
        store.Verify(s => s.AddCredentialToUserAsync(It.IsAny<Fido2User>(), It.IsAny<StoredCredential>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task InitiateRegistrationAsync_DefaultsDisplayNameToUsernameAsync()
    {
        var (fido2, _, facade) = NewSut();
        SetupRequestNewCredential(fido2);

        var options = await facade.InitiateRegistrationAsync("bob");

        Assert.Equal("bob", options.User.DisplayName);
    }

    [Fact]
    public async Task InitiateRegistrationAsync_RefusesAnAccountThatAlreadyExistsAsync()
    {
        // Signing up must not be a way to add a passkey to someone else's account by entering its username.
        var (fido2, store, facade) = NewSut();
        store.Setup(s => s.GetUserAsync("carol", It.IsAny<CancellationToken>())).ReturnsAsync(NewUser("carol", 3));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => facade.InitiateRegistrationAsync("carol"));

        Assert.Contains(nameof(ISimpleFido2Authentication.InitiateAddCredentialAsync), ex.Message);
        fido2.Verify(f => f.RequestNewCredential(It.IsAny<RequestNewCredentialParams>()), Times.Never());
    }

    [Fact]
    public async Task InitiateRegistrationAsync_AppliesDefaultsWhenNoOptionsAreGivenAsync()
    {
        var (fido2, _, facade) = NewSut();
        RequestNewCredentialParams? captured = null;
        SetupRequestNewCredential(fido2, p => captured = p);

        await facade.InitiateRegistrationAsync("dave");

        Assert.Equal(AttestationConveyancePreference.None, captured!.AttestationPreference);
        Assert.Equal(PubKeyCredParam.Defaults, captured.PubKeyCredParams);
        Assert.Equal(AuthenticatorSelection.Default.ResidentKey, captured.AuthenticatorSelection.ResidentKey);
    }

    [Fact]
    public async Task InitiateRegistrationAsync_LetsCallerOverrideTheDefaultsAsync()
    {
        var (fido2, _, facade) = NewSut();
        RequestNewCredentialParams? captured = null;
        SetupRequestNewCredential(fido2, p => captured = p);
        var overriddenParams = new[] { PubKeyCredParam.ES256 };

        await facade.InitiateRegistrationAsync("erin", options: new SimpleRegistrationOptions
        {
            AttestationPreference = AttestationConveyancePreference.Direct,
            PubKeyCredParams = overriddenParams,
        });

        Assert.Equal(AttestationConveyancePreference.Direct, captured!.AttestationPreference);
        Assert.Same(overriddenParams, captured.PubKeyCredParams);
    }

    // --- InitiateAddCredentialAsync -----------------------------------------------------------------------------

    [Fact]
    public async Task InitiateAddCredentialAsync_RejectsNullOrEmptyUsernameAsync()
    {
        var (_, _, facade) = NewSut();

        await Assert.ThrowsAsync<ArgumentException>(() => facade.InitiateAddCredentialAsync(""));
        await Assert.ThrowsAsync<ArgumentNullException>(() => facade.InitiateAddCredentialAsync(null!));
    }

    [Fact]
    public async Task InitiateAddCredentialAsync_UsesTheExistingAccountAndExcludesItsCredentialsAsync()
    {
        var (fido2, store, facade) = NewSut();
        var user = NewUser("carol", 3);
        var existing = new[] { NewStoredCredential(), NewStoredCredential() };
        store.Setup(s => s.GetUserAsync("carol", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        store.Setup(s => s.GetCredentialsByUserAsync(user, It.IsAny<CancellationToken>())).ReturnsAsync(existing.ToList());
        RequestNewCredentialParams? captured = null;
        SetupRequestNewCredential(fido2, p => captured = p);

        var options = await facade.InitiateAddCredentialAsync("carol", new SimpleRegistrationOptions { AttestationPreference = AttestationConveyancePreference.Direct });

        Assert.Same(user, options.User);
        Assert.Equal(AttestationConveyancePreference.Direct, captured!.AttestationPreference);
        Assert.Equal(2, captured.ExcludeCredentials.Count);
        Assert.Contains(captured.ExcludeCredentials, d => d.Id.SequenceEqual(existing[0].Id));
        Assert.Contains(captured.ExcludeCredentials, d => d.Id.SequenceEqual(existing[1].Id));
        store.Verify(s => s.GetOrAddUserAsync(It.IsAny<string>(), It.IsAny<Func<Fido2User>>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task InitiateAddCredentialAsync_UnknownAccountThrowsAsync()
    {
        var (fido2, store, facade) = NewSut();
        store.Setup(s => s.GetUserAsync("ghost", It.IsAny<CancellationToken>())).ReturnsAsync((Fido2User?)null);

        await Assert.ThrowsAsync<InvalidOperationException>(() => facade.InitiateAddCredentialAsync("ghost"));
        fido2.Verify(f => f.RequestNewCredential(It.IsAny<RequestNewCredentialParams>()), Times.Never());
    }

    // --- CompleteRegistrationAsync ------------------------------------------------------------------------------

    [Fact]
    public async Task CompleteRegistrationAsync_RejectsNullArgumentsAsync()
    {
        var (_, _, facade) = NewSut();
        var options = NewCredentialCreateOptions(NewUser("frank", 6));

        await Assert.ThrowsAsync<ArgumentNullException>(() => facade.CompleteRegistrationAsync(null!, new AuthenticatorAttestationRawResponse()));
        await Assert.ThrowsAsync<ArgumentNullException>(() => facade.CompleteRegistrationAsync(options, null!));
    }

    [Fact]
    public async Task CompleteRegistrationAsync_MapsEveryFieldIntoTheStoredCredentialAsync()
    {
        var (fido2, store, facade) = NewSut();
        var user = NewUser("grace", 7);
        store.Setup(s => s.GetUserAsync("grace", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        var originalOptions = NewCredentialCreateOptions(user);
        var registered = NewRegistered(Guid.NewGuid().ToByteArray());
        fido2.Setup(f => f.MakeNewCredentialAsync(It.IsAny<MakeNewCredentialParams>(), It.IsAny<CancellationToken>())).ReturnsAsync(registered);
        StoredCredential? saved = null;
        store.Setup(s => s.AddCredentialToUserAsync(user, It.IsAny<StoredCredential>(), It.IsAny<CancellationToken>()))
            .Callback((Fido2User _, StoredCredential c, CancellationToken _) => saved = c)
            .Returns(Task.CompletedTask);
        var attestationResponse = new AuthenticatorAttestationRawResponse
        {
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs { CredProps = new CredentialPropertiesOutput { Rk = true } },
        };

        var returnedUser = await facade.CompleteRegistrationAsync(originalOptions, attestationResponse);

        Assert.Same(user, returnedUser);
        Assert.NotNull(saved);
        Assert.Equal(registered.Id, saved!.Id);
        Assert.Equal(registered.RpId, saved.RpId);
        Assert.Equal(registered.PublicKey, saved.PublicKey);
        Assert.Equal(registered.Transports, saved.Transports);
        Assert.Equal(registered.SignCount, saved.SignCount);
        Assert.Equal(registered.UvInitialized, saved.UvInitialized);
        Assert.Equal(registered.IsBackupEligible, saved.IsBackupEligible);
        Assert.Equal(registered.IsBackedUp, saved.IsBackedUp);
        Assert.Equal(registered.AttestationObject, saved.AttestationObject);
        Assert.Equal(registered.AttestationClientDataJson, saved.AttestationClientDataJson);
        Assert.Equal(registered.AttestationFormat, saved.AttestationFormat);
        Assert.Equal(registered.AaGuid, saved.AaGuid);
        Assert.Equal(user.Id, saved.UserId);
        Assert.Equal(user.Id, saved.UserHandle);
        Assert.True(saved.IsDiscoverable);
    }

    [Fact]
    public async Task CompleteRegistrationAsync_LeavesIsDiscoverableNullWithNoClientExtensionResultsAsync()
    {
        var (fido2, store, facade) = NewSut();
        var user = NewUser("heidi", 8);
        store.Setup(s => s.GetUserAsync("heidi", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        var originalOptions = NewCredentialCreateOptions(user);
        fido2.Setup(f => f.MakeNewCredentialAsync(It.IsAny<MakeNewCredentialParams>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(NewRegistered(Guid.NewGuid().ToByteArray()));
        StoredCredential? saved = null;
        store.Setup(s => s.AddCredentialToUserAsync(user, It.IsAny<StoredCredential>(), It.IsAny<CancellationToken>()))
            .Callback((Fido2User _, StoredCredential c, CancellationToken _) => saved = c)
            .Returns(Task.CompletedTask);

        await facade.CompleteRegistrationAsync(originalOptions, new AuthenticatorAttestationRawResponse());

        Assert.Null(saved!.IsDiscoverable);
    }

    [Fact]
    public async Task CompleteRegistrationAsync_LeavesIsDiscoverableNullWithNoCredPropsAsync()
    {
        var (fido2, store, facade) = NewSut();
        var user = NewUser("ike", 15);
        store.Setup(s => s.GetUserAsync("ike", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        var originalOptions = NewCredentialCreateOptions(user);
        fido2.Setup(f => f.MakeNewCredentialAsync(It.IsAny<MakeNewCredentialParams>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(NewRegistered(Guid.NewGuid().ToByteArray()));
        StoredCredential? saved = null;
        store.Setup(s => s.AddCredentialToUserAsync(user, It.IsAny<StoredCredential>(), It.IsAny<CancellationToken>()))
            .Callback((Fido2User _, StoredCredential c, CancellationToken _) => saved = c)
            .Returns(Task.CompletedTask);
        // ClientExtensionResults is present (some other extension fired), but credProps specifically did not --
        // a different code path through the null-conditional chain than "no ClientExtensionResults at all".
        var attestationResponse = new AuthenticatorAttestationRawResponse
        {
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs(),
        };

        await facade.CompleteRegistrationAsync(originalOptions, attestationResponse);

        Assert.Null(saved!.IsDiscoverable);
    }

    [Fact]
    public async Task CompleteRegistrationAsync_UniquenessCallbackQueriesTheStoreAsync()
    {
        var (fido2, store, facade) = NewSut();
        var credentialId = Guid.NewGuid().ToByteArray();
        var registered = NewRegistered(credentialId);
        var originalOptions = NewCredentialCreateOptions(registered.User);
        store.Setup(s => s.GetUserAsync(registered.User.Name, It.IsAny<CancellationToken>())).ReturnsAsync(registered.User);
        IsCredentialIdUniqueToUserAsyncDelegate? callback = null;
        fido2.Setup(f => f.MakeNewCredentialAsync(It.IsAny<MakeNewCredentialParams>(), It.IsAny<CancellationToken>()))
            .Callback((MakeNewCredentialParams p, CancellationToken _) => callback = p.IsCredentialIdUniqueToUserCallback)
            .ReturnsAsync(registered);
        store.Setup(s => s.AddCredentialToUserAsync(It.IsAny<Fido2User>(), It.IsAny<StoredCredential>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        store.Setup(s => s.GetUsersByCredentialIdAsync(credentialId, It.IsAny<CancellationToken>())).ReturnsAsync([]);

        await facade.CompleteRegistrationAsync(originalOptions, new AuthenticatorAttestationRawResponse());

        Assert.NotNull(callback);
        var isUnique = await callback!(new IsCredentialIdUniqueToUserParams(credentialId, registered.User), CancellationToken.None);
        Assert.True(isUnique);

        store.Setup(s => s.GetUsersByCredentialIdAsync(credentialId, It.IsAny<CancellationToken>())).ReturnsAsync([NewUser("someoneElse", 99)]);
        Assert.False(await callback(new IsCredentialIdUniqueToUserParams(credentialId, registered.User), CancellationToken.None));
    }

    [Fact]
    public async Task CompleteRegistrationAsync_CreatesTheSignedUpAccountOnlyOnceTheCredentialVerifiesAsync()
    {
        var (fido2, store, facade) = NewSut();
        var newUser = NewUser("judy", 16);
        var originalOptions = NewCredentialCreateOptions(newUser);
        fido2.Setup(f => f.MakeNewCredentialAsync(It.IsAny<MakeNewCredentialParams>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(NewRegistered(Guid.NewGuid().ToByteArray()));
        store.Setup(s => s.GetUserAsync("judy", It.IsAny<CancellationToken>())).ReturnsAsync((Fido2User?)null);
        store.Setup(s => s.GetOrAddUserAsync("judy", It.IsAny<Func<Fido2User>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string _, Func<Fido2User> addCallback, CancellationToken _) => addCallback());
        StoredCredential? saved = null;
        store.Setup(s => s.AddCredentialToUserAsync(newUser, It.IsAny<StoredCredential>(), It.IsAny<CancellationToken>()))
            .Callback((Fido2User _, StoredCredential c, CancellationToken _) => saved = c)
            .Returns(Task.CompletedTask);

        var returned = await facade.CompleteRegistrationAsync(originalOptions, new AuthenticatorAttestationRawResponse());

        Assert.Same(newUser, returned);
        Assert.Equal(newUser.Id, saved!.UserHandle);
        store.Verify(s => s.GetOrAddUserAsync("judy", It.IsAny<Func<Fido2User>>(), It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task CompleteRegistrationAsync_StoresNothingWhenTheResponseDoesNotVerifyAsync()
    {
        var (fido2, store, facade) = NewSut();
        var originalOptions = NewCredentialCreateOptions(NewUser("kim", 17));
        fido2.Setup(f => f.MakeNewCredentialAsync(It.IsAny<MakeNewCredentialParams>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Fido2VerificationException("bad"));

        await Assert.ThrowsAsync<Fido2VerificationException>(() => facade.CompleteRegistrationAsync(originalOptions, new AuthenticatorAttestationRawResponse()));

        store.Verify(s => s.GetOrAddUserAsync(It.IsAny<string>(), It.IsAny<Func<Fido2User>>(), It.IsAny<CancellationToken>()), Times.Never());
        store.Verify(s => s.AddCredentialToUserAsync(It.IsAny<Fido2User>(), It.IsAny<StoredCredential>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Theory]
    [InlineData(true)]  // the name was taken by someone else after this sign-up began
    [InlineData(false)] // a concurrent sign-up for the same name created it first
    public async Task CompleteRegistrationAsync_RefusesWhenTheNamedAccountIsNotTheOneTheCeremonyWasForAsync(bool existsAlready)
    {
        // The options carry the user handle the ceremony was started for. Attaching the credential to whichever
        // account holds the name now would hand that account to whoever completed this ceremony.
        var (fido2, store, facade) = NewSut();
        var ceremonyUser = NewUser("lena", 18);
        var otherAccount = NewUser("lena", 19);
        fido2.Setup(f => f.MakeNewCredentialAsync(It.IsAny<MakeNewCredentialParams>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(NewRegistered(Guid.NewGuid().ToByteArray()));
        store.Setup(s => s.GetUserAsync("lena", It.IsAny<CancellationToken>())).ReturnsAsync(existsAlready ? otherAccount : null);
        store.Setup(s => s.GetOrAddUserAsync("lena", It.IsAny<Func<Fido2User>>(), It.IsAny<CancellationToken>())).ReturnsAsync(otherAccount);

        await Assert.ThrowsAsync<InvalidOperationException>(() => facade.CompleteRegistrationAsync(NewCredentialCreateOptions(ceremonyUser), new AuthenticatorAttestationRawResponse()));

        store.Verify(s => s.AddCredentialToUserAsync(It.IsAny<Fido2User>(), It.IsAny<StoredCredential>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    // --- InitiateAuthenticationAsync ----------------------------------------------------------------------------

    [Fact]
    public async Task InitiateAuthenticationAsync_WithAKnownUsernamePopulatesAllowedCredentialsAsync()
    {
        var (fido2, store, facade) = NewSut();
        var user = NewUser("ivan", 9);
        var creds = new List<StoredCredential> { NewStoredCredential(), NewStoredCredential() };
        store.Setup(s => s.GetUserAsync("ivan", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        store.Setup(s => s.GetCredentialsByUserAsync(user, It.IsAny<CancellationToken>())).ReturnsAsync(creds);
        GetAssertionOptionsParams? captured = null;
        fido2.Setup(f => f.GetAssertionOptions(It.IsAny<GetAssertionOptionsParams>()))
            .Returns((GetAssertionOptionsParams p) => { captured = p; return new AssertionOptions(); });

        await facade.InitiateAuthenticationAsync("ivan");

        Assert.Equal(2, captured!.AllowedCredentials.Count);
    }

    [Fact]
    public async Task InitiateAuthenticationAsync_UnknownUsernameThrowsAsync()
    {
        var (_, store, facade) = NewSut();
        store.Setup(s => s.GetUserAsync("ghost", It.IsAny<CancellationToken>())).ReturnsAsync((Fido2User?)null);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => facade.InitiateAuthenticationAsync("ghost"));
        Assert.Contains("ghost", ex.Message);
    }

    [Fact]
    public async Task InitiateAuthenticationAsync_WithoutAUsernameLeavesAllowedCredentialsEmptyAsync()
    {
        var (fido2, store, facade) = NewSut();
        GetAssertionOptionsParams? captured = null;
        fido2.Setup(f => f.GetAssertionOptions(It.IsAny<GetAssertionOptionsParams>()))
            .Returns((GetAssertionOptionsParams p) => { captured = p; return new AssertionOptions(); });

        await facade.InitiateAuthenticationAsync();

        Assert.Empty(captured!.AllowedCredentials);
        store.Verify(s => s.GetUserAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    // --- CompleteAuthenticationAsync -----------------------------------------------------------------------------

    [Fact]
    public async Task CompleteAuthenticationAsync_RejectsNullArgumentsAsync()
    {
        var (_, _, facade) = NewSut();
        var options = new AssertionOptions();

        await Assert.ThrowsAsync<ArgumentNullException>(() => facade.CompleteAuthenticationAsync(null!, new AuthenticatorAssertionRawResponse()));
        await Assert.ThrowsAsync<ArgumentNullException>(() => facade.CompleteAuthenticationAsync(options, null!));
    }

    [Fact]
    public async Task CompleteAuthenticationAsync_UnknownCredentialThrowsAsync()
    {
        var (_, store, facade) = NewSut();
        var rawId = Guid.NewGuid().ToByteArray();
        store.Setup(s => s.GetCredentialByIdAsync(rawId, It.IsAny<CancellationToken>())).ReturnsAsync((StoredCredential?)null);
        var response = new AuthenticatorAssertionRawResponse { RawId = rawId };

        await Assert.ThrowsAsync<InvalidOperationException>(() => facade.CompleteAuthenticationAsync(new AssertionOptions(), response));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task CompleteAuthenticationAsync_PassesUvInitializationAuthorizedThroughFaithfullyAsync(bool authorized)
    {
        var (fido2, store, facade) = NewSut();
        var stored = NewStoredCredential();
        var response = new AuthenticatorAssertionRawResponse { RawId = stored.Id };
        store.Setup(s => s.GetCredentialByIdAsync(stored.Id, It.IsAny<CancellationToken>())).ReturnsAsync(stored);
        var verifyResult = new VerifyAssertionResult { CredentialId = stored.Id, SignCount = stored.SignCount + 1 };
        fido2.Setup(f => f.MakeAssertionAsync(It.IsAny<MakeAssertionParams>(), It.IsAny<CancellationToken>())).ReturnsAsync(verifyResult);
        bool? passedThrough = null;
        store.Setup(s => s.UpdateCredentialRecordAsync(verifyResult, It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .Callback((VerifyAssertionResult _, bool uv, CancellationToken _) => passedThrough = uv)
            .Returns(Task.CompletedTask);
        store.Setup(s => s.GetUsersByCredentialIdAsync(stored.Id, It.IsAny<CancellationToken>())).ReturnsAsync([NewUser("judy", 10)]);

        await facade.CompleteAuthenticationAsync(new AssertionOptions(), response, authorized);

        Assert.Equal(authorized, passedThrough);
    }

    [Fact]
    public async Task CompleteAuthenticationAsync_DefaultsUvInitializationAuthorizedToFalseAsync()
    {
        var (fido2, store, facade) = NewSut();
        var stored = NewStoredCredential();
        var response = new AuthenticatorAssertionRawResponse { RawId = stored.Id };
        store.Setup(s => s.GetCredentialByIdAsync(stored.Id, It.IsAny<CancellationToken>())).ReturnsAsync(stored);
        var verifyResult = new VerifyAssertionResult { CredentialId = stored.Id, SignCount = stored.SignCount + 1 };
        fido2.Setup(f => f.MakeAssertionAsync(It.IsAny<MakeAssertionParams>(), It.IsAny<CancellationToken>())).ReturnsAsync(verifyResult);
        store.Setup(s => s.GetUsersByCredentialIdAsync(stored.Id, It.IsAny<CancellationToken>())).ReturnsAsync([NewUser("karl", 11)]);

        await facade.CompleteAuthenticationAsync(new AssertionOptions(), response);

        store.Verify(s => s.UpdateCredentialRecordAsync(verifyResult, false, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task CompleteAuthenticationAsync_UsesTheStoredCredentialForVerificationAsync()
    {
        var (fido2, store, facade) = NewSut();
        var stored = NewStoredCredential(signCount: 4, backupEligible: true);
        var response = new AuthenticatorAssertionRawResponse { RawId = stored.Id };
        store.Setup(s => s.GetCredentialByIdAsync(stored.Id, It.IsAny<CancellationToken>())).ReturnsAsync(stored);
        MakeAssertionParams? captured = null;
        fido2.Setup(f => f.MakeAssertionAsync(It.IsAny<MakeAssertionParams>(), It.IsAny<CancellationToken>()))
            .Callback((MakeAssertionParams p, CancellationToken _) => captured = p)
            .ReturnsAsync(new VerifyAssertionResult { CredentialId = stored.Id, SignCount = 5 });
        store.Setup(s => s.UpdateCredentialRecordAsync(It.IsAny<VerifyAssertionResult>(), It.IsAny<bool>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        store.Setup(s => s.GetUsersByCredentialIdAsync(stored.Id, It.IsAny<CancellationToken>())).ReturnsAsync([NewUser("liam", 12)]);

        await facade.CompleteAuthenticationAsync(new AssertionOptions(), response);

        Assert.Equal(stored.PublicKey, captured!.StoredPublicKey);
        Assert.Equal(stored.SignCount, captured.StoredSignatureCounter);
        Assert.Equal(stored.IsBackupEligible, captured.StoredBackupEligible);
    }

    [Fact]
    public async Task CompleteAuthenticationAsync_OwnershipCallbackQueriesTheStoreByUserHandleAsync()
    {
        var (fido2, store, facade) = NewSut();
        var stored = NewStoredCredential();
        var response = new AuthenticatorAssertionRawResponse { RawId = stored.Id };
        store.Setup(s => s.GetCredentialByIdAsync(stored.Id, It.IsAny<CancellationToken>())).ReturnsAsync(stored);
        IsUserHandleOwnerOfCredentialIdAsync? callback = null;
        fido2.Setup(f => f.MakeAssertionAsync(It.IsAny<MakeAssertionParams>(), It.IsAny<CancellationToken>()))
            .Callback((MakeAssertionParams p, CancellationToken _) => callback = p.IsUserHandleOwnerOfCredentialIdCallback)
            .ReturnsAsync(new VerifyAssertionResult { CredentialId = stored.Id });
        store.Setup(s => s.UpdateCredentialRecordAsync(It.IsAny<VerifyAssertionResult>(), It.IsAny<bool>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        store.Setup(s => s.GetUsersByCredentialIdAsync(stored.Id, It.IsAny<CancellationToken>())).ReturnsAsync([NewUser("mia", 13)]);
        var otherHandle = Guid.NewGuid().ToByteArray();
        store.Setup(s => s.GetCredentialsByUserHandleAsync(stored.UserHandle, It.IsAny<CancellationToken>())).ReturnsAsync([stored]);
        store.Setup(s => s.GetCredentialsByUserHandleAsync(otherHandle, It.IsAny<CancellationToken>())).ReturnsAsync([]);

        await facade.CompleteAuthenticationAsync(new AssertionOptions(), response);

        Assert.NotNull(callback);
        Assert.True(await callback!(new IsUserHandleOwnerOfCredentialIdParams(stored.Id, stored.UserHandle), CancellationToken.None));
        Assert.False(await callback(new IsUserHandleOwnerOfCredentialIdParams(stored.Id, otherHandle), CancellationToken.None));
    }

    [Fact]
    public async Task CompleteAuthenticationAsync_ReturnsTheResolvedOwnerAsync()
    {
        var (fido2, store, facade) = NewSut();
        var stored = NewStoredCredential();
        var response = new AuthenticatorAssertionRawResponse { RawId = stored.Id };
        var owner = NewUser("nina", 14);
        store.Setup(s => s.GetCredentialByIdAsync(stored.Id, It.IsAny<CancellationToken>())).ReturnsAsync(stored);
        fido2.Setup(f => f.MakeAssertionAsync(It.IsAny<MakeAssertionParams>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new VerifyAssertionResult { CredentialId = stored.Id });
        store.Setup(s => s.UpdateCredentialRecordAsync(It.IsAny<VerifyAssertionResult>(), It.IsAny<bool>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        store.Setup(s => s.GetUsersByCredentialIdAsync(stored.Id, It.IsAny<CancellationToken>())).ReturnsAsync([owner]);

        var result = await facade.CompleteAuthenticationAsync(new AssertionOptions(), response);

        Assert.Same(owner, result);
    }

    [Fact]
    public async Task CompleteAuthenticationAsync_UnresolvableOwnerThrowsAsync()
    {
        var (fido2, store, facade) = NewSut();
        var stored = NewStoredCredential();
        var response = new AuthenticatorAssertionRawResponse { RawId = stored.Id };
        store.Setup(s => s.GetCredentialByIdAsync(stored.Id, It.IsAny<CancellationToken>())).ReturnsAsync(stored);
        fido2.Setup(f => f.MakeAssertionAsync(It.IsAny<MakeAssertionParams>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new VerifyAssertionResult { CredentialId = stored.Id });
        store.Setup(s => s.UpdateCredentialRecordAsync(It.IsAny<VerifyAssertionResult>(), It.IsAny<bool>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        store.Setup(s => s.GetUsersByCredentialIdAsync(stored.Id, It.IsAny<CancellationToken>())).ReturnsAsync([]);

        await Assert.ThrowsAsync<InvalidOperationException>(() => facade.CompleteAuthenticationAsync(new AssertionOptions(), response));
    }

    // --- DI registration ------------------------------------------------------------------------------------------

    [Fact]
    public void AddFido2Simple_RegistersTheFacadeScoped()
    {
        var services = new ServiceCollection();
        services.AddSingleton(new Mock<IFido2>().Object);
        services.AddSingleton(new Mock<ICredentialStore>().Object);

        services.AddFido2Simple();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var facade = scope.ServiceProvider.GetRequiredService<ISimpleFido2Authentication>();

        Assert.IsType<SimpleFido2Authentication>(facade);
    }

    [Fact]
    public void AddFido2Simple_RejectsANullServiceCollection()
    {
        Assert.Throws<ArgumentNullException>(() => ((IServiceCollection)null!).AddFido2Simple());
    }
}
