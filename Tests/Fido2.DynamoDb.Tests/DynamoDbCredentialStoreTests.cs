using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Microsoft.Extensions.DependencyInjection;

namespace Fido2NetLib.DynamoDb.Tests;

/// <summary>
/// Covers <see cref="DynamoDbCredentialStore"/> against a real <c>amazon/dynamodb-local</c> container (see
/// <see cref="DynamoDbLocalFixture"/>), so the conditional writes and GSI queries it relies on are really
/// exercised. Skipped, not failed, when Docker is unavailable.
/// </summary>
public sealed class DynamoDbCredentialStoreTests : IClassFixture<DynamoDbLocalFixture>
{
    private readonly DynamoDbLocalFixture _fixture;

    public DynamoDbCredentialStoreTests(DynamoDbLocalFixture fixture) => _fixture = fixture;

    private DynamoDbCredentialStore NewStore() => new(_fixture.Client, _fixture.Options);

    private static string UniqueName(string prefix) => $"{prefix}-{Guid.NewGuid():N}";

    private static Fido2User NewUser(string name) => new() { Name = name, Id = Guid.NewGuid().ToByteArray(), DisplayName = name.ToUpperInvariant() };

    private static StoredCredential NewCredential(byte[]? id = null, byte[]? userHandle = null, uint signCount = 0) => new()
    {
        Id = id ?? Guid.NewGuid().ToByteArray(),
        PublicKey = [1, 2, 3],
        SignCount = signCount,
        Transports = [AuthenticatorTransport.Internal, AuthenticatorTransport.Hybrid],
        UserHandle = userHandle ?? Guid.NewGuid().ToByteArray(),
        AttestationFormat = "none",
        RegDate = DateTimeOffset.UtcNow,
        AaGuid = Guid.NewGuid(),
    };

    private static VerifyAssertionResult Assertion(byte[] credentialId, uint signCount, bool backedUp = false, bool userVerified = false) => new()
    {
        CredentialId = credentialId,
        SignCount = signCount,
        IsBackedUp = backedUp,
        IsUserVerified = userVerified,
    };

    [SkippableFact]
    public async Task GetOrAddUserAsync_CreatesTheUserOnlyOnceAsync()
    {
        Skip.IfNot(_fixture.IsAvailable, _fixture.SkipReason);
        var store = NewStore();
        var name = UniqueName("alice");

        var user = await store.GetOrAddUserAsync(name, () => NewUser(name));
        var again = await store.GetOrAddUserAsync(name, () => NewUser(name));

        Assert.Equal(user.Id, again.Id);
        Assert.Equal(user.Id, (await store.GetUserAsync(name))!.Id);
    }

    [SkippableFact]
    public async Task AddCredentialToUserAsync_StoresTheCredentialWithTheUsersIdAsync()
    {
        Skip.IfNot(_fixture.IsAvailable, _fixture.SkipReason);
        var store = NewStore();
        var name = UniqueName("bob");
        var user = await store.GetOrAddUserAsync(name, () => NewUser(name));
        var credential = NewCredential();

        await store.AddCredentialToUserAsync(user, credential);

        var stored = await store.GetCredentialByIdAsync(credential.Id);
        Assert.NotNull(stored);
        Assert.Equal(user.Id, stored!.UserId);
        Assert.Equal(credential.Transports, stored.Transports);
    }

    [SkippableFact]
    public async Task ACredentialCanOnlyBeRegisteredOnceGloballyAsync()
    {
        Skip.IfNot(_fixture.IsAvailable, _fixture.SkipReason);
        var store = NewStore();
        var name1 = UniqueName("carol");
        var name2 = UniqueName("dave");
        var user1 = await store.GetOrAddUserAsync(name1, () => NewUser(name1));
        var user2 = await store.GetOrAddUserAsync(name2, () => NewUser(name2));
        var id = Guid.NewGuid().ToByteArray();
        await store.AddCredentialToUserAsync(user1, NewCredential(id));

        // Same credential ID, a different user: the global uniqueness reservation must refuse this.
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.AddCredentialToUserAsync(user2, NewCredential(id)));
    }

    [SkippableFact]
    public async Task GetCredentialsByUserAsync_ReturnsOnlyThatUsersCredentialsAsync()
    {
        Skip.IfNot(_fixture.IsAvailable, _fixture.SkipReason);
        var store = NewStore();
        var aliceName = UniqueName("alice");
        var bobName = UniqueName("bob");
        var alice = await store.GetOrAddUserAsync(aliceName, () => NewUser(aliceName));
        var bob = await store.GetOrAddUserAsync(bobName, () => NewUser(bobName));

        await store.AddCredentialToUserAsync(alice, NewCredential());
        await store.AddCredentialToUserAsync(alice, NewCredential());
        await store.AddCredentialToUserAsync(bob, NewCredential());

        Assert.Equal(2, (await store.GetCredentialsByUserAsync(alice)).Count);
        Assert.Single(await store.GetCredentialsByUserAsync(bob));
    }

    [SkippableFact]
    public async Task GetCredentialsByUserHandleAsync_FindsTheDiscoverableCredentialAsync()
    {
        Skip.IfNot(_fixture.IsAvailable, _fixture.SkipReason);
        var store = NewStore();
        var name = UniqueName("carol");
        var user = await store.GetOrAddUserAsync(name, () => NewUser(name));
        var userHandle = Guid.NewGuid().ToByteArray();
        var credential = NewCredential(userHandle: userHandle);
        await store.AddCredentialToUserAsync(user, credential);

        var found = Assert.Single(await store.GetCredentialsByUserHandleAsync(userHandle));

        Assert.Equal(credential.Id, found.Id);
    }

    [SkippableFact]
    public async Task GetUsersByCredentialIdAsync_ResolvesTheOwningUserAsync()
    {
        Skip.IfNot(_fixture.IsAvailable, _fixture.SkipReason);
        var store = NewStore();
        var name = UniqueName("dave");
        var user = await store.GetOrAddUserAsync(name, () => NewUser(name));
        var credential = NewCredential();
        await store.AddCredentialToUserAsync(user, credential);

        var owner = Assert.Single(await store.GetUsersByCredentialIdAsync(credential.Id));

        Assert.Equal(name, owner.Name);
    }

    [SkippableFact]
    public async Task GetUsersByCredentialIdAsync_ReturnsEmptyForAnUnknownCredentialAsync()
    {
        Skip.IfNot(_fixture.IsAvailable, _fixture.SkipReason);
        Assert.Empty(await NewStore().GetUsersByCredentialIdAsync(Guid.NewGuid().ToByteArray()));
    }

    [SkippableFact]
    public async Task UpdateCredentialRecordAsync_AppliesSignCountAndBackupStateAsync()
    {
        Skip.IfNot(_fixture.IsAvailable, _fixture.SkipReason);
        var store = NewStore();
        var name = UniqueName("erin");
        var user = await store.GetOrAddUserAsync(name, () => NewUser(name));
        var credential = NewCredential(signCount: 1);
        await store.AddCredentialToUserAsync(user, credential);

        await store.UpdateCredentialRecordAsync(Assertion(credential.Id, 2, backedUp: true, userVerified: true));

        var stored = await store.GetCredentialByIdAsync(credential.Id);
        Assert.Equal(2u, stored!.SignCount);
        Assert.True(stored.IsBackedUp);
        // Promoting uvInitialized needs the caller's authorization.
        Assert.False(stored.UvInitialized);
    }

    [SkippableFact]
    public async Task UpdateCredentialRecordAsync_PromotesUvInitializedOnlyWhenAuthorizedAndVerifiedAsync()
    {
        Skip.IfNot(_fixture.IsAvailable, _fixture.SkipReason);
        var store = NewStore();
        var name = UniqueName("frank");
        var user = await store.GetOrAddUserAsync(name, () => NewUser(name));
        var credential = NewCredential(signCount: 1);
        await store.AddCredentialToUserAsync(user, credential);

        await store.UpdateCredentialRecordAsync(Assertion(credential.Id, 2, userVerified: false), uvInitializationAuthorized: true);
        Assert.False((await store.GetCredentialByIdAsync(credential.Id))!.UvInitialized);

        await store.UpdateCredentialRecordAsync(Assertion(credential.Id, 3, userVerified: true), uvInitializationAuthorized: true);
        Assert.True((await store.GetCredentialByIdAsync(credential.Id))!.UvInitialized);

        // Never demoted.
        await store.UpdateCredentialRecordAsync(Assertion(credential.Id, 4, userVerified: false));
        Assert.True((await store.GetCredentialByIdAsync(credential.Id))!.UvInitialized);
    }

    [SkippableTheory]
    [InlineData(7u, 6u)]
    [InlineData(7u, 7u)]
    [InlineData(7u, 0u)]
    public async Task UpdateCredentialRecordAsync_RefusesACounterAnotherSignInHasAlreadyPassedAsync(uint alreadyStored, uint thisAssertion)
    {
        Skip.IfNot(_fixture.IsAvailable, _fixture.SkipReason);
        // Two sign-ins both verified against a counter of 5: one stores 7 first, then the slower one arrives.
        var store = NewStore();
        var name = UniqueName("grace");
        var user = await store.GetOrAddUserAsync(name, () => NewUser(name));
        var credential = NewCredential(signCount: 5);
        await store.AddCredentialToUserAsync(user, credential);
        await store.UpdateCredentialRecordAsync(Assertion(credential.Id, alreadyStored));

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => store.UpdateCredentialRecordAsync(Assertion(credential.Id, thisAssertion, backedUp: true)));

        Assert.Equal(Fido2ErrorCode.InvalidSignCount, ex.Code);
        var stored = await store.GetCredentialByIdAsync(credential.Id);
        Assert.Equal(alreadyStored, stored!.SignCount);
        Assert.False(stored.IsBackedUp);
    }

    [SkippableFact]
    public async Task UpdateCredentialRecordAsync_RejectsAnUnknownCredentialAsync()
    {
        Skip.IfNot(_fixture.IsAvailable, _fixture.SkipReason);
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => NewStore().UpdateCredentialRecordAsync(Assertion(Guid.NewGuid().ToByteArray(), 1)));
    }

    [SkippableFact]
    public async Task RemoveCredentialAsync_RemovesAKnownCredentialAndReportsTrueAsync()
    {
        Skip.IfNot(_fixture.IsAvailable, _fixture.SkipReason);
        var store = NewStore();
        var name = UniqueName("heidi");
        var user = await store.GetOrAddUserAsync(name, () => NewUser(name));
        var credential = NewCredential();
        await store.AddCredentialToUserAsync(user, credential);

        Assert.True(await store.RemoveCredentialAsync(credential.Id));
        Assert.Null(await store.GetCredentialByIdAsync(credential.Id));
        Assert.False(await store.RemoveCredentialAsync(credential.Id));
    }

    [SkippableFact]
    public async Task RemoveCredentialAsync_FreesTheCredentialIdForReuseAsync()
    {
        Skip.IfNot(_fixture.IsAvailable, _fixture.SkipReason);
        var store = NewStore();
        var name1 = UniqueName("ivan");
        var name2 = UniqueName("judy");
        var user1 = await store.GetOrAddUserAsync(name1, () => NewUser(name1));
        var user2 = await store.GetOrAddUserAsync(name2, () => NewUser(name2));
        var id = Guid.NewGuid().ToByteArray();
        await store.AddCredentialToUserAsync(user1, NewCredential(id));
        await store.RemoveCredentialAsync(id);

        // The uniqueness reservation must have been removed too, or this would throw.
        await store.AddCredentialToUserAsync(user2, NewCredential(id));

        Assert.Equal(user2.Id, (await store.GetCredentialByIdAsync(id))!.UserId);
    }

    [Fact]
    public void TheRegistrationRejectsANullServiceCollection()
    {
        Assert.Throws<ArgumentNullException>(() => ((IServiceCollection)null!).AddFido2DynamoDbStore());
    }
}
