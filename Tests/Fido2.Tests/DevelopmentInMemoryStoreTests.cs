using Fido2NetLib;
using Fido2NetLib.Development;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Test;

/// <summary>
/// Covers <see cref="DevelopmentInMemoryStore"/> through <see cref="ICredentialStore"/>, the contract the demos
/// and the EF Core store share: in particular that the signature counter never moves backwards and that
/// <c>uvInitialized</c> is only promoted when authorized.
/// </summary>
public class DevelopmentInMemoryStoreTests
{
    private readonly ICredentialStore _store = new DevelopmentInMemoryStore();

    private static Fido2User NewUser(string name, byte id) => new() { Name = name, Id = [id], DisplayName = name };

    private static StoredCredential NewCredential(uint signCount = 0, byte[] userHandle = null) => new()
    {
        Id = Guid.NewGuid().ToByteArray(),
        PublicKey = [1],
        SignCount = signCount,
        UserHandle = userHandle ?? [7],
        Transports = [],
    };

    private static VerifyAssertionResult Assertion(byte[] id, uint signCount, bool userVerified = false, bool backedUp = false) => new()
    {
        CredentialId = id,
        SignCount = signCount,
        IsUserVerified = userVerified,
        IsBackedUp = backedUp,
    };

    private async Task<(Fido2User User, StoredCredential Credential)> RegisteredAsync(uint signCount = 0)
    {
        var user = await _store.GetOrAddUserAsync("alice", () => NewUser("alice", 1));
        var credential = NewCredential(signCount);
        await _store.AddCredentialToUserAsync(user, credential);
        return (user, credential);
    }

    [Fact]
    public async Task StoresAndFindsUsersAndCredentialsAsync()
    {
        Assert.Null(await _store.GetUserAsync("alice"));

        var (user, credential) = await RegisteredAsync();

        Assert.Same(user, await _store.GetUserAsync("alice"));
        Assert.Same(user, await _store.GetOrAddUserAsync("alice", () => NewUser("alice", 2)));
        Assert.Same(credential, await _store.GetCredentialByIdAsync(credential.Id));
        Assert.Same(credential, Assert.Single(await _store.GetCredentialsByUserAsync(user)));
        Assert.Same(credential, Assert.Single(await _store.GetCredentialsByUserHandleAsync([7])));
        Assert.Same(user, Assert.Single(await _store.GetUsersByCredentialIdAsync(credential.Id)));
        Assert.Equal(user.Id, credential.UserId);
    }

    [Fact]
    public async Task RemovesACredentialAsync()
    {
        var (_, credential) = await RegisteredAsync();

        Assert.True(await _store.RemoveCredentialAsync(credential.Id));
        Assert.False(await _store.RemoveCredentialAsync(credential.Id));
        Assert.Null(await _store.GetCredentialByIdAsync(credential.Id));
        Assert.Empty(await _store.GetUsersByCredentialIdAsync(credential.Id));
    }

    [Fact]
    public async Task UpdatesTheCounterAndBackupStateAsync()
    {
        var (_, credential) = await RegisteredAsync(signCount: 1);

        await _store.UpdateCredentialRecordAsync(Assertion(credential.Id, 2, userVerified: true, backedUp: true));

        Assert.Equal(2u, credential.SignCount);
        Assert.True(credential.IsBackedUp);
        Assert.False(credential.UvInitialized);
    }

    [Fact]
    public async Task PromotesUvInitializedOnlyWhenAuthorizedAndVerifiedAsync()
    {
        var (_, credential) = await RegisteredAsync();

        await _store.UpdateCredentialRecordAsync(Assertion(credential.Id, 0, userVerified: false), uvInitializationAuthorized: true);
        Assert.False(credential.UvInitialized);

        await _store.UpdateCredentialRecordAsync(Assertion(credential.Id, 0, userVerified: true), uvInitializationAuthorized: true);
        Assert.True(credential.UvInitialized);
    }

    [Theory]
    [InlineData(5u, 5u)]
    [InlineData(5u, 4u)]
    [InlineData(5u, 0u)]
    public async Task RefusesACounterThatDoesNotAdvanceAsync(uint stored, uint asserted)
    {
        var (_, credential) = await RegisteredAsync(signCount: stored);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => _store.UpdateCredentialRecordAsync(Assertion(credential.Id, asserted, backedUp: true)));

        Assert.Equal(Fido2ErrorCode.InvalidSignCount, ex.Code);
        Assert.Equal(stored, credential.SignCount);
        Assert.False(credential.IsBackedUp);
    }

    [Fact]
    public async Task RejectsAnUnknownCredentialAsync()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(() => _store.UpdateCredentialRecordAsync(Assertion([9], 1)));
    }
}
