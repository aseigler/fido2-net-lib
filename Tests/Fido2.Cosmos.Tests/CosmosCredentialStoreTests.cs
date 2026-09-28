using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Microsoft.Azure.Cosmos;
using Microsoft.Extensions.DependencyInjection;

namespace Fido2NetLib.Cosmos.Tests;

/// <summary>
/// Covers <see cref="CosmosCredentialStore"/> against a real emulator (see <see cref="CosmosEmulatorFixture"/>),
/// so partitioning, ETag-conditioned writes, and cross-partition query behaviour are really exercised, not
/// mocked. Every test returns early when <see cref="CosmosEmulatorFixture.Available"/> is <see langword="false"/>:
/// in a Docker-less or otherwise constrained environment the emulator cannot start, which is an environment
/// limitation, not something these tests should report as a store defect.
/// </summary>
[Collection(CosmosEmulatorCollection.Name)]
public sealed class CosmosCredentialStoreTests(CosmosEmulatorFixture fixture)
{
    private CosmosCredentialStore NewStore() => new(fixture.Container);

    private static Fido2User NewUser(string name, byte id) => new() { Name = name, Id = [id], DisplayName = name.ToUpperInvariant() };

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

    private async Task<StoredCredential> RegisteredCredentialAsync(string username, byte userId, uint signCount = 0)
    {
        var store = NewStore();
        var user = await store.GetOrAddUserAsync(username, () => NewUser(username, userId));
        var credential = NewCredential(signCount: signCount);
        await store.AddCredentialToUserAsync(user, credential);
        return credential;
    }

    [Fact]
    public async Task GetOrAddUserAsync_CreatesTheUserOnlyOnceAsync()
    {
        if (!fixture.Available)
            return;
        var store = NewStore();

        var user = await store.GetOrAddUserAsync("cosmos-alice", () => NewUser("cosmos-alice", 1));
        var again = await store.GetOrAddUserAsync("cosmos-alice", () => NewUser("cosmos-alice", 2));

        Assert.Equal(user.Id, again.Id);
        Assert.Equal(user.Id, (await NewStore().GetUserAsync("cosmos-alice"))!.Id);
    }

    [Fact]
    public async Task GetOrAddUserAsync_ReturnsTheUserAConcurrentRequestAddedAsync()
    {
        if (!fixture.Available)
            return;

        // The callback runs after this store found no user, so adding the same name from another store instance
        // inside it reproduces two requests racing to create one account.
        var store = NewStore();

        var user = await store.GetOrAddUserAsync("cosmos-frank", () =>
        {
            NewStore().GetOrAddUserAsync("cosmos-frank", () => NewUser("cosmos-frank", 6)).GetAwaiter().GetResult();
            return NewUser("cosmos-frank", 7);
        });

        Assert.Equal([6], user.Id);
    }

    [Fact]
    public async Task AddCredentialToUserAsync_StoresTheCredentialWithTheUsersIdAsync()
    {
        if (!fixture.Available)
            return;
        var store = NewStore();
        var user = await store.GetOrAddUserAsync("cosmos-bob", () => NewUser("cosmos-bob", 9));
        var credential = NewCredential();

        await store.AddCredentialToUserAsync(user, credential);

        var stored = await store.GetCredentialByIdAsync(credential.Id);
        Assert.NotNull(stored);
        Assert.Equal(user.Id, stored!.UserId);
        Assert.Equal(credential.Transports, stored.Transports);
    }

    [Fact]
    public async Task ACredentialCanOnlyBeRegisteredOnceAsync()
    {
        if (!fixture.Available)
            return;
        var store = NewStore();
        var user = await store.GetOrAddUserAsync("cosmos-onceonly", () => NewUser("cosmos-onceonly", 20));
        var id = Guid.NewGuid().ToByteArray();
        await store.AddCredentialToUserAsync(user, NewCredential(id));

        await Assert.ThrowsAsync<InvalidOperationException>(() => NewStore().AddCredentialToUserAsync(user, NewCredential(id)));
    }

    [Fact]
    public async Task ACredentialNeedsAStoredUserAsync()
    {
        if (!fixture.Available)
            return;
        await Assert.ThrowsAsync<InvalidOperationException>(() => NewStore().AddCredentialToUserAsync(NewUser("cosmos-nobody", 99), NewCredential()));
    }

    [Fact]
    public async Task GetCredentialsByUserAsync_ReturnsOnlyThatUsersCredentialsAsync()
    {
        if (!fixture.Available)
            return;
        var store = NewStore();
        var alice = await store.GetOrAddUserAsync("cosmos-alice2", () => NewUser("cosmos-alice2", 21));
        var bob = await store.GetOrAddUserAsync("cosmos-bob2", () => NewUser("cosmos-bob2", 22));

        await store.AddCredentialToUserAsync(alice, NewCredential());
        await store.AddCredentialToUserAsync(alice, NewCredential());
        await store.AddCredentialToUserAsync(bob, NewCredential());

        Assert.Equal(2, (await NewStore().GetCredentialsByUserAsync(alice)).Count);
        Assert.Single(await NewStore().GetCredentialsByUserAsync(bob));
    }

    [Fact]
    public async Task GetCredentialsByUserHandleAsync_FindsTheDiscoverableCredentialAsync()
    {
        if (!fixture.Available)
            return;
        var store = NewStore();
        var user = await store.GetOrAddUserAsync("cosmos-carol", () => NewUser("cosmos-carol", 23));
        var userHandle = Guid.NewGuid().ToByteArray();
        var credential = NewCredential(userHandle: userHandle);
        await store.AddCredentialToUserAsync(user, credential);

        var found = Assert.Single(await NewStore().GetCredentialsByUserHandleAsync(userHandle));

        Assert.Equal(credential.Id, found.Id);
    }

    [Fact]
    public async Task GetUsersByCredentialIdAsync_ResolvesTheOwningUserAsync()
    {
        if (!fixture.Available)
            return;
        var store = NewStore();
        var user = await store.GetOrAddUserAsync("cosmos-dave", () => NewUser("cosmos-dave", 24));
        var credential = NewCredential();
        await store.AddCredentialToUserAsync(user, credential);

        var owner = Assert.Single(await NewStore().GetUsersByCredentialIdAsync(credential.Id));

        Assert.Equal("cosmos-dave", owner.Name);
    }

    [Fact]
    public async Task GetUsersByCredentialIdAsync_ReturnsEmptyForAnUnknownCredentialAsync()
    {
        if (!fixture.Available)
            return;
        Assert.Empty(await NewStore().GetUsersByCredentialIdAsync([0xde, 0xad]));
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_AppliesSignCountAndBackupStateAsync()
    {
        if (!fixture.Available)
            return;
        var credential = await RegisteredCredentialAsync("cosmos-erin", 25, signCount: 1);

        await NewStore().UpdateCredentialRecordAsync(Assertion(credential.Id, 2, backedUp: true, userVerified: true));

        var stored = await NewStore().GetCredentialByIdAsync(credential.Id);
        Assert.Equal(2u, stored!.SignCount);
        Assert.True(stored.IsBackedUp);
        // Promoting uvInitialized needs the caller's authorization.
        Assert.False(stored.UvInitialized);
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_PromotesUvInitializedOnlyWhenAuthorizedAndVerifiedAsync()
    {
        if (!fixture.Available)
            return;
        var credential = await RegisteredCredentialAsync("cosmos-erin2", 26, signCount: 1);

        await NewStore().UpdateCredentialRecordAsync(Assertion(credential.Id, 2, userVerified: false), uvInitializationAuthorized: true);
        Assert.False((await NewStore().GetCredentialByIdAsync(credential.Id))!.UvInitialized);

        await NewStore().UpdateCredentialRecordAsync(Assertion(credential.Id, 3, userVerified: true), uvInitializationAuthorized: true);
        Assert.True((await NewStore().GetCredentialByIdAsync(credential.Id))!.UvInitialized);

        // Never demoted.
        await NewStore().UpdateCredentialRecordAsync(Assertion(credential.Id, 4, userVerified: false));
        Assert.True((await NewStore().GetCredentialByIdAsync(credential.Id))!.UvInitialized);
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_UpdatesACredentialWhoseCounterIsAlwaysZeroAsync()
    {
        if (!fixture.Available)
            return;
        // Most passkeys report 0 every time; the rule only applies once either counter is non-zero.
        var credential = await RegisteredCredentialAsync("cosmos-erin3", 27, signCount: 0);

        await NewStore().UpdateCredentialRecordAsync(Assertion(credential.Id, 0, backedUp: true));

        Assert.True((await NewStore().GetCredentialByIdAsync(credential.Id))!.IsBackedUp);
    }

    [Theory]
    [InlineData(7u, 6u)]
    [InlineData(7u, 7u)]
    [InlineData(7u, 0u)]
    public async Task UpdateCredentialRecordAsync_RefusesACounterAnotherSignInHasAlreadyPassedAsync(uint alreadyStored, uint thisAssertion)
    {
        if (!fixture.Available)
            return;
        // Two sign-ins both verified against a counter of 5: one stores 7 first, then the slower one arrives.
        var credential = await RegisteredCredentialAsync($"cosmos-race-{alreadyStored}-{thisAssertion}", (byte)(alreadyStored + thisAssertion + 40), signCount: 5);
        await NewStore().UpdateCredentialRecordAsync(Assertion(credential.Id, alreadyStored));

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => NewStore().UpdateCredentialRecordAsync(Assertion(credential.Id, thisAssertion, backedUp: true)));

        Assert.Equal(Fido2ErrorCode.InvalidSignCount, ex.Code);
        var stored = await NewStore().GetCredentialByIdAsync(credential.Id);
        Assert.Equal(alreadyStored, stored!.SignCount);
        Assert.False(stored.IsBackedUp);
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_RejectsAnUnknownCredentialAsync()
    {
        if (!fixture.Available)
            return;
        await Assert.ThrowsAsync<InvalidOperationException>(() => NewStore().UpdateCredentialRecordAsync(Assertion([0xde, 0xad], 1)));
        await Assert.ThrowsAsync<ArgumentNullException>(() => NewStore().UpdateCredentialRecordAsync(null!));
    }

    [Fact]
    public async Task RemoveCredentialAsync_RemovesAKnownCredentialAndReportsTrueAsync()
    {
        if (!fixture.Available)
            return;
        var credential = await RegisteredCredentialAsync("cosmos-removeme", 41, signCount: 0);

        Assert.True(await NewStore().RemoveCredentialAsync(credential.Id));
        Assert.Null(await NewStore().GetCredentialByIdAsync(credential.Id));
        Assert.False(await NewStore().RemoveCredentialAsync(credential.Id));
    }

    [Fact]
    public void TheRegistrationRejectsANullServiceCollection()
    {
        Assert.Throws<ArgumentNullException>(() => ((IServiceCollection)null!).AddFido2CosmosStore(_ => fixture.Container));
    }

    [Fact]
    public void TheRegistrationRejectsANullContainerFactory()
    {
        Assert.Throws<ArgumentNullException>(() => new ServiceCollection().AddFido2CosmosStore(null!));
    }

    [Fact]
    public async Task WorksThroughTheDIRegistrationAsync()
    {
        if (!fixture.Available)
            return;

        var services = new ServiceCollection();
        services.AddFido2CosmosStore(_ => fixture.Container);

        using var provider = services.BuildServiceProvider();
        var store = provider.GetRequiredService<ICredentialStore>();

        Assert.IsType<CosmosCredentialStore>(store);

        var user = await store.GetOrAddUserAsync("cosmos-heidi", () => NewUser("cosmos-heidi", 50));
        var credential = NewCredential(signCount: 1);
        await store.AddCredentialToUserAsync(user, credential);
        await store.UpdateCredentialRecordAsync(Assertion(credential.Id, 2));

        Assert.Equal(2u, (await store.GetCredentialByIdAsync(credential.Id))!.SignCount);
    }
}
