using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Microsoft.Extensions.DependencyInjection;

using StackExchange.Redis;

using Xunit.Abstractions;

namespace Fido2NetLib.Redis.Tests;

/// <summary>
/// Covers <see cref="RedisCredentialStore"/> against a real, ephemeral Redis container (via Testcontainers), so
/// the hand-maintained indexes and the Lua-scripted atomic counter update are really exercised, not mocked. Skips
/// itself when Docker is not reachable in this environment.
/// </summary>
public sealed class RedisCredentialStoreTests(RedisContainerFixture fixture, ITestOutputHelper output) : IClassFixture<RedisContainerFixture>
{
    // Each test gets its own key prefix so tests sharing one container/database cannot see each other's data.
    private RedisCredentialStore NewStore() => new(fixture.Connect(), $"fido2-test-{Guid.NewGuid():N}:");

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

    /// <summary>Whether to run this test, given whether Docker was reachable to start the Redis container.</summary>
    private bool Skip()
    {
        if (fixture.Available)
            return false;

        output.WriteLine($"Skipped: no Docker daemon reachable to start the Redis test container ({fixture.UnavailableReason})");
        return true;
    }

    [Fact]
    public async Task GetOrAddUserAsync_CreatesTheUserOnlyOnceAsync()
    {
        if (Skip()) return;
        var store = NewStore();

        var user = await store.GetOrAddUserAsync("alice", () => NewUser("alice", 1));
        var again = await store.GetOrAddUserAsync("alice", () => NewUser("alice", 2));

        Assert.Equal(user.Id, again.Id);
        Assert.Equal(user.Id, (await store.GetUserAsync("alice"))!.Id);
    }

    [Fact]
    public async Task AddCredentialToUserAsync_StoresTheCredentialWithTheUsersIdAsync()
    {
        if (Skip()) return;
        var store = NewStore();
        var user = await store.GetOrAddUserAsync("bob", () => NewUser("bob", 9));
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
        if (Skip()) return;
        var store = NewStore();
        var user = await store.GetOrAddUserAsync("bob", () => NewUser("bob", 9));
        var id = Guid.NewGuid().ToByteArray();
        await store.AddCredentialToUserAsync(user, NewCredential(id));

        await Assert.ThrowsAsync<InvalidOperationException>(() => store.AddCredentialToUserAsync(user, NewCredential(id)));
    }

    [Fact]
    public async Task GetCredentialsByUserAsync_ReturnsOnlyThatUsersCredentialsAsync()
    {
        if (Skip()) return;
        var store = NewStore();
        var alice = await store.GetOrAddUserAsync("alice", () => NewUser("alice", 1));
        var bob = await store.GetOrAddUserAsync("bob", () => NewUser("bob", 2));

        await store.AddCredentialToUserAsync(alice, NewCredential());
        await store.AddCredentialToUserAsync(alice, NewCredential());
        await store.AddCredentialToUserAsync(bob, NewCredential());

        Assert.Equal(2, (await store.GetCredentialsByUserAsync(alice)).Count);
        Assert.Single(await store.GetCredentialsByUserAsync(bob));
    }

    [Fact]
    public async Task GetCredentialsByUserHandleAsync_FindsTheDiscoverableCredentialAsync()
    {
        if (Skip()) return;
        var store = NewStore();
        var user = await store.GetOrAddUserAsync("carol", () => NewUser("carol", 3));
        var userHandle = new byte[] { 3, 3, 3 };
        var credential = NewCredential(userHandle: userHandle);
        await store.AddCredentialToUserAsync(user, credential);

        var found = Assert.Single(await store.GetCredentialsByUserHandleAsync(userHandle));

        Assert.Equal(credential.Id, found.Id);
    }

    [Fact]
    public async Task GetUsersByCredentialIdAsync_ResolvesTheOwningUserAsync()
    {
        if (Skip()) return;
        var store = NewStore();
        var user = await store.GetOrAddUserAsync("dave", () => NewUser("dave", 4));
        var credential = NewCredential();
        await store.AddCredentialToUserAsync(user, credential);

        var owner = Assert.Single(await store.GetUsersByCredentialIdAsync(credential.Id));

        Assert.Equal("dave", owner.Name);
    }

    [Fact]
    public async Task GetUsersByCredentialIdAsync_ReturnsEmptyForAnUnknownCredentialAsync()
    {
        if (Skip()) return;
        Assert.Empty(await NewStore().GetUsersByCredentialIdAsync([0xde, 0xad]));
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_AppliesSignCountAndBackupStateAsync()
    {
        if (Skip()) return;
        var store = NewStore();
        var user = await store.GetOrAddUserAsync("erin", () => NewUser("erin", 5));
        var credential = NewCredential(signCount: 1);
        await store.AddCredentialToUserAsync(user, credential);

        await store.UpdateCredentialRecordAsync(Assertion(credential.Id, 2, backedUp: true, userVerified: true));

        var stored = await store.GetCredentialByIdAsync(credential.Id);
        Assert.Equal(2u, stored!.SignCount);
        Assert.True(stored.IsBackedUp);
        // Promoting uvInitialized needs the caller's authorization.
        Assert.False(stored.UvInitialized);
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_PromotesUvInitializedOnlyWhenAuthorizedAndVerifiedAsync()
    {
        if (Skip()) return;
        var store = NewStore();
        var user = await store.GetOrAddUserAsync("erin", () => NewUser("erin", 5));
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

    [Fact]
    public async Task UpdateCredentialRecordAsync_UpdatesACredentialWhoseCounterIsAlwaysZeroAsync()
    {
        if (Skip()) return;
        var store = NewStore();
        var user = await store.GetOrAddUserAsync("erin", () => NewUser("erin", 5));
        var credential = NewCredential(signCount: 0);
        await store.AddCredentialToUserAsync(user, credential);

        await store.UpdateCredentialRecordAsync(Assertion(credential.Id, 0, backedUp: true));

        Assert.True((await store.GetCredentialByIdAsync(credential.Id))!.IsBackedUp);
    }

    [Theory]
    [InlineData(7u, 6u)]
    [InlineData(7u, 7u)]
    [InlineData(7u, 0u)]
    public async Task UpdateCredentialRecordAsync_RefusesACounterAnotherSignInHasAlreadyPassedAsync(uint alreadyStored, uint thisAssertion)
    {
        if (Skip()) return;
        // Two sign-ins both verified against a counter of 5: one stores 7 first, then the slower one arrives.
        var store = NewStore();
        var user = await store.GetOrAddUserAsync("erin", () => NewUser("erin", 5));
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

    [Fact]
    public async Task UpdateCredentialRecordAsync_RejectsAnUnknownCredentialAsync()
    {
        if (Skip()) return;
        await Assert.ThrowsAsync<InvalidOperationException>(() => NewStore().UpdateCredentialRecordAsync(Assertion([0xde, 0xad], 1)));
        await Assert.ThrowsAsync<ArgumentNullException>(() => NewStore().UpdateCredentialRecordAsync(null!));
    }

    [Fact]
    public async Task RemoveCredentialAsync_RemovesAKnownCredentialAndItsIndexesAsync()
    {
        if (Skip()) return;
        var store = NewStore();
        var user = await store.GetOrAddUserAsync("erin", () => NewUser("erin", 5));
        var credential = NewCredential();
        await store.AddCredentialToUserAsync(user, credential);

        Assert.True(await store.RemoveCredentialAsync(credential.Id));

        Assert.Null(await store.GetCredentialByIdAsync(credential.Id));
        Assert.False(await store.RemoveCredentialAsync(credential.Id));
        // The reverse indexes must not leave a dangling reference to the removed credential.
        Assert.Empty(await store.GetCredentialsByUserAsync(user));
        Assert.Empty(await store.GetCredentialsByUserHandleAsync(credential.UserHandle));
        Assert.Empty(await store.GetUsersByCredentialIdAsync(credential.Id));
    }

    [Fact]
    public async Task TheRegistrationRejectsANullServiceCollection()
    {
        Assert.Throws<ArgumentNullException>(() => ((IServiceCollection)null!).AddFido2RedisStore());
    }

    [Fact]
    public async Task WorksThroughDependencyInjectionAsync()
    {
        if (Skip()) return;

        var services = new ServiceCollection();
        services.AddSingleton(fixture.Connect());
        services.AddFido2RedisStore($"fido2-test-{Guid.NewGuid():N}:");

        using var provider = services.BuildServiceProvider();
        var store = provider.GetRequiredService<ICredentialStore>();

        var user = await store.GetOrAddUserAsync("heidi", () => NewUser("heidi", 12));
        var credential = NewCredential(signCount: 1);
        await store.AddCredentialToUserAsync(user, credential);
        await store.UpdateCredentialRecordAsync(Assertion(credential.Id, 2));

        Assert.IsType<RedisCredentialStore>(store);
        Assert.Equal(2u, (await store.GetCredentialByIdAsync(credential.Id))!.SignCount);
    }
}
