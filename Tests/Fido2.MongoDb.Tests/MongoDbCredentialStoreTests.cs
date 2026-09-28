using Fido2NetLib.Exceptions;
using Fido2NetLib.MongoDb;
using Fido2NetLib.Objects;

using Microsoft.Extensions.DependencyInjection;

using MongoDB.Driver;

using Testcontainers.MongoDb;

namespace Fido2NetLib.MongoDb.Tests;

/// <summary>
/// One MongoDB container shared across <see cref="MongoDbCredentialStoreTests"/>; each test uses its own database
/// within it, so tests do not see each other's data without paying to start a container per test.
/// </summary>
public sealed class MongoDbContainerFixture : IAsyncLifetime
{
    private MongoDbContainer? _container;

    /// <summary>
    /// Whether the container started successfully. Tests should call
    /// <c>Skip.IfNot(fixture.IsAvailable, fixture.SkipReason)</c> before using <see cref="ConnectionString"/>.
    /// </summary>
    public bool IsAvailable { get; private set; }

    /// <summary>
    /// Why the fixture is unavailable, set only when <see cref="IsAvailable"/> is <see langword="false"/>.
    /// </summary>
    public string SkipReason { get; private set; } = "";

    public string ConnectionString => _container!.GetConnectionString();

    public async Task InitializeAsync()
    {
        try
        {
            // Building the container (not just starting it) already probes for a Docker endpoint, so both steps
            // need to be inside this try: with Docker unavailable, .Build() itself throws, before StartAsync runs.
            _container = new MongoDbBuilder("mongo:7.0").Build();
            await _container.StartAsync();
            IsAvailable = true;
        }
        catch (Exception ex)
        {
            IsAvailable = false;
            SkipReason = $"MongoDB container could not be started (is Docker available?): {ex.Message}";
        }
    }

    public Task DisposeAsync() => _container != null ? _container.DisposeAsync().AsTask() : Task.CompletedTask;
}

/// <summary>
/// The xunit collection <see cref="MongoDbCredentialStoreTests"/> shares its container fixture through.
/// </summary>
[CollectionDefinition(Name)]
public sealed class MongoDbCollection : ICollectionFixture<MongoDbContainerFixture>
{
    /// <summary>
    /// The collection name tests opt into with <c>[Collection(MongoDbCollection.Name)]</c>.
    /// </summary>
    public const string Name = "MongoDb";
}

/// <summary>
/// Covers <see cref="MongoDbCredentialStore"/> against a real MongoDB server (via Testcontainers), so the behaviour
/// it relies on -- the unique index on the username, the credential ID as <c>_id</c>, the atomic pipeline update --
/// is really exercised.
/// </summary>
[Collection(MongoDbCollection.Name)]
public sealed class MongoDbCredentialStoreTests(MongoDbContainerFixture fixture)
{
    private readonly string _databaseName = $"fido2-{Guid.NewGuid():N}";

    private IMongoDatabase NewDatabase() => new MongoClient(fixture.ConnectionString).GetDatabase(_databaseName);

    private async Task<MongoDbCredentialStore> NewStoreAsync()
    {
        var store = new MongoDbCredentialStore(NewDatabase());
        await store.EnsureIndexesCreatedAsync();
        return store;
    }

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

    private async Task<StoredCredential> RegisteredCredentialAsync(uint signCount = 0)
    {
        var store = await NewStoreAsync();
        var user = await store.GetOrAddUserAsync("erin", () => NewUser("erin", 5));
        var credential = NewCredential(signCount: signCount);
        await store.AddCredentialToUserAsync(user, credential);
        return credential;
    }

    private async Task<StoredCredential> ReloadAsync(byte[] id) => (await (await NewStoreAsync()).GetCredentialByIdAsync(id))!;

    [SkippableFact]
    public async Task GetOrAddUserAsync_CreatesTheUserOnlyOnceAsync()
    {
        Skip.IfNot(fixture.IsAvailable, fixture.SkipReason);
        var store = await NewStoreAsync();

        var user = await store.GetOrAddUserAsync("alice", () => NewUser("alice", 1));
        var again = await store.GetOrAddUserAsync("alice", () => NewUser("alice", 2));

        Assert.Equal(user.Id, again.Id);
        Assert.Equal(user.Id, (await (await NewStoreAsync()).GetUserAsync("alice"))!.Id);
    }

    [SkippableFact]
    public async Task GetOrAddUserAsync_ReturnsTheUserAConcurrentRequestAddedAsync()
    {
        Skip.IfNot(fixture.IsAvailable, fixture.SkipReason);
        // The callback runs after this store found no user, so adding the same name from another store inside it
        // reproduces two requests racing to create one account.
        var store = await NewStoreAsync();

        var user = await store.GetOrAddUserAsync("frank", () =>
        {
            NewDatabase().GetCollection<Fido2User>("fido2.users").InsertOne(NewUser("frank", 6));
            return NewUser("frank", 7);
        });

        Assert.Equal([6], user.Id);
        var all = await NewDatabase().GetCollection<Fido2User>("fido2.users").Find(u => u.Name == "frank").ToListAsync();
        Assert.Single(all);
    }

    [SkippableFact]
    public async Task AddCredentialToUserAsync_StoresTheCredentialWithTheUsersIdAsync()
    {
        Skip.IfNot(fixture.IsAvailable, fixture.SkipReason);
        var store = await NewStoreAsync();
        var user = await store.GetOrAddUserAsync("bob", () => NewUser("bob", 9));
        var credential = NewCredential();

        await store.AddCredentialToUserAsync(user, credential);

        var stored = await ReloadAsync(credential.Id);
        Assert.Equal(user.Id, stored.UserId);
        Assert.Equal(credential.Transports, stored.Transports);
    }

    [SkippableFact]
    public async Task ACredentialCanOnlyBeRegisteredOnceAsync()
    {
        Skip.IfNot(fixture.IsAvailable, fixture.SkipReason);
        var store = await NewStoreAsync();
        var user = await store.GetOrAddUserAsync("bob", () => NewUser("bob", 9));
        var id = Guid.NewGuid().ToByteArray();
        await store.AddCredentialToUserAsync(user, NewCredential(id));

        await Assert.ThrowsAsync<MongoWriteException>(async () => await (await NewStoreAsync()).AddCredentialToUserAsync(user, NewCredential(id)));
    }

    [SkippableFact]
    public async Task GetCredentialsByUserAsync_ReturnsOnlyThatUsersCredentialsAsync()
    {
        Skip.IfNot(fixture.IsAvailable, fixture.SkipReason);
        var store = await NewStoreAsync();
        var alice = await store.GetOrAddUserAsync("alice", () => NewUser("alice", 1));
        var bob = await store.GetOrAddUserAsync("bob", () => NewUser("bob", 2));

        await store.AddCredentialToUserAsync(alice, NewCredential());
        await store.AddCredentialToUserAsync(alice, NewCredential());
        await store.AddCredentialToUserAsync(bob, NewCredential());

        Assert.Equal(2, (await (await NewStoreAsync()).GetCredentialsByUserAsync(alice)).Count);
        Assert.Single(await (await NewStoreAsync()).GetCredentialsByUserAsync(bob));
    }

    [SkippableFact]
    public async Task GetCredentialsByUserHandleAsync_FindsTheDiscoverableCredentialAsync()
    {
        Skip.IfNot(fixture.IsAvailable, fixture.SkipReason);
        var store = await NewStoreAsync();
        var user = await store.GetOrAddUserAsync("carol", () => NewUser("carol", 3));
        var userHandle = new byte[] { 3, 3, 3 };
        var credential = NewCredential(userHandle: userHandle);
        await store.AddCredentialToUserAsync(user, credential);

        var found = Assert.Single(await (await NewStoreAsync()).GetCredentialsByUserHandleAsync(userHandle));

        Assert.Equal(credential.Id, found.Id);
    }

    [SkippableFact]
    public async Task GetUsersByCredentialIdAsync_ResolvesTheOwningUserAsync()
    {
        Skip.IfNot(fixture.IsAvailable, fixture.SkipReason);
        var store = await NewStoreAsync();
        var user = await store.GetOrAddUserAsync("dave", () => NewUser("dave", 4));
        var credential = NewCredential();
        await store.AddCredentialToUserAsync(user, credential);

        var owner = Assert.Single(await (await NewStoreAsync()).GetUsersByCredentialIdAsync(credential.Id));

        Assert.Equal("dave", owner.Name);
    }

    [SkippableFact]
    public async Task GetUsersByCredentialIdAsync_ReturnsEmptyForAnUnknownCredentialAsync()
    {
        Skip.IfNot(fixture.IsAvailable, fixture.SkipReason);
        Assert.Empty(await (await NewStoreAsync()).GetUsersByCredentialIdAsync([0xde, 0xad]));
    }

    [SkippableFact]
    public async Task UpdateCredentialRecordAsync_AppliesSignCountAndBackupStateAsync()
    {
        Skip.IfNot(fixture.IsAvailable, fixture.SkipReason);
        var credential = await RegisteredCredentialAsync(signCount: 1);

        await (await NewStoreAsync()).UpdateCredentialRecordAsync(Assertion(credential.Id, 2, backedUp: true, userVerified: true));

        var stored = await ReloadAsync(credential.Id);
        Assert.Equal(2u, stored.SignCount);
        Assert.True(stored.IsBackedUp);
        // Promoting uvInitialized needs the caller's authorization.
        Assert.False(stored.UvInitialized);
    }

    [SkippableFact]
    public async Task UpdateCredentialRecordAsync_PromotesUvInitializedOnlyWhenAuthorizedAndVerifiedAsync()
    {
        Skip.IfNot(fixture.IsAvailable, fixture.SkipReason);
        var credential = await RegisteredCredentialAsync(signCount: 1);

        await (await NewStoreAsync()).UpdateCredentialRecordAsync(Assertion(credential.Id, 2, userVerified: false), uvInitializationAuthorized: true);
        Assert.False((await ReloadAsync(credential.Id)).UvInitialized);

        await (await NewStoreAsync()).UpdateCredentialRecordAsync(Assertion(credential.Id, 3, userVerified: true), uvInitializationAuthorized: true);
        Assert.True((await ReloadAsync(credential.Id)).UvInitialized);

        // Never demoted.
        await (await NewStoreAsync()).UpdateCredentialRecordAsync(Assertion(credential.Id, 4, userVerified: false));
        Assert.True((await ReloadAsync(credential.Id)).UvInitialized);
    }

    [SkippableFact]
    public async Task UpdateCredentialRecordAsync_UpdatesACredentialWhoseCounterIsAlwaysZeroAsync()
    {
        Skip.IfNot(fixture.IsAvailable, fixture.SkipReason);
        // Most passkeys report 0 every time; the rule only applies once either counter is non-zero.
        var credential = await RegisteredCredentialAsync(signCount: 0);

        await (await NewStoreAsync()).UpdateCredentialRecordAsync(Assertion(credential.Id, 0, backedUp: true));

        Assert.True((await ReloadAsync(credential.Id)).IsBackedUp);
    }

    [SkippableTheory]
    [InlineData(7u, 6u)]
    [InlineData(7u, 7u)]
    [InlineData(7u, 0u)]
    public async Task UpdateCredentialRecordAsync_RefusesACounterAnotherSignInHasAlreadyPassedAsync(uint alreadyStored, uint thisAssertion)
    {
        Skip.IfNot(fixture.IsAvailable, fixture.SkipReason);
        // Two sign-ins both verified against a counter of 5: one stores 7 first, then the slower one arrives.
        var credential = await RegisteredCredentialAsync(signCount: 5);
        await (await NewStoreAsync()).UpdateCredentialRecordAsync(Assertion(credential.Id, alreadyStored));

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => NewStoreAsync().Result.UpdateCredentialRecordAsync(Assertion(credential.Id, thisAssertion, backedUp: true)));

        Assert.Equal(Fido2ErrorCode.InvalidSignCount, ex.Code);
        var stored = await ReloadAsync(credential.Id);
        Assert.Equal(alreadyStored, stored.SignCount);
        Assert.False(stored.IsBackedUp);
    }

    [SkippableFact]
    public async Task UpdateCredentialRecordAsync_RejectsAnUnknownCredentialAsync()
    {
        Skip.IfNot(fixture.IsAvailable, fixture.SkipReason);
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await (await NewStoreAsync()).UpdateCredentialRecordAsync(Assertion([0xde, 0xad], 1)));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await (await NewStoreAsync()).UpdateCredentialRecordAsync(null!));
    }

    [SkippableFact]
    public async Task RemoveCredentialAsync_RemovesAKnownCredentialAndReportsTrueAsync()
    {
        Skip.IfNot(fixture.IsAvailable, fixture.SkipReason);
        var credential = await RegisteredCredentialAsync();

        Assert.True(await (await NewStoreAsync()).RemoveCredentialAsync(credential.Id));
        Assert.Null(await (await NewStoreAsync()).GetCredentialByIdAsync(credential.Id));
        Assert.False(await (await NewStoreAsync()).RemoveCredentialAsync(credential.Id));
    }

    [SkippableFact]
    public async Task WorksThroughDependencyInjectionAsync()
    {
        Skip.IfNot(fixture.IsAvailable, fixture.SkipReason);
        var services = new ServiceCollection();
        services.AddSingleton<IMongoDatabase>(_ => NewDatabase());
        services.AddFido2MongoDbStore();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<ICredentialStore>();
        await ((MongoDbCredentialStore)store).EnsureIndexesCreatedAsync();

        var user = await store.GetOrAddUserAsync("heidi", () => NewUser("heidi", 12));
        var credential = NewCredential(signCount: 1);
        await store.AddCredentialToUserAsync(user, credential);
        await store.UpdateCredentialRecordAsync(Assertion(credential.Id, 2));

        Assert.IsType<MongoDbCredentialStore>(store);
        Assert.Equal(2u, (await store.GetCredentialByIdAsync(credential.Id))!.SignCount);
    }

    [Fact]
    public void TheRegistrationRejectsANullServiceCollection()
    {
        Assert.Throws<ArgumentNullException>(() => ((IServiceCollection)null!).AddFido2MongoDbStore());
    }
}
