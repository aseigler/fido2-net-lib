using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Fido2NetLib.EntityFrameworkCore.Tests;

/// <summary>
/// Covers <see cref="EntityFrameworkCoreCredentialStore{TContext}"/> against SQLite, so the relational behaviour the
/// store relies on -- unique indexes, the foreign key, conditional updates -- is really exercised.
/// </summary>
public sealed class EntityFrameworkCoreCredentialStoreTests : IDisposable
{
    // One in-memory database per test, alive as long as this connection is open; each context gets its own
    // connection to it, as separate requests would.
    private readonly string _connectionString = $"Data Source=fido2-{Guid.NewGuid():N};Mode=Memory;Cache=Shared";
    private readonly SqliteConnection _keepAlive;

    public EntityFrameworkCoreCredentialStoreTests()
    {
        _keepAlive = new SqliteConnection(_connectionString);
        _keepAlive.Open();

        using var context = NewContext();
        context.Database.EnsureCreated();
    }

    public void Dispose() => _keepAlive.Dispose();

    private Fido2DbContext NewContext() => new(new DbContextOptionsBuilder<Fido2DbContext>().UseSqlite(_connectionString).Options);

    private EntityFrameworkCoreCredentialStore NewStore() => new(NewContext());

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
        var store = NewStore();
        var user = await store.GetOrAddUserAsync("erin", () => NewUser("erin", 5));
        var credential = NewCredential(signCount: signCount);
        await store.AddCredentialToUserAsync(user, credential);
        return credential;
    }

    private async Task<StoredCredential> ReloadAsync(byte[] id) => (await NewStore().GetCredentialByIdAsync(id))!;

    [Fact]
    public async Task GetOrAddUserAsync_CreatesTheUserOnlyOnceAsync()
    {
        var store = NewStore();

        var user = await store.GetOrAddUserAsync("alice", () => NewUser("alice", 1));
        var again = await store.GetOrAddUserAsync("alice", () => NewUser("alice", 2));

        Assert.Equal(user.Id, again.Id);
        Assert.Equal(user.Id, (await NewStore().GetUserAsync("alice"))!.Id);
    }

    [Fact]
    public async Task GetOrAddUserAsync_ReturnsTheUserAConcurrentRequestAddedAsync()
    {
        // The callback runs after this store found no user, so adding the same name from another context inside it
        // reproduces two requests racing to create one account.
        var store = NewStore();

        var user = await store.GetOrAddUserAsync("frank", () =>
        {
            using var other = NewContext();
            other.Fido2Users.Add(NewUser("frank", 6));
            other.SaveChanges();
            return NewUser("frank", 7);
        });

        Assert.Equal([6], user.Id);
        Assert.Single(await NewContext().Fido2Users.Where(u => u.Name == "frank").ToListAsync());
    }

    [Fact]
    public async Task GetOrAddUserAsync_RethrowsAFailureThatIsNotARaceAsync()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => NewStore().GetOrAddUserAsync("grace", () => new Fido2User { Name = null!, Id = [8], DisplayName = "Grace" }));

        Assert.Contains("grace", ex.Message);
    }

    [Fact]
    public async Task AddCredentialToUserAsync_StoresTheCredentialWithTheUsersIdAsync()
    {
        var store = NewStore();
        var user = await store.GetOrAddUserAsync("bob", () => NewUser("bob", 9));
        var credential = NewCredential();

        await store.AddCredentialToUserAsync(user, credential);

        var stored = await ReloadAsync(credential.Id);
        Assert.Equal(user.Id, stored.UserId);
        Assert.Equal(credential.Transports, stored.Transports);
    }

    [Fact]
    public async Task ACredentialCanOnlyBeRegisteredOnceAsync()
    {
        var store = NewStore();
        var user = await store.GetOrAddUserAsync("bob", () => NewUser("bob", 9));
        var id = Guid.NewGuid().ToByteArray();
        await store.AddCredentialToUserAsync(user, NewCredential(id));

        await Assert.ThrowsAsync<DbUpdateException>(() => NewStore().AddCredentialToUserAsync(user, NewCredential(id)));
    }

    [Fact]
    public async Task ACredentialNeedsAStoredUserAsync()
    {
        await Assert.ThrowsAsync<DbUpdateException>(() => NewStore().AddCredentialToUserAsync(NewUser("nobody", 99), NewCredential()));
    }

    [Fact]
    public async Task StoresTheLongestCredentialIdWebAuthnAllowsAsync()
    {
        var store = NewStore();
        var user = await store.GetOrAddUserAsync("long", () => NewUser("long", 10));
        var id = new byte[StoredCredentialConfiguration.MaxCredentialIdLength];
        Random.Shared.NextBytes(id);

        await store.AddCredentialToUserAsync(user, NewCredential(id));

        Assert.NotNull(await NewStore().GetCredentialByIdAsync(id));
    }

    [Fact]
    public async Task StoresACredentialWithoutTransportsAsync()
    {
        var store = NewStore();
        var user = await store.GetOrAddUserAsync("bare", () => NewUser("bare", 11));
        var credential = NewCredential();
        credential.Transports = null!;

        await store.AddCredentialToUserAsync(user, credential);

        var stored = await ReloadAsync(credential.Id);
        Assert.Null(stored.Transports);
    }

    [Fact]
    public async Task GetCredentialsByUserAsync_ReturnsOnlyThatUsersCredentialsAsync()
    {
        var store = NewStore();
        var alice = await store.GetOrAddUserAsync("alice", () => NewUser("alice", 1));
        var bob = await store.GetOrAddUserAsync("bob", () => NewUser("bob", 2));

        await store.AddCredentialToUserAsync(alice, NewCredential());
        await store.AddCredentialToUserAsync(alice, NewCredential());
        await store.AddCredentialToUserAsync(bob, NewCredential());

        Assert.Equal(2, (await NewStore().GetCredentialsByUserAsync(alice)).Count);
        Assert.Single(await NewStore().GetCredentialsByUserAsync(bob));
    }

    [Fact]
    public async Task GetCredentialsByUserHandleAsync_FindsTheDiscoverableCredentialAsync()
    {
        var store = NewStore();
        var user = await store.GetOrAddUserAsync("carol", () => NewUser("carol", 3));
        var userHandle = new byte[] { 3, 3, 3 };
        var credential = NewCredential(userHandle: userHandle);
        await store.AddCredentialToUserAsync(user, credential);

        var found = Assert.Single(await NewStore().GetCredentialsByUserHandleAsync(userHandle));

        Assert.Equal(credential.Id, found.Id);
    }

    [Fact]
    public async Task GetUsersByCredentialIdAsync_ResolvesTheOwningUserAsync()
    {
        var store = NewStore();
        var user = await store.GetOrAddUserAsync("dave", () => NewUser("dave", 4));
        var credential = NewCredential();
        await store.AddCredentialToUserAsync(user, credential);

        var owner = Assert.Single(await NewStore().GetUsersByCredentialIdAsync(credential.Id));

        Assert.Equal("dave", owner.Name);
    }

    [Fact]
    public async Task GetUsersByCredentialIdAsync_ReturnsEmptyForAnUnknownCredentialAsync()
    {
        Assert.Empty(await NewStore().GetUsersByCredentialIdAsync([0xde, 0xad]));
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_AppliesSignCountAndBackupStateAsync()
    {
        var credential = await RegisteredCredentialAsync(signCount: 1);

        await NewStore().UpdateCredentialRecordAsync(Assertion(credential.Id, 2, backedUp: true, userVerified: true));

        var stored = await ReloadAsync(credential.Id);
        Assert.Equal(2u, stored.SignCount);
        Assert.True(stored.IsBackedUp);
        // Promoting uvInitialized needs the caller's authorization.
        Assert.False(stored.UvInitialized);
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_PromotesUvInitializedOnlyWhenAuthorizedAndVerifiedAsync()
    {
        var credential = await RegisteredCredentialAsync(signCount: 1);

        await NewStore().UpdateCredentialRecordAsync(Assertion(credential.Id, 2, userVerified: false), uvInitializationAuthorized: true);
        Assert.False((await ReloadAsync(credential.Id)).UvInitialized);

        await NewStore().UpdateCredentialRecordAsync(Assertion(credential.Id, 3, userVerified: true), uvInitializationAuthorized: true);
        Assert.True((await ReloadAsync(credential.Id)).UvInitialized);

        // Never demoted.
        await NewStore().UpdateCredentialRecordAsync(Assertion(credential.Id, 4, userVerified: false));
        Assert.True((await ReloadAsync(credential.Id)).UvInitialized);
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_UpdatesACredentialWhoseCounterIsAlwaysZeroAsync()
    {
        // Most passkeys report 0 every time; the rule only applies once either counter is non-zero.
        var credential = await RegisteredCredentialAsync(signCount: 0);

        await NewStore().UpdateCredentialRecordAsync(Assertion(credential.Id, 0, backedUp: true));

        Assert.True((await ReloadAsync(credential.Id)).IsBackedUp);
    }

    [Theory]
    [InlineData(7u, 6u)]
    [InlineData(7u, 7u)]
    [InlineData(7u, 0u)]
    public async Task UpdateCredentialRecordAsync_RefusesACounterAnotherSignInHasAlreadyPassedAsync(uint alreadyStored, uint thisAssertion)
    {
        // Two sign-ins both verified against a counter of 5: one stores 7 first, then the slower one arrives.
        var credential = await RegisteredCredentialAsync(signCount: 5);
        await NewStore().UpdateCredentialRecordAsync(Assertion(credential.Id, alreadyStored));

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => NewStore().UpdateCredentialRecordAsync(Assertion(credential.Id, thisAssertion, backedUp: true)));

        Assert.Equal(Fido2ErrorCode.InvalidSignCount, ex.Code);
        var stored = await ReloadAsync(credential.Id);
        Assert.Equal(alreadyStored, stored.SignCount);
        Assert.False(stored.IsBackedUp);
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_RejectsAnUnknownCredentialAsync()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(() => NewStore().UpdateCredentialRecordAsync(Assertion([0xde, 0xad], 1)));
        await Assert.ThrowsAsync<ArgumentNullException>(() => NewStore().UpdateCredentialRecordAsync(null!));
    }

    [Fact]
    public async Task RemoveCredentialAsync_RemovesAKnownCredentialAndReportsTrueAsync()
    {
        var credential = await RegisteredCredentialAsync();

        Assert.True(await NewStore().RemoveCredentialAsync(credential.Id));
        Assert.Null(await NewStore().GetCredentialByIdAsync(credential.Id));
        Assert.False(await NewStore().RemoveCredentialAsync(credential.Id));
    }

    [Fact]
    public async Task DeletingAUserDeletesTheirCredentialsAsync()
    {
        var credential = await RegisteredCredentialAsync();

        using (var context = NewContext())
        {
            context.Fido2Users.Remove(await context.Fido2Users.SingleAsync(u => u.Name == "erin"));
            await context.SaveChangesAsync();
        }

        Assert.Null(await NewStore().GetCredentialByIdAsync(credential.Id));
    }

    private sealed class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : DbContext(options)
    {
        public DbSet<Order> Orders => Set<Order>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.ApplyConfigurationsFromAssembly(typeof(Fido2DbContext).Assembly);
        }
    }

    private sealed class Order
    {
        public int Id { get; set; }
    }

    [Fact]
    public async Task WorksInsideTheApplicationsOwnContextAsync()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();

        var services = new ServiceCollection();
        services.AddDbContext<ApplicationDbContext>(options => options.UseSqlite(connection));
        services.AddFido2EntityFrameworkCoreStore<ApplicationDbContext>();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ApplicationDbContext>().Database.EnsureCreated();
        var store = scope.ServiceProvider.GetRequiredService<ICredentialStore>();

        var user = await store.GetOrAddUserAsync("heidi", () => NewUser("heidi", 12));
        var credential = NewCredential(signCount: 1);
        await store.AddCredentialToUserAsync(user, credential);
        await store.UpdateCredentialRecordAsync(Assertion(credential.Id, 2));

        Assert.IsType<EntityFrameworkCoreCredentialStore<ApplicationDbContext>>(store);
        Assert.Equal(2u, (await store.GetCredentialByIdAsync(credential.Id))!.SignCount);
    }

    [Fact]
    public void TheRegistrationRejectsANullServiceCollection()
    {
        Assert.Throws<ArgumentNullException>(() => ((IServiceCollection)null!).AddFido2EntityFrameworkCoreStore<Fido2DbContext>());
    }
}
