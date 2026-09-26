using Fido2NetLib.Exceptions;
using Fido2NetLib.MongoDb;
using Fido2NetLib.Objects;

using Microsoft.Extensions.DependencyInjection;

using Moq;

using MongoDB.Bson;
using MongoDB.Driver;

namespace Fido2NetLib.MongoDb.Tests;

/// <summary>
/// Unit-tests <see cref="MongoDbCredentialStore"/>'s own logic (the filters and updates it builds, its argument
/// validation, its branching) against mocked <see cref="IMongoDatabase"/>/<see cref="IMongoCollection{TDocument}"/>
/// instances, so it is covered without a real MongoDB server. <see cref="MongoDbCredentialStoreTests"/> covers the
/// real-server behaviour (indexes, atomic updates, duplicate-key handling) this can't reach.
/// </summary>
/// <remarks>
/// <c>IMongoCollection&lt;TDocument&gt;.Find</c> is a static extension method, not part of the interface, so it
/// cannot be mocked directly. Its real implementation builds a fluent wrapper that calls back into the mocked
/// collection's own <c>FindAsync</c> -- an actual interface member -- so tests mock that instead and let the real
/// (unmocked) <c>Find(...).FirstOrDefaultAsync()</c>/<c>ToListAsync()</c>/<c>AnyAsync()</c> extension chain run on
/// top of it.
/// </remarks>
public sealed class MongoDbCredentialStoreMockTests
{
    private static Mock<IAsyncCursor<T>> MockCursor<T>(IReadOnlyList<T> items)
    {
        var cursor = new Mock<IAsyncCursor<T>>();
        var served = false;
        cursor.Setup(c => c.Current).Returns(items);
        cursor.Setup(c => c.MoveNextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() =>
            {
                if (served)
                {
                    return false;
                }

                served = true;
                return true;
            });
        return cursor;
    }

    private static void SetupFind<T>(Mock<IMongoCollection<T>> collection, IReadOnlyList<T> items)
    {
        collection
            .Setup(c => c.FindAsync(It.IsAny<FilterDefinition<T>>(), It.IsAny<FindOptions<T, T>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(MockCursor(items).Object);
    }

    /// <summary>
    /// <c>IFindFluent&lt;T,T&gt;.AnyAsync()</c> resolves to <c>IFindFluentExtensions.AnyAsync</c> (more specific
    /// than <c>IAsyncCursorSourceExtensions.AnyAsync</c>), which projects to <see cref="BsonDocument"/> and calls
    /// <c>FindAsync</c> with <c>FindOptions&lt;T, BsonDocument&gt;</c> -- a different generic instantiation than
    /// plain reads use, so it needs its own mock setup rather than <see cref="SetupFind{T}"/>.
    /// </summary>
    private static void SetupAny<T>(Mock<IMongoCollection<T>> collection, bool any)
    {
        collection
            .Setup(c => c.FindAsync(It.IsAny<FilterDefinition<T>>(), It.IsAny<FindOptions<T, BsonDocument>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(MockCursor<BsonDocument>(any ? [new BsonDocument()] : []).Object);
    }

    private static (Mock<IMongoDatabase> Database, Mock<IMongoCollection<Fido2User>> Users, Mock<IMongoCollection<StoredCredential>> Credentials) NewMocks()
    {
        var database = new Mock<IMongoDatabase>();
        var users = new Mock<IMongoCollection<Fido2User>>();
        var credentials = new Mock<IMongoCollection<StoredCredential>>();

        database.Setup(d => d.GetCollection<Fido2User>("fido2.users", null)).Returns(users.Object);
        database.Setup(d => d.GetCollection<StoredCredential>("fido2.credentials", null)).Returns(credentials.Object);

        return (database, users, credentials);
    }

    private static Fido2User NewUser(string name, byte id) => new() { Name = name, Id = [id], DisplayName = name.ToUpperInvariant() };

    private static StoredCredential NewCredential(byte[]? id = null, byte[]? userId = null) => new()
    {
        Id = id ?? Guid.NewGuid().ToByteArray(),
        PublicKey = [1, 2, 3],
        UserId = userId ?? [9],
        UserHandle = Guid.NewGuid().ToByteArray(),
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

    [Fact]
    public void ConstructorRejectsANullDatabase()
    {
        Assert.Throws<ArgumentNullException>(() => new MongoDbCredentialStore(null!));
    }

    [Fact]
    public void ConstructorUsesTheConfiguredCollectionNames()
    {
        var database = new Mock<IMongoDatabase>();
        var users = new Mock<IMongoCollection<Fido2User>>();
        var credentials = new Mock<IMongoCollection<StoredCredential>>();
        database.Setup(d => d.GetCollection<Fido2User>("custom.users", null)).Returns(users.Object);
        database.Setup(d => d.GetCollection<StoredCredential>("custom.creds", null)).Returns(credentials.Object);

        _ = new MongoDbCredentialStore(database.Object, new MongoDbCredentialStoreOptions { UsersCollectionName = "custom.users", CredentialsCollectionName = "custom.creds" });

        database.Verify(d => d.GetCollection<Fido2User>("custom.users", null), Times.Once);
        database.Verify(d => d.GetCollection<StoredCredential>("custom.creds", null), Times.Once);
    }

    [Fact]
    public async Task EnsureIndexesCreatedAsync_CreatesTheUniqueUsernameIndexAndTheCredentialLookupIndexesAsync()
    {
        var (database, users, credentials) = NewMocks();
        var userIndexes = new Mock<IMongoIndexManager<Fido2User>>();
        var credentialIndexes = new Mock<IMongoIndexManager<StoredCredential>>();
        users.Setup(u => u.Indexes).Returns(userIndexes.Object);
        credentials.Setup(c => c.Indexes).Returns(credentialIndexes.Object);
        userIndexes
            .Setup(i => i.CreateOneAsync(It.IsAny<CreateIndexModel<Fido2User>>(), It.IsAny<CreateOneIndexOptions>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync("name_1");
        credentialIndexes
            .Setup(i => i.CreateManyAsync(It.IsAny<IEnumerable<CreateIndexModel<StoredCredential>>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(["userId_1", "userHandle_1"]);

        await new MongoDbCredentialStore(database.Object).EnsureIndexesCreatedAsync();

        userIndexes.Verify(
            i => i.CreateOneAsync(It.Is<CreateIndexModel<Fido2User>>(m => m.Options.Unique == true), It.IsAny<CreateOneIndexOptions>(), It.IsAny<CancellationToken>()),
            Times.Once);
        credentialIndexes.Verify(
            i => i.CreateManyAsync(It.Is<IEnumerable<CreateIndexModel<StoredCredential>>>(models => models.Count() == 2), It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task GetUserAsync_ReturnsNullWhenThereIsNoMatchAsync()
    {
        var (database, users, _) = NewMocks();
        SetupFind(users, []);

        Assert.Null(await new MongoDbCredentialStore(database.Object).GetUserAsync("nobody"));
    }

    [Fact]
    public async Task GetUserAsync_ReturnsTheMatchingUserAsync()
    {
        var (database, users, _) = NewMocks();
        var user = NewUser("alice", 1);
        SetupFind(users, [user]);

        var found = await new MongoDbCredentialStore(database.Object).GetUserAsync("alice");

        Assert.Equal(user.Id, found!.Id);
    }

    [Fact]
    public async Task GetOrAddUserAsync_ReturnsTheExistingUserWithoutInsertingAsync()
    {
        var (database, users, _) = NewMocks();
        var existing = NewUser("alice", 1);
        SetupFind(users, [existing]);

        var user = await new MongoDbCredentialStore(database.Object).GetOrAddUserAsync("alice", () => throw new InvalidOperationException("should not be called"));

        Assert.Equal(existing.Id, user.Id);
        users.Verify(u => u.InsertOneAsync(It.IsAny<Fido2User>(), It.IsAny<InsertOneOptions>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task GetOrAddUserAsync_InsertsAndReturnsANewUserWhenNoneExistsAsync()
    {
        var (database, users, _) = NewMocks();
        SetupFind(users, []);
        users.Setup(u => u.InsertOneAsync(It.IsAny<Fido2User>(), It.IsAny<InsertOneOptions>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);

        var user = await new MongoDbCredentialStore(database.Object).GetOrAddUserAsync("bob", () => NewUser("bob", 9));

        Assert.Equal("bob", user.Name);
        users.Verify(u => u.InsertOneAsync(It.Is<Fido2User>(u => u.Name == "bob"), It.IsAny<InsertOneOptions>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    // GetOrAddUserAsync's catch of a duplicate-key MongoWriteException (the concurrent-insert race) is NOT covered
    // here: MongoDB.Driver's WriteError has no public constructor, so a real MongoWriteException with
    // WriteError.Category == DuplicateKey cannot be built from outside the driver. Only a live server (or a fake
    // that actually enforces the unique index) can trigger this branch -- see the Testcontainers-backed
    // ACredentialCanOnlyBeRegisteredOnceAsync-equivalent coverage for the parallel case on the credentials
    // collection, which the store relies on the same way.

    [Fact]
    public async Task GetCredentialsByUserAsync_RejectsANullUser()
    {
        var (database, _, _) = NewMocks();
        await Assert.ThrowsAsync<ArgumentNullException>(() => new MongoDbCredentialStore(database.Object).GetCredentialsByUserAsync(null!));
    }

    [Fact]
    public async Task GetCredentialsByUserAsync_ReturnsThatUsersCredentialsAsync()
    {
        var (database, _, credentials) = NewMocks();
        var credential = NewCredential(userId: [1]);
        SetupFind(credentials, [credential]);

        var found = await new MongoDbCredentialStore(database.Object).GetCredentialsByUserAsync(NewUser("alice", 1));

        Assert.Equal(credential.Id, Assert.Single(found).Id);
    }

    [Fact]
    public async Task GetCredentialByIdAsync_ReturnsNullWhenThereIsNoMatchAsync()
    {
        var (database, _, credentials) = NewMocks();
        SetupFind(credentials, []);

        Assert.Null(await new MongoDbCredentialStore(database.Object).GetCredentialByIdAsync([0xde, 0xad]));
    }

    [Fact]
    public async Task GetCredentialByIdAsync_ReturnsTheMatchingCredentialAsync()
    {
        var (database, _, credentials) = NewMocks();
        var credential = NewCredential();
        SetupFind(credentials, [credential]);

        var found = await new MongoDbCredentialStore(database.Object).GetCredentialByIdAsync(credential.Id);

        Assert.Equal(credential.Id, found!.Id);
    }

    [Fact]
    public async Task GetCredentialsByUserHandleAsync_ReturnsTheMatchingCredentialsAsync()
    {
        var (database, _, credentials) = NewMocks();
        var credential = NewCredential();
        SetupFind(credentials, [credential]);

        var found = await new MongoDbCredentialStore(database.Object).GetCredentialsByUserHandleAsync(credential.UserHandle);

        Assert.Equal(credential.Id, Assert.Single(found).Id);
    }

    [Fact]
    public async Task GetUsersByCredentialIdAsync_ReturnsEmptyWhenTheCredentialIsUnknownAsync()
    {
        var (database, _, credentials) = NewMocks();
        SetupFind(credentials, []);

        Assert.Empty(await new MongoDbCredentialStore(database.Object).GetUsersByCredentialIdAsync([0xde, 0xad]));
    }

    [Fact]
    public async Task GetUsersByCredentialIdAsync_ReturnsEmptyWhenTheCredentialsOwnerIsGoneAsync()
    {
        var (database, users, credentials) = NewMocks();
        var credential = NewCredential(userId: [7]);
        SetupFind(credentials, [credential]);
        SetupFind(users, []);

        Assert.Empty(await new MongoDbCredentialStore(database.Object).GetUsersByCredentialIdAsync(credential.Id));
    }

    [Fact]
    public async Task GetUsersByCredentialIdAsync_ResolvesTheOwningUserAsync()
    {
        var (database, users, credentials) = NewMocks();
        var owner = NewUser("dave", 4);
        var credential = NewCredential(userId: owner.Id);
        SetupFind(credentials, [credential]);
        SetupFind(users, [owner]);

        var found = await new MongoDbCredentialStore(database.Object).GetUsersByCredentialIdAsync(credential.Id);

        Assert.Equal("dave", Assert.Single(found).Name);
    }

    [Fact]
    public async Task AddCredentialToUserAsync_RejectsNullArguments()
    {
        var (database, _, _) = NewMocks();
        var store = new MongoDbCredentialStore(database.Object);

        await Assert.ThrowsAsync<ArgumentNullException>(() => store.AddCredentialToUserAsync(null!, NewCredential()));
        await Assert.ThrowsAsync<ArgumentNullException>(() => store.AddCredentialToUserAsync(NewUser("a", 1), null!));
    }

    [Fact]
    public async Task AddCredentialToUserAsync_StampsTheCredentialWithTheUsersIdBeforeInsertingAsync()
    {
        var (database, _, credentials) = NewMocks();
        credentials.Setup(c => c.InsertOneAsync(It.IsAny<StoredCredential>(), It.IsAny<InsertOneOptions>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        var user = NewUser("bob", 9);
        var credential = NewCredential();

        await new MongoDbCredentialStore(database.Object).AddCredentialToUserAsync(user, credential);

        Assert.Equal(user.Id, credential.UserId);
        credentials.Verify(c => c.InsertOneAsync(It.Is<StoredCredential>(c => c.UserId == user.Id), It.IsAny<InsertOneOptions>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_RejectsANullAssertion()
    {
        var (database, _, _) = NewMocks();
        await Assert.ThrowsAsync<ArgumentNullException>(() => new MongoDbCredentialStore(database.Object).UpdateCredentialRecordAsync(null!));
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_ReturnsWhenTheConditionalUpdateModifiedTheDocumentAsync()
    {
        var (database, _, credentials) = NewMocks();
        credentials
            .Setup(c => c.UpdateOneAsync(It.IsAny<FilterDefinition<StoredCredential>>(), It.IsAny<UpdateDefinition<StoredCredential>>(), It.IsAny<UpdateOptions>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new UpdateResult.Acknowledged(1, 1, null));

        // No exception means success; the store never has to fall back to the exists-check below.
        await new MongoDbCredentialStore(database.Object).UpdateCredentialRecordAsync(Assertion([1, 2, 3], 5));
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_UpdatesACredentialWhoseCounterIsAlwaysZeroAsync()
    {
        // Exercises the signCount == 0 side of the counter-condition ternary; every other test here uses a
        // non-zero counter, which only ever takes the Lt(...) branch.
        var (database, _, credentials) = NewMocks();
        credentials
            .Setup(c => c.UpdateOneAsync(It.IsAny<FilterDefinition<StoredCredential>>(), It.IsAny<UpdateDefinition<StoredCredential>>(), It.IsAny<UpdateOptions>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new UpdateResult.Acknowledged(1, 1, null));

        await new MongoDbCredentialStore(database.Object).UpdateCredentialRecordAsync(Assertion([1, 2, 3], 0, backedUp: true));
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_PromotesUvInitializedWhenAuthorizedAndVerifiedAsync()
    {
        // Exercises both operands of "uvInitializationAuthorized && assertionResult.IsUserVerified" being true;
        // every other test here leaves at least one of them false/default.
        var (database, _, credentials) = NewMocks();
        credentials
            .Setup(c => c.UpdateOneAsync(It.IsAny<FilterDefinition<StoredCredential>>(), It.IsAny<UpdateDefinition<StoredCredential>>(), It.IsAny<UpdateOptions>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new UpdateResult.Acknowledged(1, 1, null));

        await new MongoDbCredentialStore(database.Object).UpdateCredentialRecordAsync(
            Assertion([1, 2, 3], 5, userVerified: true), uvInitializationAuthorized: true);
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_RejectsAnUnknownCredentialAsync()
    {
        var (database, _, credentials) = NewMocks();
        credentials
            .Setup(c => c.UpdateOneAsync(It.IsAny<FilterDefinition<StoredCredential>>(), It.IsAny<UpdateDefinition<StoredCredential>>(), It.IsAny<UpdateOptions>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new UpdateResult.Acknowledged(0, 0, null));
        SetupFind(credentials, []);
        SetupAny(credentials, any: false);

        await Assert.ThrowsAsync<InvalidOperationException>(() => new MongoDbCredentialStore(database.Object).UpdateCredentialRecordAsync(Assertion([1, 2, 3], 5)));
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_RefusesAStaleCounterAsync()
    {
        var (database, _, credentials) = NewMocks();
        var existing = NewCredential(id: [1, 2, 3]);
        credentials
            .Setup(c => c.UpdateOneAsync(It.IsAny<FilterDefinition<StoredCredential>>(), It.IsAny<UpdateDefinition<StoredCredential>>(), It.IsAny<UpdateOptions>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new UpdateResult.Acknowledged(1, 0, null));
        SetupFind(credentials, [existing]);
        SetupAny(credentials, any: true);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => new MongoDbCredentialStore(database.Object).UpdateCredentialRecordAsync(Assertion([1, 2, 3], 5)));

        Assert.Equal(Fido2ErrorCode.InvalidSignCount, ex.Code);
    }

    [Fact]
    public async Task RemoveCredentialAsync_ReportsWhetherACredentialWasRemovedAsync()
    {
        var (database, _, credentials) = NewMocks();
        credentials.SetupSequence(c => c.DeleteOneAsync(It.IsAny<FilterDefinition<StoredCredential>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DeleteResult.Acknowledged(1))
            .ReturnsAsync(new DeleteResult.Acknowledged(0));
        var store = new MongoDbCredentialStore(database.Object);

        Assert.True(await store.RemoveCredentialAsync([1, 2, 3]));
        Assert.False(await store.RemoveCredentialAsync([1, 2, 3]));
    }

    [Fact]
    public void AddFido2MongoDbStore_RegistersTheStoreOverARegisteredDatabase()
    {
        var (database, _, _) = NewMocks();
        var services = (IServiceCollection)new ServiceCollection();
        services.AddSingleton(database.Object);

        services.AddFido2MongoDbStore();

        using var provider = services.BuildServiceProvider();
        var store = provider.GetRequiredService<ICredentialStore>();
        Assert.IsType<MongoDbCredentialStore>(store);
    }

    [Fact]
    public async Task GetOrAddUserAsync_ReturnsTheUserAConcurrentRequestAddedAsync()
    {
        var (database, users, _) = NewMocks();
        var winner = new Fido2User { Name = "frank", Id = [6], DisplayName = "FRANK" };
        users
            .Setup(u => u.InsertOneAsync(It.IsAny<Fido2User>(), It.IsAny<InsertOneOptions>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(MakeDuplicateKeyException());
        users
            .SetupSequence(u => u.FindAsync(It.IsAny<FilterDefinition<Fido2User>>(), It.IsAny<FindOptions<Fido2User, Fido2User>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(MockCursor<Fido2User>([]).Object)
            .ReturnsAsync(MockCursor([winner]).Object);

        var user = await new MongoDbCredentialStore(database.Object).GetOrAddUserAsync("frank", () => new Fido2User { Name = "frank", Id = [7], DisplayName = "FRANK" });

        Assert.Equal(winner.Id, user.Id);
    }

    [Fact]
    public async Task GetOrAddUserAsync_RethrowsWhenTheRaceLoserStillFindsNoOneAsync()
    {
        var (database, users, _) = NewMocks();
        users
            .Setup(u => u.InsertOneAsync(It.IsAny<Fido2User>(), It.IsAny<InsertOneOptions>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(MakeDuplicateKeyException());
        SetupFind(users, []);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => new MongoDbCredentialStore(database.Object).GetOrAddUserAsync("ghost", () => new Fido2User { Name = "ghost", Id = [9], DisplayName = "GHOST" }));
    }

    /// <summary>
    /// <see cref="WriteError"/>'s constructor is internal to the driver, so the one way to build a
    /// <see cref="MongoWriteException"/> carrying a <see cref="ServerErrorCategory.DuplicateKey"/> error from test
    /// code is reflection.
    /// </summary>
    private static MongoWriteException MakeDuplicateKeyException()
    {
        var writeErrorCtor = typeof(WriteError).GetConstructor(
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance,
            [typeof(ServerErrorCategory), typeof(int), typeof(string), typeof(BsonDocument)])!;
        var writeError = (WriteError)writeErrorCtor.Invoke([ServerErrorCategory.DuplicateKey, 11000, "duplicate key", new BsonDocument()]);

        var connectionId = new MongoDB.Driver.Core.Connections.ConnectionId(
            new MongoDB.Driver.Core.Servers.ServerId(new MongoDB.Driver.Core.Clusters.ClusterId(), new System.Net.DnsEndPoint("localhost", 27017)));

        return new MongoWriteException(connectionId, writeError, null, null);
    }

    /// <summary>
    /// <see cref="Fido2MongoDbClassMaps.EnsureRegistered"/> double-checks under a lock so a losing thread's inner
    /// check (finding registration already done by the winner) only fires under real concurrency; this forces
    /// that race by resetting the private "registered" flag via reflection and calling it from many threads at
    /// once, rather than relying on chance to hit it during the rest of this suite.
    /// </summary>
    [Fact]
    public void EnsureRegistered_IsSafeUnderConcurrentFirstCalls()
    {
        var classMapsType = typeof(MongoDbCredentialStore).Assembly.GetType("Fido2NetLib.MongoDb.Fido2MongoDbClassMaps")!;
        var registeredField = classMapsType.GetField("_registered", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var gateField = classMapsType.GetField("_gate", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var ensureRegistered = classMapsType.GetMethod("EnsureRegistered", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)!;
        var gate = gateField.GetValue(null)!;
        registeredField.SetValue(null, false);

        // Widen the double-checked lock's race window on purpose: hold the gate open while every thread piles up
        // past the outer check (all seeing "not registered yet"), then release them together so more than one is
        // guaranteed to reach the inner check after the first has already set the flag.
        const int threadCount = 32;
        var readyToRace = new System.Threading.Barrier(threadCount);
        var threads = new System.Threading.Thread[threadCount];
        lock (gate)
        {
            for (var i = 0; i < threadCount; i++)
            {
                threads[i] = new System.Threading.Thread(() =>
                {
                    readyToRace.SignalAndWait();
                    ensureRegistered.Invoke(null, null);
                });
                threads[i].Start();
            }

            // Give every thread a chance to clear the outer check and start waiting on the gate before it opens.
            System.Threading.Thread.Sleep(50);
        }

        foreach (var thread in threads)
        {
            thread.Join();
        }

        Assert.True((bool)registeredField.GetValue(null)!);
    }
}
