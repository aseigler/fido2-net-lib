using System.Text.Json;

using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Microsoft.Extensions.DependencyInjection;

using Moq;

using StackExchange.Redis;

namespace Fido2NetLib.Redis.Tests;

/// <summary>
/// Unit-tests <see cref="RedisCredentialStore"/> in isolation against a mocked <see cref="IDatabase"/>, so its own
/// logic (which keys it reads/writes, how it interprets the update script's replies, index consistency) is
/// exercised without needing a real Redis server. This complements, but cannot replace,
/// <see cref="RedisCredentialStoreTests"/>: the Lua script named by
/// <c>RedisCredentialStore.UpdateCredentialRecordScript</c> runs server-side inside Redis, so no mock can prove the
/// script itself is correct -- only that this class sends it the right arguments and reacts correctly to each
/// possible reply the script can give. That gap is real and is only closed by the real-Redis tests.
/// </summary>
public sealed class RedisCredentialStoreMockTests
{
    private static readonly JsonSerializerOptions SerializerOptions = new();

    private readonly Mock<IDatabase> _db = new();
    private readonly RedisCredentialStore _store;

    public RedisCredentialStoreMockTests()
    {
        var mux = new Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(_db.Object);
        _store = new RedisCredentialStore(mux.Object, "fido2:");
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

    private void SetupStringGet(string key, RedisValue value) =>
        _db.Setup(d => d.StringGetAsync(new RedisKey(key), It.IsAny<CommandFlags>())).ReturnsAsync(value);

    // --- GetUserAsync ---

    [Fact]
    public async Task GetUserAsync_ReadsTheExpectedKeyAndReturnsNullWhenMissingAsync()
    {
        SetupStringGet("fido2:user:ghost", RedisValue.Null);

        var result = await _store.GetUserAsync("ghost");

        Assert.Null(result);
    }

    [Fact]
    public async Task GetUserAsync_DeserializesTheStoredUserAsync()
    {
        var user = NewUser("alice", 1);
        SetupStringGet("fido2:user:alice", JsonSerializer.Serialize(user, SerializerOptions));

        var result = await _store.GetUserAsync("alice");

        Assert.NotNull(result);
        Assert.Equal(user.Id, result!.Id);
        Assert.Equal("ALICE", result.DisplayName);
    }

    // --- GetOrAddUserAsync ---

    [Fact]
    public async Task GetOrAddUserAsync_ReturnsTheExistingUserWithoutWritingAsync()
    {
        var user = NewUser("bob", 2);
        SetupStringGet("fido2:user:bob", JsonSerializer.Serialize(user, SerializerOptions));

        var result = await _store.GetOrAddUserAsync("bob", () => throw new InvalidOperationException("should not be called"));

        Assert.Equal(user.Id, result.Id);
        _db.Verify(d => d.StringSetAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<TimeSpan?>(), It.IsAny<bool>(), It.IsAny<When>(), It.IsAny<CommandFlags>()), Times.Never());
    }

    [Fact]
    public async Task GetOrAddUserAsync_CreatesTheUserWithSetNxWhenAbsentAsync()
    {
        SetupStringGet("fido2:user:carol", RedisValue.Null);
        RedisValue? written = null;
        _db.Setup(d => d.StringSetAsync(new RedisKey("fido2:user:carol"), It.IsAny<RedisValue>(), It.IsAny<TimeSpan?>(), It.IsAny<bool>(), When.NotExists, It.IsAny<CommandFlags>()))
            .Callback<RedisKey, RedisValue, TimeSpan?, bool, When, CommandFlags>((_, v, _, _, _, _) => written = v)
            .ReturnsAsync(true);

        var user = NewUser("carol", 3);
        var result = await _store.GetOrAddUserAsync("carol", () => user);

        Assert.Equal(user.Id, result.Id);
        Assert.NotNull(written);
        Assert.Equal(user.Id, JsonSerializer.Deserialize<Fido2User>(written!.Value!, SerializerOptions)!.Id);
    }

    [Fact]
    public async Task GetOrAddUserAsync_LosingTheRaceReadsBackTheWinnersUserAsync()
    {
        var winner = NewUser("dave", 4);
        // The first read (before the callback) finds nothing; SET NX fails (someone else won); the second read
        // (after the callback) finds the winner's user.
        var calls = 0;
        _db.Setup(d => d.StringGetAsync(new RedisKey("fido2:user:dave"), It.IsAny<CommandFlags>()))
            .ReturnsAsync(() => calls++ == 0 ? RedisValue.Null : JsonSerializer.Serialize(winner, SerializerOptions));
        _db.Setup(d => d.StringSetAsync(new RedisKey("fido2:user:dave"), It.IsAny<RedisValue>(), It.IsAny<TimeSpan?>(), It.IsAny<bool>(), When.NotExists, It.IsAny<CommandFlags>()))
            .ReturnsAsync(false);

        var result = await _store.GetOrAddUserAsync("dave", () => NewUser("dave", 40));

        Assert.Equal(winner.Id, result.Id);
    }

    [Fact]
    public async Task GetOrAddUserAsync_ThrowsIfTheRaceCannotBeResolvedAsync()
    {
        SetupStringGet("fido2:user:erin", RedisValue.Null);
        _db.Setup(d => d.StringSetAsync(new RedisKey("fido2:user:erin"), It.IsAny<RedisValue>(), It.IsAny<TimeSpan?>(), It.IsAny<bool>(), When.NotExists, It.IsAny<CommandFlags>()))
            .ReturnsAsync(false);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => _store.GetOrAddUserAsync("erin", () => NewUser("erin", 5)));
        Assert.Contains("erin", ex.Message);
    }

    // --- GetCredentialsByUserAsync / GetCredentialsByUserHandleAsync ---

    [Fact]
    public async Task GetCredentialsByUserAsync_ReturnsEmptyWithoutReadingCredentialsWhenTheIndexIsEmptyAsync()
    {
        _db.Setup(d => d.SetMembersAsync(new RedisKey("fido2:usercreds:frank"), It.IsAny<CommandFlags>())).ReturnsAsync([]);

        var result = await _store.GetCredentialsByUserAsync(NewUser("frank", 6));

        Assert.Empty(result);
        _db.Verify(d => d.StringGetAsync(It.IsAny<RedisKey[]>(), It.IsAny<CommandFlags>()), Times.Never());
    }

    [Fact]
    public async Task GetCredentialsByUserAsync_ReadsEachIndexedCredentialAsync()
    {
        var credential = NewCredential();
        var hex = Convert.ToHexString(credential.Id);
        _db.Setup(d => d.SetMembersAsync(new RedisKey("fido2:usercreds:grace"), It.IsAny<CommandFlags>())).ReturnsAsync([hex]);
        _db.Setup(d => d.StringGetAsync(
                It.Is<RedisKey[]>(keys => keys.Length == 1 && keys[0] == new RedisKey($"fido2:cred:{hex}")),
                It.IsAny<CommandFlags>()))
            .ReturnsAsync([JsonSerializer.Serialize(credential, SerializerOptions)]);

        var result = await _store.GetCredentialsByUserAsync(NewUser("grace", 7));

        var found = Assert.Single(result);
        Assert.Equal(credential.Id, found.Id);
    }

    [Fact]
    public async Task GetCredentialsByUserAsync_SkipsAnIndexedIdThatNoLongerHasARecordAsync()
    {
        var hex = Convert.ToHexString(Guid.NewGuid().ToByteArray());
        _db.Setup(d => d.SetMembersAsync(new RedisKey("fido2:usercreds:henry"), It.IsAny<CommandFlags>())).ReturnsAsync([hex]);
        _db.Setup(d => d.StringGetAsync(It.IsAny<RedisKey[]>(), It.IsAny<CommandFlags>())).ReturnsAsync([RedisValue.Null]);

        var result = await _store.GetCredentialsByUserAsync(NewUser("henry", 8));

        Assert.Empty(result);
    }

    [Fact]
    public async Task GetCredentialsByUserHandleAsync_ReadsFromTheUserHandleIndexAsync()
    {
        var userHandle = new byte[] { 9, 9, 9 };
        var credential = NewCredential(userHandle: userHandle);
        var hex = Convert.ToHexString(credential.Id);
        _db.Setup(d => d.SetMembersAsync(new RedisKey($"fido2:userhandle:{Convert.ToHexString(userHandle)}:creds"), It.IsAny<CommandFlags>())).ReturnsAsync([hex]);
        _db.Setup(d => d.StringGetAsync(It.IsAny<RedisKey[]>(), It.IsAny<CommandFlags>())).ReturnsAsync([JsonSerializer.Serialize(credential, SerializerOptions)]);

        var result = await _store.GetCredentialsByUserHandleAsync(userHandle);

        var found = Assert.Single(result);
        Assert.Equal(credential.Id, found.Id);
    }

    // --- GetCredentialByIdAsync ---

    [Fact]
    public async Task GetCredentialByIdAsync_ReturnsNullWhenMissingAsync()
    {
        var id = Guid.NewGuid().ToByteArray();
        SetupStringGet($"fido2:cred:{Convert.ToHexString(id)}", RedisValue.Null);

        Assert.Null(await _store.GetCredentialByIdAsync(id));
    }

    [Fact]
    public async Task GetCredentialByIdAsync_DeserializesTheStoredCredentialAsync()
    {
        var credential = NewCredential();
        SetupStringGet($"fido2:cred:{Convert.ToHexString(credential.Id)}", JsonSerializer.Serialize(credential, SerializerOptions));

        var result = await _store.GetCredentialByIdAsync(credential.Id);

        Assert.NotNull(result);
        Assert.Equal(credential.Id, result!.Id);
    }

    // --- GetUsersByCredentialIdAsync ---

    [Fact]
    public async Task GetUsersByCredentialIdAsync_ReturnsEmptyWhenNoOwnerIsIndexedAsync()
    {
        var id = Guid.NewGuid().ToByteArray();
        SetupStringGet($"fido2:cred:{Convert.ToHexString(id)}:owner", RedisValue.Null);

        Assert.Empty(await _store.GetUsersByCredentialIdAsync(id));
    }

    [Fact]
    public async Task GetUsersByCredentialIdAsync_ReturnsEmptyWhenTheIndexedOwnerNoLongerExistsAsync()
    {
        var id = Guid.NewGuid().ToByteArray();
        SetupStringGet($"fido2:cred:{Convert.ToHexString(id)}:owner", "ivan");
        SetupStringGet("fido2:user:ivan", RedisValue.Null);

        Assert.Empty(await _store.GetUsersByCredentialIdAsync(id));
    }

    [Fact]
    public async Task GetUsersByCredentialIdAsync_ResolvesTheOwningUserAsync()
    {
        var id = Guid.NewGuid().ToByteArray();
        var user = NewUser("judy", 10);
        SetupStringGet($"fido2:cred:{Convert.ToHexString(id)}:owner", "judy");
        SetupStringGet("fido2:user:judy", JsonSerializer.Serialize(user, SerializerOptions));

        var owner = Assert.Single(await _store.GetUsersByCredentialIdAsync(id));
        Assert.Equal("judy", owner.Name);
    }

    // --- AddCredentialToUserAsync ---

    private (Mock<ITransaction> Tx, List<(RedisKey Key, RedisValue Value)> SetCalls, List<(RedisKey Key, RedisValue Value)> SetAddCalls) SetupTransaction(bool committed)
    {
        var tx = new Mock<ITransaction>();
        var setCalls = new List<(RedisKey, RedisValue)>();
        var setAddCalls = new List<(RedisKey, RedisValue)>();

        tx.Setup(t => t.AddCondition(It.IsAny<Condition>())).Returns((ConditionResult)null!);
        tx.Setup(t => t.StringSetAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<TimeSpan?>(), It.IsAny<bool>(), When.Always, It.IsAny<CommandFlags>()))
            .Callback<RedisKey, RedisValue, TimeSpan?, bool, When, CommandFlags>((k, v, _, _, _, _) => setCalls.Add((k, v)))
            .ReturnsAsync(true);
        tx.Setup(t => t.SetAddAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<CommandFlags>()))
            .Callback<RedisKey, RedisValue, CommandFlags>((k, v, _) => setAddCalls.Add((k, v)))
            .ReturnsAsync(true);
        tx.Setup(t => t.ExecuteAsync(It.IsAny<CommandFlags>())).ReturnsAsync(committed);

        _db.Setup(d => d.CreateTransaction(It.IsAny<object>())).Returns(tx.Object);
        return (tx, setCalls, setAddCalls);
    }

    [Fact]
    public async Task AddCredentialToUserAsync_WritesTheCredentialAndAllThreeIndexesInOneTransactionAsync()
    {
        var (tx, setCalls, setAddCalls) = SetupTransaction(committed: true);
        var user = NewUser("karen", 11);
        var credential = NewCredential(userHandle: [1, 2, 3]);

        await _store.AddCredentialToUserAsync(user, credential);

        tx.Verify(t => t.AddCondition(It.IsAny<Condition>()), Times.Once());
        Assert.Contains(setCalls, c => c.Key == new RedisKey($"fido2:cred:{Convert.ToHexString(credential.Id)}"));
        Assert.Contains(setCalls, c => c.Key == new RedisKey($"fido2:cred:{Convert.ToHexString(credential.Id)}:owner") && c.Value == "karen");
        Assert.Contains(setAddCalls, c => c.Key == new RedisKey("fido2:usercreds:karen") && c.Value == Convert.ToHexString(credential.Id));
        Assert.Contains(setAddCalls, c => c.Key == new RedisKey($"fido2:userhandle:{Convert.ToHexString(credential.UserHandle)}:creds") && c.Value == Convert.ToHexString(credential.Id));
        Assert.Equal(user.Id, credential.UserId);
    }

    [Theory]
    [InlineData("bob:creds")]
    [InlineData("bob:creds:x")]
    [InlineData("")]
    public async Task AUsernameCannotClaimAnotherUsersCredentialIndexAsync(string squatter)
    {
        // Usernames are chosen by whoever signs up. The user record written for the squatter must never land on
        // a key that holds bob's credential index -- the old "user:{name}:creds" scheme put the user "bob:creds"
        // exactly there, after which every write to bob's index failed with WRONGTYPE.
        var userRecordKeys = new List<RedisKey>();
        _db.Setup(d => d.StringGetAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>())).ReturnsAsync(RedisValue.Null);
        _db.Setup(d => d.StringSetAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<TimeSpan?>(), It.IsAny<bool>(), When.NotExists, It.IsAny<CommandFlags>()))
            .Callback<RedisKey, RedisValue, TimeSpan?, bool, When, CommandFlags>((k, _, _, _, _, _) => userRecordKeys.Add(k))
            .ReturnsAsync(true);
        await _store.GetOrAddUserAsync(squatter, () => NewUser(squatter, 1));

        var (_, setCalls, setAddCalls) = SetupTransaction(committed: true);
        await _store.AddCredentialToUserAsync(NewUser("bob", 2), NewCredential());

        var bobsKeys = setCalls.Select(c => c.Item1).Concat(setAddCalls.Select(c => c.Item1)).ToList();
        var squatterKey = Assert.Single(userRecordKeys);
        Assert.DoesNotContain(squatterKey, bobsKeys);
    }

    [Fact]
    public async Task AddCredentialToUserAsync_ThrowsWhenTheTransactionIsAbortedByTheConditionAsync()
    {
        SetupTransaction(committed: false);
        var user = NewUser("leo", 12);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => _store.AddCredentialToUserAsync(user, NewCredential()));
        Assert.Contains("already registered", ex.Message);
    }

    // --- UpdateCredentialRecordAsync ---

    private void SetupScript(byte[] credentialId, RedisResult result, Action<RedisKey[], RedisValue[]>? captureArgs = null) =>
        _db.Setup(d => d.ScriptEvaluateAsync(
                It.IsAny<string>(),
                It.Is<RedisKey[]>(keys => keys.Length == 1 && keys[0] == new RedisKey($"fido2:cred:{Convert.ToHexString(credentialId)}")),
                It.IsAny<RedisValue[]>(),
                It.IsAny<CommandFlags>()))
            .Callback<string, RedisKey[], RedisValue[], CommandFlags>((_, keys, values, _) => captureArgs?.Invoke(keys, values))
            .ReturnsAsync(result);

    [Fact]
    public async Task UpdateCredentialRecordAsync_RejectsANullAssertionAsync()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() => _store.UpdateCredentialRecordAsync(null!));
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_SendsTheSignCountBackupStateAndPromotionFlagToTheScriptAsync()
    {
        var id = Guid.NewGuid().ToByteArray();
        RedisValue[]? captured = null;
        SetupScript(id, RedisResult.Create((RedisValue)"ok"), (_, values) => captured = values);

        await _store.UpdateCredentialRecordAsync(Assertion(id, 5, backedUp: true, userVerified: true), uvInitializationAuthorized: true);

        Assert.NotNull(captured);
        Assert.Equal(5, (long)captured![0]);
        Assert.Equal("true", (string?)captured[1]);
        Assert.Equal("true", (string?)captured[2]);
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_DoesNotPromoteUvWithoutAuthorizationAsync()
    {
        var id = Guid.NewGuid().ToByteArray();
        RedisValue[]? captured = null;
        SetupScript(id, RedisResult.Create((RedisValue)"ok"), (_, values) => captured = values);

        await _store.UpdateCredentialRecordAsync(Assertion(id, 5, userVerified: true), uvInitializationAuthorized: false);

        Assert.Equal("false", (string?)captured![2]);
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_ThrowsWhenTheScriptReportsTheCredentialMissingAsync()
    {
        var id = Guid.NewGuid().ToByteArray();
        SetupScript(id, RedisResult.Create((RedisValue)"missing"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => _store.UpdateCredentialRecordAsync(Assertion(id, 1)));
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_ThrowsInvalidSignCountWhenTheScriptReportsStaleAsync()
    {
        var id = Guid.NewGuid().ToByteArray();
        SetupScript(id, RedisResult.Create((RedisValue)"stale"));

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => _store.UpdateCredentialRecordAsync(Assertion(id, 1)));
        Assert.Equal(Fido2ErrorCode.InvalidSignCount, ex.Code);
        Assert.Equal(RedisCredentialStore.StaleSignCountMessage, ex.Message);
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_ThrowsOnAnUnrecognizedScriptReplyAsync()
    {
        var id = Guid.NewGuid().ToByteArray();
        SetupScript(id, RedisResult.Create((RedisValue)"what-is-this"));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => _store.UpdateCredentialRecordAsync(Assertion(id, 1)));
        Assert.Contains("what-is-this", ex.Message);
    }

    // --- DI registration ---

    [Fact]
    public void AddFido2RedisStore_RegistersARedisCredentialStoreOverTheRegisteredMultiplexer()
    {
        var services = new ServiceCollection();
        var mux = new Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(_db.Object);
        services.AddSingleton(mux.Object);
        services.AddFido2RedisStore();

        using var provider = services.BuildServiceProvider();
        var store = provider.GetRequiredService<ICredentialStore>();

        Assert.IsType<RedisCredentialStore>(store);
    }

    [Fact]
    public void AddFido2RedisStore_RejectsANullServiceCollection()
    {
        Assert.Throws<ArgumentNullException>(() => ((IServiceCollection)null!).AddFido2RedisStore());
    }

    // --- RemoveCredentialAsync ---

    [Fact]
    public async Task RemoveCredentialAsync_ReturnsFalseWithoutStartingATransactionWhenUnknownAsync()
    {
        var id = Guid.NewGuid().ToByteArray();
        SetupStringGet($"fido2:cred:{Convert.ToHexString(id)}", RedisValue.Null);

        Assert.False(await _store.RemoveCredentialAsync(id));
        _db.Verify(d => d.CreateTransaction(It.IsAny<object>()), Times.Never());
    }

    [Fact]
    public async Task RemoveCredentialAsync_RemovesTheCredentialAndAllThreeIndexesAsync()
    {
        var credential = NewCredential(userHandle: [7, 7, 7]);
        var hex = Convert.ToHexString(credential.Id);
        SetupStringGet($"fido2:cred:{hex}", JsonSerializer.Serialize(credential, SerializerOptions));
        SetupStringGet($"fido2:cred:{hex}:owner", "mia");

        var (tx, _, _) = SetupTransaction(committed: true);
        var deleteCalls = new List<RedisKey>();
        var removeCalls = new List<(RedisKey Key, RedisValue Value)>();
        tx.Setup(t => t.KeyDeleteAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
            .Callback<RedisKey, CommandFlags>((k, _) => deleteCalls.Add(k))
            .ReturnsAsync(true);
        tx.Setup(t => t.SetRemoveAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<CommandFlags>()))
            .Callback<RedisKey, RedisValue, CommandFlags>((k, v, _) => removeCalls.Add((k, v)))
            .ReturnsAsync(true);

        var removed = await _store.RemoveCredentialAsync(credential.Id);

        Assert.True(removed);
        Assert.Contains(deleteCalls, k => k == new RedisKey($"fido2:cred:{hex}"));
        Assert.Contains(deleteCalls, k => k == new RedisKey($"fido2:cred:{hex}:owner"));
        Assert.Contains(removeCalls, c => c.Key == new RedisKey($"fido2:userhandle:{Convert.ToHexString(credential.UserHandle)}:creds") && c.Value == hex);
        Assert.Contains(removeCalls, c => c.Key == new RedisKey("fido2:usercreds:mia") && c.Value == hex);
    }

    [Fact]
    public async Task RemoveCredentialAsync_SkipsTheUserIndexWhenNoOwnerIsRecordedAsync()
    {
        var credential = NewCredential(userHandle: [8, 8, 8]);
        var hex = Convert.ToHexString(credential.Id);
        SetupStringGet($"fido2:cred:{hex}", JsonSerializer.Serialize(credential, SerializerOptions));
        SetupStringGet($"fido2:cred:{hex}:owner", RedisValue.Null);

        var (tx, _, _) = SetupTransaction(committed: true);
        var removeCalls = new List<(RedisKey Key, RedisValue Value)>();
        tx.Setup(t => t.KeyDeleteAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>())).ReturnsAsync(true);
        tx.Setup(t => t.SetRemoveAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<CommandFlags>()))
            .Callback<RedisKey, RedisValue, CommandFlags>((k, v, _) => removeCalls.Add((k, v)))
            .ReturnsAsync(true);

        Assert.True(await _store.RemoveCredentialAsync(credential.Id));

        Assert.DoesNotContain(removeCalls, c => c.Key == new RedisKey("fido2:usercreds:") || c.Key.ToString()!.StartsWith("fido2:usercreds:mia"));
        Assert.Single(removeCalls);
    }
}
