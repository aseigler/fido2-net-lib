using System.Text.Json;

using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using StackExchange.Redis;

namespace Fido2NetLib.Redis;

/// <summary>
/// An <see cref="ICredentialStore"/> backed by Redis.
/// </summary>
/// <remarks>
/// <para>
/// Redis has no native secondary index, so every lookup this interface needs -- by user, by credential ID, by
/// user handle, and the reverse "who owns this credential ID" lookup -- is served by a hand-maintained index
/// (a Redis Set of credential IDs per user or per user handle, and a single owner-username key per credential)
/// rather than a directory/table scan. <see cref="AddCredentialToUserAsync"/> and
/// <see cref="RemoveCredentialAsync"/> are the only places that write these indexes, and they do so inside a
/// single Redis transaction together with the credential record itself, so the indexes can never drift out of
/// sync with what they index -- there is no foreign key or cascade delete to fall back on if a caller bypassed
/// this class and wrote to Redis directly.
/// </para>
/// <para>
/// This store is only as durable as the Redis deployment it points at: unless the server has RDB or AOF
/// persistence enabled, credentials stored here do not survive a Redis restart. Enabling persistence is a
/// deployment concern for whoever runs the Redis instance, not something this class can enforce.
/// </para>
/// </remarks>
/// <param name="connectionMultiplexer">The connection to the Redis server holding the credential data.</param>
/// <param name="keyPrefix">A prefix applied to every key this store writes, to share a Redis instance with other data.</param>
public sealed class RedisCredentialStore(IConnectionMultiplexer connectionMultiplexer, string keyPrefix = "fido2:") : ICredentialStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new();

    // KEYS[1] = credential key.
    // ARGV[1] = new sign count. ARGV[2] = "true"/"false" backed-up. ARGV[3] = "true"/"false" promote uvInitialized.
    // Returns "missing", "stale", or "ok". Mirrors the EF Core store's single conditional UPDATE: the counter is
    // only ever accepted if it is greater than the stored one, or both are zero (an authenticator that does not
    // implement counters), and this whole read-compare-write happens in one atomic round trip on the server.
    private const string UpdateCredentialRecordScript = """
        local json = redis.call('GET', KEYS[1])
        if not json then
            return 'missing'
        end
        local cred = cjson.decode(json)
        local newCount = tonumber(ARGV[1])
        local oldCount = tonumber(cred['SignCount'])
        if not ((newCount == 0 and oldCount == 0) or oldCount < newCount) then
            return 'stale'
        end
        cred['SignCount'] = newCount
        cred['IsBackedUp'] = (ARGV[2] == 'true')
        if ARGV[3] == 'true' then
            cred['UvInitialized'] = true
        end
        redis.call('SET', KEYS[1], cjson.encode(cred))
        return 'ok'
        """;

    private IDatabase Database => connectionMultiplexer.GetDatabase();

    private RedisKey UserKey(string username) => (RedisKey)(keyPrefix + "user:" + username);

    private RedisKey UserCredentialsKey(string username) => (RedisKey)(keyPrefix + "user:" + username + ":creds");

    private RedisKey CredentialKey(byte[] credentialId) => (RedisKey)(keyPrefix + "cred:" + Convert.ToHexString(credentialId));

    private RedisKey CredentialOwnerKey(byte[] credentialId) => (RedisKey)(keyPrefix + "cred:" + Convert.ToHexString(credentialId) + ":owner");

    private RedisKey UserHandleCredentialsKey(byte[] userHandle) => (RedisKey)(keyPrefix + "userhandle:" + Convert.ToHexString(userHandle) + ":creds");

    /// <inheritdoc/>
    public async Task<Fido2User?> GetUserAsync(string username, CancellationToken cancellationToken = default)
    {
        var value = await Database.StringGetAsync(UserKey(username)).ConfigureAwait(false);
        return value.IsNullOrEmpty ? null : JsonSerializer.Deserialize<Fido2User>(value!, SerializerOptions);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Two requests adding the same name at once cannot both succeed: <c>SET ... NX</c> is atomic, so the one
    /// that loses the race reads back the user the other added instead of creating a second account.
    /// </remarks>
    public async Task<Fido2User> GetOrAddUserAsync(string username, Func<Fido2User> addCallback, CancellationToken cancellationToken = default)
    {
        var existing = await GetUserAsync(username, cancellationToken).ConfigureAwait(false);
        if (existing != null)
            return existing;

        var user = addCallback();
        var json = JsonSerializer.Serialize(user, SerializerOptions);

        var created = await Database.StringSetAsync(UserKey(username), json, when: When.NotExists).ConfigureAwait(false);
        if (created)
            return user;

        return await GetUserAsync(username, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Could not add or find the user '{username}'.");
    }

    /// <inheritdoc/>
    public async Task<List<StoredCredential>> GetCredentialsByUserAsync(Fido2User user, CancellationToken cancellationToken = default)
    {
        return await GetCredentialsAsync(UserCredentialsKey(user.Name)).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task<StoredCredential?> GetCredentialByIdAsync(byte[] id, CancellationToken cancellationToken = default)
    {
        var value = await Database.StringGetAsync(CredentialKey(id)).ConfigureAwait(false);
        return value.IsNullOrEmpty ? null : JsonSerializer.Deserialize<StoredCredential>(value!, SerializerOptions);
    }

    /// <inheritdoc/>
    public async Task<List<StoredCredential>> GetCredentialsByUserHandleAsync(byte[] userHandle, CancellationToken cancellationToken = default)
    {
        return await GetCredentialsAsync(UserHandleCredentialsKey(userHandle)).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task<List<Fido2User>> GetUsersByCredentialIdAsync(byte[] credentialId, CancellationToken cancellationToken = default)
    {
        var owner = await Database.StringGetAsync(CredentialOwnerKey(credentialId)).ConfigureAwait(false);
        if (owner.IsNullOrEmpty)
            return [];

        var user = await GetUserAsync(owner!, cancellationToken).ConfigureAwait(false);
        return user is null ? [] : [user];
    }

    /// <inheritdoc/>
    /// <remarks>
    /// The credential record and all three of its indexes (the per-user set, the per-user-handle set, and the
    /// owner-username key) are written in a single Redis transaction, conditioned on the credential key not
    /// already existing, so a credential can only ever be registered once and no index write can be observed
    /// without the others.
    /// </remarks>
    public async Task AddCredentialToUserAsync(Fido2User user, StoredCredential credential, CancellationToken cancellationToken = default)
    {
        credential.UserId = user.Id;
        var json = JsonSerializer.Serialize(credential, SerializerOptions);

        var transaction = Database.CreateTransaction();
        transaction.AddCondition(Condition.KeyNotExists(CredentialKey(credential.Id)));

        _ = transaction.StringSetAsync(CredentialKey(credential.Id), json);
        _ = transaction.SetAddAsync(UserCredentialsKey(user.Name), Convert.ToHexString(credential.Id));
        _ = transaction.StringSetAsync(CredentialOwnerKey(credential.Id), user.Name);
        _ = transaction.SetAddAsync(UserHandleCredentialsKey(credential.UserHandle), Convert.ToHexString(credential.Id));

        var committed = await transaction.ExecuteAsync().ConfigureAwait(false);
        if (!committed)
            throw new InvalidOperationException("A credential with this ID is already registered.");
    }

    /// <inheritdoc/>
    public async Task UpdateCredentialRecordAsync(VerifyAssertionResult assertionResult, bool uvInitializationAuthorized = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertionResult);

        var promoteUv = uvInitializationAuthorized && assertionResult.IsUserVerified;

        var result = (string?)await Database.ScriptEvaluateAsync(
            UpdateCredentialRecordScript,
            keys: [CredentialKey(assertionResult.CredentialId)],
            values: [assertionResult.SignCount, assertionResult.IsBackedUp ? "true" : "false", promoteUv ? "true" : "false"])
            .ConfigureAwait(false);

        switch (result)
        {
            case "ok":
                return;
            case "missing":
                throw new InvalidOperationException("No stored credential matches the asserted credential ID.");
            case "stale":
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidSignCount, StaleSignCountMessage);
            default:
                throw new InvalidOperationException($"Unexpected result '{result}' from the credential update script.");
        }
    }

    internal const string StaleSignCountMessage = "Another sign-in has already stored a signature counter at or above this assertion's; it may be a replay or a cloned authenticator";

    /// <inheritdoc/>
    /// <remarks>
    /// The owning username and user handle are read before the transaction that deletes the credential and its
    /// indexes; a concurrent <see cref="AddCredentialToUserAsync"/> racing between that read and the transaction
    /// (impossible in practice, since a credential ID is never reused) is the only window where this could leave
    /// a stale index entry behind.
    /// </remarks>
    public async Task<bool> RemoveCredentialAsync(byte[] credentialId, CancellationToken cancellationToken = default)
    {
        var credentialKey = CredentialKey(credentialId);
        var value = await Database.StringGetAsync(credentialKey).ConfigureAwait(false);
        if (value.IsNullOrEmpty)
            return false;

        var credential = JsonSerializer.Deserialize<StoredCredential>(value!, SerializerOptions)!;
        var owner = await Database.StringGetAsync(CredentialOwnerKey(credentialId)).ConfigureAwait(false);

        var transaction = Database.CreateTransaction();
        _ = transaction.KeyDeleteAsync(credentialKey);
        _ = transaction.KeyDeleteAsync(CredentialOwnerKey(credentialId));
        _ = transaction.SetRemoveAsync(UserHandleCredentialsKey(credential.UserHandle), Convert.ToHexString(credentialId));
        if (!owner.IsNullOrEmpty)
            _ = transaction.SetRemoveAsync(UserCredentialsKey(owner!), Convert.ToHexString(credentialId));

        await transaction.ExecuteAsync().ConfigureAwait(false);
        return true;
    }

    private async Task<List<StoredCredential>> GetCredentialsAsync(RedisKey indexKey)
    {
        var members = await Database.SetMembersAsync(indexKey).ConfigureAwait(false);
        if (members.Length == 0)
            return [];

        var keys = Array.ConvertAll(members, m => CredentialKey(Convert.FromHexString(m!)));
        var values = await Database.StringGetAsync(keys).ConfigureAwait(false);

        var credentials = new List<StoredCredential>(values.Length);
        foreach (var value in values)
        {
            if (!value.IsNullOrEmpty)
                credentials.Add(JsonSerializer.Deserialize<StoredCredential>(value!, SerializerOptions)!);
        }

        return credentials;
    }
}
