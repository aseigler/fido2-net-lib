using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using MongoDB.Bson;
using MongoDB.Driver;

namespace Fido2NetLib.MongoDb;

/// <summary>
/// An <see cref="ICredentialStore"/> over MongoDB, using one collection of <see cref="Fido2User"/> documents and one
/// of <see cref="StoredCredential"/> documents.
/// </summary>
/// <remarks>
/// <see cref="EnsureIndexesCreatedAsync"/> must be called once (e.g. at application startup) before the store is
/// used: the unique index on the username is what makes <see cref="GetOrAddUserAsync"/> race-safe, the same way the
/// EF Core store relies on a unique database constraint rather than application-level locking.
/// </remarks>
public sealed class MongoDbCredentialStore : ICredentialStore
{
    /// <summary>
    /// A sign count another sign-in has already passed cannot be reused.
    /// </summary>
    internal const string StaleSignCountMessage = "Another sign-in has already stored a signature counter at or above this assertion's; it may be a replay or a cloned authenticator";

    private readonly IMongoCollection<Fido2User> _users;
    private readonly IMongoCollection<StoredCredential> _credentials;

    /// <summary>
    /// Creates the store over collections in <paramref name="database"/>, named per <paramref name="options"/>.
    /// </summary>
    /// <param name="database">The database the users and credentials collections live in.</param>
    /// <param name="options">The collection names to use; defaults are used when omitted.</param>
    public MongoDbCredentialStore(IMongoDatabase database, MongoDbCredentialStoreOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(database);
        options ??= new MongoDbCredentialStoreOptions();

        Fido2MongoDbClassMaps.EnsureRegistered();

        _users = database.GetCollection<Fido2User>(options.UsersCollectionName);
        _credentials = database.GetCollection<StoredCredential>(options.CredentialsCollectionName);
    }

    /// <summary>
    /// Creates the unique index on the username and the lookup indexes credential queries rely on. Idempotent: safe
    /// to call every time the application starts.
    /// </summary>
    public async Task EnsureIndexesCreatedAsync(CancellationToken cancellationToken = default)
    {
        await _users.Indexes.CreateOneAsync(
            new CreateIndexModel<Fido2User>(
                Builders<Fido2User>.IndexKeys.Ascending(u => u.Name),
                new CreateIndexOptions { Unique = true }),
            cancellationToken: cancellationToken);

        await _credentials.Indexes.CreateManyAsync(
            [
                new CreateIndexModel<StoredCredential>(Builders<StoredCredential>.IndexKeys.Ascending(c => c.UserId)),
                new CreateIndexModel<StoredCredential>(Builders<StoredCredential>.IndexKeys.Ascending(c => c.UserHandle)),
            ],
            cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<Fido2User?> GetUserAsync(string username, CancellationToken cancellationToken = default)
    {
        return await _users.Find(Builders<Fido2User>.Filter.Eq(u => u.Name, username)).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Two requests adding the same name at once cannot both succeed: the unique index on the username rejects the
    /// second insert, and the loser reads back the user the other one added instead of creating a second account.
    /// </remarks>
    public async Task<Fido2User> GetOrAddUserAsync(string username, Func<Fido2User> addCallback, CancellationToken cancellationToken = default)
    {
        var existing = await GetUserAsync(username, cancellationToken);
        if (existing is not null)
        {
            return existing;
        }

        var user = addCallback();

        try
        {
            await _users.InsertOneAsync(user, options: null, cancellationToken);
            return user;
        }
        catch (MongoWriteException ex) when (ex.WriteError?.Category == ServerErrorCategory.DuplicateKey)
        {
            return await GetUserAsync(username, cancellationToken)
                ?? throw new InvalidOperationException($"Could not add or find the user '{username}'.");
        }
    }

    /// <inheritdoc/>
    public async Task<List<StoredCredential>> GetCredentialsByUserAsync(Fido2User user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);

        return await _credentials.Find(Builders<StoredCredential>.Filter.Eq(c => c.UserId, user.Id)).ToListAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<StoredCredential?> GetCredentialByIdAsync(byte[] id, CancellationToken cancellationToken = default)
    {
        return await _credentials.Find(Builders<StoredCredential>.Filter.Eq(c => c.Id, id)).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<List<StoredCredential>> GetCredentialsByUserHandleAsync(byte[] userHandle, CancellationToken cancellationToken = default)
    {
        return await _credentials.Find(Builders<StoredCredential>.Filter.Eq(c => c.UserHandle, userHandle)).ToListAsync(cancellationToken);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// The credential ID is the collection's <c>_id</c>, so at most one credential -- and so at most one owning
    /// user -- can ever match.
    /// </remarks>
    public async Task<List<Fido2User>> GetUsersByCredentialIdAsync(byte[] credentialId, CancellationToken cancellationToken = default)
    {
        var credential = await GetCredentialByIdAsync(credentialId, cancellationToken);
        if (credential is null)
        {
            return [];
        }

        var user = await _users.Find(Builders<Fido2User>.Filter.Eq(u => u.Id, credential.UserId)).FirstOrDefaultAsync(cancellationToken);
        return user is null ? [] : [user];
    }

    /// <inheritdoc/>
    /// <remarks>
    /// The credential ID is the collection's <c>_id</c>, so a credential already registered under that ID makes
    /// this insert fail with a duplicate-key error, the same way the EF Core store relies on a unique constraint.
    /// </remarks>
    public async Task AddCredentialToUserAsync(Fido2User user, StoredCredential credential, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(credential);

        credential.UserId = user.Id;
        await _credentials.InsertOneAsync(credential, options: null, cancellationToken);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// One atomic conditional update -- applied only while the stored counter is still below this assertion's (or
    /// both are zero) -- so concurrent sign-ins cannot move it backwards, and an aggregation-pipeline <c>$set</c> so
    /// <c>UvInitialized</c> is promoted from its own current value rather than a value read earlier in this method.
    /// </remarks>
    public async Task UpdateCredentialRecordAsync(VerifyAssertionResult assertionResult, bool uvInitializationAuthorized = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertionResult);

        var credentialId = assertionResult.CredentialId;
        var signCount = assertionResult.SignCount;
        var isBackedUp = assertionResult.IsBackedUp;
        var promoteUv = uvInitializationAuthorized && assertionResult.IsUserVerified;

        var counterCondition = signCount == 0
            ? Builders<StoredCredential>.Filter.Eq(c => c.SignCount, 0u)
            : Builders<StoredCredential>.Filter.Lt(c => c.SignCount, signCount);

        var filter = Builders<StoredCredential>.Filter.And(
            Builders<StoredCredential>.Filter.Eq(c => c.Id, credentialId),
            counterCondition);

        var setStage = new BsonDocument("$set", new BsonDocument
        {
            { "SignCount", (long)signCount },
            { "IsBackedUp", isBackedUp },
            { "UvInitialized", new BsonDocument("$or", new BsonArray { "$UvInitialized", promoteUv }) },
        });

        var update = Builders<StoredCredential>.Update.Pipeline(PipelineDefinition<StoredCredential, StoredCredential>.Create([setStage]));

        var result = await _credentials.UpdateOneAsync(filter, update, cancellationToken: cancellationToken);

        if (result.ModifiedCount > 0)
        {
            return;
        }

        var exists = await _credentials.Find(Builders<StoredCredential>.Filter.Eq(c => c.Id, credentialId)).AnyAsync(cancellationToken);
        if (!exists)
        {
            throw new InvalidOperationException("No stored credential matches the asserted credential ID.");
        }

        throw new Fido2VerificationException(Fido2ErrorCode.InvalidSignCount, StaleSignCountMessage);
    }

    /// <inheritdoc/>
    public async Task<bool> RemoveCredentialAsync(byte[] credentialId, CancellationToken cancellationToken = default)
    {
        var result = await _credentials.DeleteOneAsync(Builders<StoredCredential>.Filter.Eq(c => c.Id, credentialId), cancellationToken);
        return result.DeletedCount > 0;
    }
}
