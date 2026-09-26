using System.Net;

using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Microsoft.Azure.Cosmos;

namespace Fido2NetLib.Cosmos;

/// <summary>
/// An <see cref="ICredentialStore"/> backed by a single Azure Cosmos DB <see cref="Container"/>, using the native
/// Cosmos SDK rather than the generic EF Core Cosmos provider so partitioning can be modeled deliberately.
/// </summary>
/// <remarks>
/// <para>
/// The container holds three kinds of items, discriminated by a <c>type</c> field: a username-lookup item
/// (partitioned by the username itself, so a username can be claimed exactly once cluster-wide), a user item, and
/// one item per credential (both partitioned by the owning user's ID, base64url-encoded, so
/// <see cref="GetCredentialsByUserAsync"/> is a single-partition query and registering/removing a credential is a
/// point operation). The container must already exist with partition key path <c>/partitionKey</c>; this store
/// does not create it -- provisioning throughput belongs to deployment, not application startup.
/// </para>
/// <para>
/// <see cref="GetCredentialByIdAsync"/>, <see cref="GetUsersByCredentialIdAsync"/>, and
/// <see cref="GetCredentialsByUserHandleAsync"/> look a credential up by something other than its partition key,
/// so they run as cross-partition queries. Cosmos indexes every property by default, so these still use the
/// index -- they are simply not confined to one partition, which costs more RUs and latency than a point read as
/// the container grows. This is a deliberate, documented tradeoff (the same class of tradeoff DynamoDB's global
/// secondary indexes make) rather than something this store tries to eliminate.
/// </para>
/// <para>
/// A credential ID is only guaranteed unique within the user's own partition (<see cref="AddCredentialToUserAsync"/>
/// uses <see cref="Container.CreateItemAsync{T}(T, PartitionKey?, ItemRequestOptions?, CancellationToken)"/>, which
/// rejects a duplicate item id within a partition). Nothing in this container enforces global uniqueness of a
/// credential ID across every user's partition; the caller must still run the
/// <c>IsCredentialIdUniqueToUserAsyncDelegate</c> check (via <see cref="GetUsersByCredentialIdAsync"/>) before
/// registration, same as with any other store.
/// </para>
/// </remarks>
/// <param name="container">The Cosmos container holding the FIDO2 items.</param>
public sealed class CosmosCredentialStore(Container container) : ICredentialStore
{
    private const string UsernameLookupId = "lookup";
    private const string UserItemId = "user";
    private const int MaxOptimisticConcurrencyAttempts = 10;

    /// <inheritdoc/>
    public async Task<Fido2User?> GetUserAsync(string username, CancellationToken cancellationToken = default)
    {
        var lookup = await TryReadItemAsync(UsernameLookupId, username, cancellationToken);
        if (lookup is null)
            return null;

        var user = await TryReadItemAsync(UserItemId, PartitionKeyOf(lookup.UserId!), cancellationToken);
        return user is null ? null : MapToUser(user);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Two requests adding the same name at once cannot both succeed: creating the username-lookup item is a
    /// single-partition write keyed by the username itself, so Cosmos accepts only the first, and the one that
    /// loses the race reads back the user the other added instead of creating a second account.
    /// </remarks>
    public async Task<Fido2User> GetOrAddUserAsync(string username, Func<Fido2User> addCallback, CancellationToken cancellationToken = default)
    {
        var existing = await GetUserAsync(username, cancellationToken);
        if (existing != null)
            return existing;

        var user = addCallback();
        var partitionKey = PartitionKeyOf(user.Id);

        try
        {
            await container.CreateItemAsync(
                new CosmosItem { Id = UsernameLookupId, PartitionKey = username, Type = "usernameLookup", UserId = user.Id },
                new PartitionKey(username),
                cancellationToken: cancellationToken);
        }
        catch (CosmosException ex) when (ex.StatusCode == HttpStatusCode.Conflict)
        {
            return await GetUserAsync(username, cancellationToken)
                ?? throw new InvalidOperationException($"Could not add or find the user '{username}'.");
        }

        // This request won the race for the username; the user item itself is owned by this partition key, so an
        // upsert here cannot collide with anyone else.
        await container.UpsertItemAsync(
            new CosmosItem { Id = UserItemId, PartitionKey = partitionKey, Type = "user", Name = username, DisplayName = user.DisplayName, UserId = user.Id },
            new PartitionKey(partitionKey),
            cancellationToken: cancellationToken);

        return user;
    }

    /// <inheritdoc/>
    public async Task<List<StoredCredential>> GetCredentialsByUserAsync(Fido2User user, CancellationToken cancellationToken = default)
    {
        var partitionKey = PartitionKeyOf(user.Id);
        var query = new QueryDefinition("SELECT * FROM c WHERE c.type = 'credential'");

        var results = new List<StoredCredential>();
        using var iterator = container.GetItemQueryIterator<CosmosItem>(query, requestOptions: new QueryRequestOptions { PartitionKey = new PartitionKey(partitionKey) });
        while (iterator.HasMoreResults)
        {
            foreach (var item in await iterator.ReadNextAsync(cancellationToken))
                results.Add(MapToCredential(item));
        }

        return results;
    }

    /// <inheritdoc/>
    public async Task<StoredCredential?> GetCredentialByIdAsync(byte[] id, CancellationToken cancellationToken = default)
    {
        var item = await FindCredentialItemAsync(Base64UrlEncode(id), cancellationToken);
        return item is null ? null : MapToCredential(item);
    }

    /// <inheritdoc/>
    public async Task<List<StoredCredential>> GetCredentialsByUserHandleAsync(byte[] userHandle, CancellationToken cancellationToken = default)
    {
        var query = new QueryDefinition("SELECT * FROM c WHERE c.type = 'credential' AND c.userHandle = @userHandle")
            .WithParameter("@userHandle", userHandle);

        var results = new List<StoredCredential>();
        using var iterator = container.GetItemQueryIterator<CosmosItem>(query);
        while (iterator.HasMoreResults)
        {
            foreach (var item in await iterator.ReadNextAsync(cancellationToken))
                results.Add(MapToCredential(item));
        }

        return results;
    }

    /// <inheritdoc/>
    public async Task<List<Fido2User>> GetUsersByCredentialIdAsync(byte[] credentialId, CancellationToken cancellationToken = default)
    {
        var query = new QueryDefinition("SELECT * FROM c WHERE c.type = 'credential' AND c.id = @id")
            .WithParameter("@id", Base64UrlEncode(credentialId));

        var owningPartitionKeys = new List<string>();
        using var iterator = container.GetItemQueryIterator<CosmosItem>(query);
        while (iterator.HasMoreResults)
        {
            foreach (var item in await iterator.ReadNextAsync(cancellationToken))
                owningPartitionKeys.Add(item.PartitionKey);
        }

        var users = new List<Fido2User>();
        foreach (var partitionKey in owningPartitionKeys)
        {
            var user = await TryReadItemAsync(UserItemId, partitionKey, cancellationToken);
            if (user != null)
                users.Add(MapToUser(user));
        }

        return users;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Checks the user item exists first, since Cosmos itself enforces no referential integrity between items.
    /// </remarks>
    public async Task AddCredentialToUserAsync(Fido2User user, StoredCredential credential, CancellationToken cancellationToken = default)
    {
        var partitionKey = PartitionKeyOf(user.Id);

        if (await TryReadItemAsync(UserItemId, partitionKey, cancellationToken) is null)
            throw new InvalidOperationException("No stored user matches the given ID.");

        credential.UserId = user.Id;

        try
        {
            await container.CreateItemAsync(MapToItem(credential, partitionKey), new PartitionKey(partitionKey), cancellationToken: cancellationToken);
        }
        catch (CosmosException ex) when (ex.StatusCode == HttpStatusCode.Conflict)
        {
            throw new InvalidOperationException("This credential is already registered to this user.", ex);
        }
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Cosmos has no conditional-update statement, so this reads the credential, checks the sign-count rule in
    /// code, and writes it back with an <c>If-Match</c> precondition on the ETag just read. If another write got
    /// there first the precondition fails (HTTP 412); the read-check-write cycle is retried, bounded, against
    /// whatever is current each time.
    /// </remarks>
    public async Task UpdateCredentialRecordAsync(VerifyAssertionResult assertionResult, bool uvInitializationAuthorized = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertionResult);

        var encodedId = Base64UrlEncode(assertionResult.CredentialId);
        var located = await FindCredentialItemAsync(encodedId, cancellationToken)
            ?? throw new InvalidOperationException("No stored credential matches the asserted credential ID.");

        var partitionKey = located.PartitionKey;
        var signCount = assertionResult.SignCount;
        var promoteUv = uvInitializationAuthorized && assertionResult.IsUserVerified;

        for (var attempt = 0; attempt < MaxOptimisticConcurrencyAttempts; attempt++)
        {
            ItemResponse<CosmosItem> current;
            try
            {
                current = await container.ReadItemAsync<CosmosItem>(encodedId, new PartitionKey(partitionKey), cancellationToken: cancellationToken);
            }
            catch (CosmosException ex) when (ex.StatusCode == HttpStatusCode.NotFound)
            {
                throw new InvalidOperationException("No stored credential matches the asserted credential ID.", ex);
            }

            var storedSignCount = current.Resource.SignCount ?? 0;
            var counterOk = (signCount == 0 && storedSignCount == 0) || storedSignCount < signCount;
            if (!counterOk)
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidSignCount, StaleSignCountMessage);

            current.Resource.SignCount = signCount;
            current.Resource.IsBackedUp = assertionResult.IsBackedUp;
            current.Resource.UvInitialized = (current.Resource.UvInitialized ?? false) || promoteUv;

            try
            {
                await container.ReplaceItemAsync(
                    current.Resource,
                    encodedId,
                    new PartitionKey(partitionKey),
                    new ItemRequestOptions { IfMatchEtag = current.ETag },
                    cancellationToken);
                return;
            }
            catch (CosmosException ex) when (ex.StatusCode == HttpStatusCode.PreconditionFailed)
            {
                // Another write updated this credential between the read above and this replace; re-read the
                // latest state and re-check the sign-count rule against it.
            }
        }

        throw new InvalidOperationException("Could not update the credential record: too many concurrent write conflicts.");
    }

    internal const string StaleSignCountMessage = "Another sign-in has already stored a signature counter at or above this assertion's; it may be a replay or a cloned authenticator";

    /// <inheritdoc/>
    public async Task<bool> RemoveCredentialAsync(byte[] credentialId, CancellationToken cancellationToken = default)
    {
        var encodedId = Base64UrlEncode(credentialId);
        var located = await FindCredentialItemAsync(encodedId, cancellationToken);
        if (located is null)
            return false;

        try
        {
            await container.DeleteItemAsync<CosmosItem>(encodedId, new PartitionKey(located.PartitionKey), cancellationToken: cancellationToken);
            return true;
        }
        catch (CosmosException ex) when (ex.StatusCode == HttpStatusCode.NotFound)
        {
            return false;
        }
    }

    private async Task<CosmosItem?> TryReadItemAsync(string id, string partitionKey, CancellationToken cancellationToken)
    {
        try
        {
            var response = await container.ReadItemAsync<CosmosItem>(id, new PartitionKey(partitionKey), cancellationToken: cancellationToken);
            return response.Resource;
        }
        catch (CosmosException ex) when (ex.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }
    }

    private async Task<CosmosItem?> FindCredentialItemAsync(string encodedId, CancellationToken cancellationToken)
    {
        var query = new QueryDefinition("SELECT * FROM c WHERE c.type = 'credential' AND c.id = @id")
            .WithParameter("@id", encodedId);

        using var iterator = container.GetItemQueryIterator<CosmosItem>(query);
        while (iterator.HasMoreResults)
        {
            foreach (var item in await iterator.ReadNextAsync(cancellationToken))
                return item;
        }

        return null;
    }

    private static Fido2User MapToUser(CosmosItem item) => new()
    {
        Id = item.UserId!,
        Name = item.Name!,
        DisplayName = item.DisplayName!,
    };

    private static StoredCredential MapToCredential(CosmosItem item) => new()
    {
        Id = item.CredentialId!,
        RpId = item.RpId,
        PublicKey = item.PublicKey,
        SignCount = item.SignCount ?? 0,
        Transports = item.Transports,
        AuthenticatorAttachment = item.AuthenticatorAttachment,
        UvInitialized = item.UvInitialized ?? false,
        IsBackupEligible = item.IsBackupEligible ?? false,
        IsBackedUp = item.IsBackedUp ?? false,
        AttestationObject = item.AttestationObject,
        AttestationClientDataJson = item.AttestationClientDataJson,
        IsDiscoverable = item.IsDiscoverable,
        UserId = item.UserId!,
        UserHandle = item.UserHandle!,
        AttestationFormat = item.AttestationFormat,
        RegDate = item.RegDate ?? default,
        AaGuid = item.AaGuid ?? default,
    };

    private static CosmosItem MapToItem(StoredCredential credential, string partitionKey) => new()
    {
        Id = Base64UrlEncode(credential.Id),
        PartitionKey = partitionKey,
        Type = "credential",
        CredentialId = credential.Id,
        RpId = credential.RpId,
        PublicKey = credential.PublicKey,
        SignCount = credential.SignCount,
        Transports = credential.Transports,
        AuthenticatorAttachment = credential.AuthenticatorAttachment,
        UvInitialized = credential.UvInitialized,
        IsBackupEligible = credential.IsBackupEligible,
        IsBackedUp = credential.IsBackedUp,
        AttestationObject = credential.AttestationObject,
        AttestationClientDataJson = credential.AttestationClientDataJson,
        IsDiscoverable = credential.IsDiscoverable,
        UserId = credential.UserId,
        UserHandle = credential.UserHandle,
        AttestationFormat = credential.AttestationFormat,
        RegDate = credential.RegDate,
        AaGuid = credential.AaGuid,
    };

    private static string PartitionKeyOf(byte[] userId) => Base64UrlEncode(userId);

    private static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
