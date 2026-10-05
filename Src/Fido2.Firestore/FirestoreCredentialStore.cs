using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Google.Cloud.Firestore;

namespace Fido2NetLib.Firestore;

/// <summary>
/// An <see cref="ICredentialStore"/> backed by Google Cloud Firestore: three collections (usernames, users,
/// credentials), with every lookup that this store can make a direct document read instead of a query,
/// because every document ID is deterministic from what the caller already has (a username, a user ID, or a
/// credential ID).
/// </summary>
/// <remarks>
/// <para>
/// Unlike the equivalent <c>Fido2.Cosmos</c> store, there is no partition key to design around: Firestore
/// scales a collection natively, and a document ID is unique across the whole collection, not merely within a
/// partition. That means a credential ID is globally unique the instant <see cref="AddCredentialToUserAsync"/>
/// creates its document, with no further enforcement layer needed (unlike <c>Fido2.DynamoDb</c>'s reservation
/// item or <c>Fido2.Cosmos</c>'s per-partition-only guarantee) -- and a username is claimed exactly once the
/// same way, via the usernames collection's own document-ID uniqueness.
/// </para>
/// <para>
/// <see cref="GetCredentialsByUserAsync"/> and <see cref="GetCredentialsByUserHandleAsync"/> are the only two
/// operations that run an actual query rather than a direct document read, since neither a user ID nor a user
/// handle is a credential's own document ID.
/// </para>
/// </remarks>
/// <param name="db">The Firestore database the store's collections live in.</param>
/// <param name="options">The collection names to use; defaults are used when omitted.</param>
public sealed class FirestoreCredentialStore(FirestoreDb db, FirestoreCredentialStoreOptions? options = null) : ICredentialStore
{
    private readonly FirestoreCredentialStoreOptions _options = options ?? new FirestoreCredentialStoreOptions();

    private CollectionReference Usernames => db.Collection(_options.UsernamesCollectionName);

    private CollectionReference Users => db.Collection(_options.UsersCollectionName);

    private CollectionReference Credentials => db.Collection(_options.CredentialsCollectionName);

    /// <inheritdoc/>
    public async Task<Fido2User?> GetUserAsync(string username, CancellationToken cancellationToken = default)
    {
        var lookup = await Usernames.Document(username).GetSnapshotAsync(cancellationToken);
        if (!lookup.Exists)
            return null;

        var userSnapshot = await Users.Document(Base64UrlEncode(lookup.ConvertTo<UsernameItem>().UserId.ByteString.ToByteArray())).GetSnapshotAsync(cancellationToken);
        return userSnapshot.Exists ? MapToUser(userSnapshot.ConvertTo<UserItem>()) : null;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Two requests adding the same name at once cannot both succeed: claiming the username is a
    /// <see cref="DocumentReference.CreateAsync(object, CancellationToken)"/> on a document keyed by the
    /// username itself, which Firestore accepts only once; the request that loses the race reads back the
    /// user the other one added instead of creating a second account.
    /// </remarks>
    public async Task<Fido2User> GetOrAddUserAsync(string username, Func<Fido2User> addCallback, CancellationToken cancellationToken = default)
    {
        var existing = await GetUserAsync(username, cancellationToken);
        if (existing != null)
            return existing;

        var user = addCallback();

        try
        {
            await Usernames.Document(username).CreateAsync(new UsernameItem { UserId = Blob.CopyFrom(user.Id) }, cancellationToken);
        }
        catch (Grpc.Core.RpcException ex) when (ex.StatusCode == Grpc.Core.StatusCode.AlreadyExists)
        {
            return await GetUserAsync(username, cancellationToken)
                ?? throw new InvalidOperationException($"Could not add or find the user '{username}'.");
        }

        // This request won the race for the username; the user document itself is keyed by the user's own ID,
        // so a later retry of this same registration (the only other way this document could already exist)
        // overwriting it with identical data is harmless.
        await Users.Document(Base64UrlEncode(user.Id)).SetAsync(new UserItem { UserId = Blob.CopyFrom(user.Id), Name = username, DisplayName = user.DisplayName }, cancellationToken: cancellationToken);

        return user;
    }

    /// <inheritdoc/>
    public async Task<List<StoredCredential>> GetCredentialsByUserAsync(Fido2User user, CancellationToken cancellationToken = default)
    {
        var snapshot = await Credentials.WhereEqualTo(nameof(CredentialItem.UserId), Blob.CopyFrom(user.Id)).GetSnapshotAsync(cancellationToken);
        return [.. snapshot.Documents.Select(d => MapToCredential(d.ConvertTo<CredentialItem>()))];
    }

    /// <inheritdoc/>
    public async Task<StoredCredential?> GetCredentialByIdAsync(byte[] id, CancellationToken cancellationToken = default)
    {
        var snapshot = await Credentials.Document(Base64UrlEncode(id)).GetSnapshotAsync(cancellationToken);
        return snapshot.Exists ? MapToCredential(snapshot.ConvertTo<CredentialItem>()) : null;
    }

    /// <inheritdoc/>
    public async Task<List<StoredCredential>> GetCredentialsByUserHandleAsync(byte[] userHandle, CancellationToken cancellationToken = default)
    {
        var snapshot = await Credentials.WhereEqualTo(nameof(CredentialItem.UserHandle), Blob.CopyFrom(userHandle)).GetSnapshotAsync(cancellationToken);
        return [.. snapshot.Documents.Select(d => MapToCredential(d.ConvertTo<CredentialItem>()))];
    }

    /// <inheritdoc/>
    /// <remarks>
    /// A credential ID is a credential document's own ID, so this is a direct read rather than a query: at
    /// most one document can ever exist for it, which is exactly the uniqueness this method's contract
    /// requires.
    /// </remarks>
    public async Task<List<Fido2User>> GetUsersByCredentialIdAsync(byte[] credentialId, CancellationToken cancellationToken = default)
    {
        var credentialSnapshot = await Credentials.Document(Base64UrlEncode(credentialId)).GetSnapshotAsync(cancellationToken);
        if (!credentialSnapshot.Exists)
            return [];

        var userSnapshot = await Users.Document(Base64UrlEncode(credentialSnapshot.ConvertTo<CredentialItem>().UserId.ByteString.ToByteArray())).GetSnapshotAsync(cancellationToken);
        return userSnapshot.Exists ? [MapToUser(userSnapshot.ConvertTo<UserItem>())] : [];
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Checks the user document exists first, since Firestore itself enforces no referential integrity
    /// between collections.
    /// </remarks>
    public async Task AddCredentialToUserAsync(Fido2User user, StoredCredential credential, CancellationToken cancellationToken = default)
    {
        var userSnapshot = await Users.Document(Base64UrlEncode(user.Id)).GetSnapshotAsync(cancellationToken);
        if (!userSnapshot.Exists)
            throw new InvalidOperationException("No stored user matches the given ID.");

        credential.UserId = user.Id;

        try
        {
            await Credentials.Document(Base64UrlEncode(credential.Id)).CreateAsync(MapToItem(credential), cancellationToken);
        }
        catch (Grpc.Core.RpcException ex) when (ex.StatusCode == Grpc.Core.StatusCode.AlreadyExists)
        {
            throw new InvalidOperationException("This credential is already registered to this user.", ex);
        }
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Runs inside a Firestore transaction: the read of the current sign count and the write of the updated
    /// one are one atomic unit, and Firestore itself detects a conflicting concurrent write at commit time and
    /// retries the whole callback against the then-current document, bounded to a handful of attempts --
    /// there is no need for this store to manage its own optimistic-concurrency retry loop the way
    /// <c>Fido2.Cosmos</c>'s ETag-based equivalent does.
    /// </remarks>
    public async Task UpdateCredentialRecordAsync(VerifyAssertionResult assertionResult, bool uvInitializationAuthorized = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertionResult);

        var docRef = Credentials.Document(Base64UrlEncode(assertionResult.CredentialId));
        var signCount = assertionResult.SignCount;
        var promoteUv = uvInitializationAuthorized && assertionResult.IsUserVerified;

        await db.RunTransactionAsync(async transaction =>
        {
            var snapshot = await transaction.GetSnapshotAsync(docRef);
            if (!snapshot.Exists)
                throw new InvalidOperationException("No stored credential matches the asserted credential ID.");

            var current = snapshot.ConvertTo<CredentialItem>();
            var storedSignCount = current.SignCount;
            var counterOk = (signCount == 0 && storedSignCount == 0) || storedSignCount < signCount;
            if (!counterOk)
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidSignCount, StaleSignCountMessage);

            transaction.Update(docRef, new Dictionary<string, object>
            {
                [nameof(CredentialItem.SignCount)] = signCount,
                [nameof(CredentialItem.IsBackedUp)] = assertionResult.IsBackedUp,
                [nameof(CredentialItem.UvInitialized)] = current.UvInitialized || promoteUv,
            });
        }, cancellationToken: cancellationToken);
    }

    internal const string StaleSignCountMessage = "Another sign-in has already stored a signature counter at or above this assertion's; it may be a replay or a cloned authenticator";

    /// <inheritdoc/>
    public async Task<bool> RemoveCredentialAsync(byte[] credentialId, CancellationToken cancellationToken = default)
    {
        var docRef = Credentials.Document(Base64UrlEncode(credentialId));
        var snapshot = await docRef.GetSnapshotAsync(cancellationToken);
        if (!snapshot.Exists)
            return false;

        await docRef.DeleteAsync(cancellationToken: cancellationToken);
        return true;
    }

    private static Fido2User MapToUser(UserItem item) => new()
    {
        Id = item.UserId.ByteString.ToByteArray(),
        Name = item.Name,
        DisplayName = item.DisplayName,
    };

    private static StoredCredential MapToCredential(CredentialItem item) => new()
    {
        Id = item.CredentialId.ByteString.ToByteArray(),
        RpId = item.RpId,
        PublicKey = item.PublicKey?.ByteString.ToByteArray(),
        SignCount = (uint)item.SignCount,
        Transports = item.Transports,
        AuthenticatorAttachment = item.AuthenticatorAttachment,
        UvInitialized = item.UvInitialized,
        IsBackupEligible = item.IsBackupEligible,
        IsBackedUp = item.IsBackedUp,
        AttestationObject = item.AttestationObject?.ByteString.ToByteArray(),
        AttestationClientDataJson = item.AttestationClientDataJson?.ByteString.ToByteArray(),
        IsDiscoverable = item.IsDiscoverable,
        UserId = item.UserId.ByteString.ToByteArray(),
        UserHandle = item.UserHandle.ByteString.ToByteArray(),
        AttestationFormat = item.AttestationFormat,
        RegDate = item.RegDate.ToDateTimeOffset(),
        AaGuid = Guid.Parse(item.AaGuid),
    };

    private static CredentialItem MapToItem(StoredCredential credential) => new()
    {
        CredentialId = Blob.CopyFrom(credential.Id),
        UserId = Blob.CopyFrom(credential.UserId),
        UserHandle = Blob.CopyFrom(credential.UserHandle),
        RpId = credential.RpId,
        PublicKey = credential.PublicKey is null ? null : Blob.CopyFrom(credential.PublicKey),
        SignCount = credential.SignCount,
        Transports = credential.Transports,
        AuthenticatorAttachment = credential.AuthenticatorAttachment,
        UvInitialized = credential.UvInitialized,
        IsBackupEligible = credential.IsBackupEligible,
        IsBackedUp = credential.IsBackedUp,
        AttestationObject = credential.AttestationObject is null ? null : Blob.CopyFrom(credential.AttestationObject),
        AttestationClientDataJson = credential.AttestationClientDataJson is null ? null : Blob.CopyFrom(credential.AttestationClientDataJson),
        IsDiscoverable = credential.IsDiscoverable,
        AttestationFormat = credential.AttestationFormat,
        RegDate = Timestamp.FromDateTimeOffset(credential.RegDate),
        AaGuid = credential.AaGuid.ToString(),
    };

    private static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
