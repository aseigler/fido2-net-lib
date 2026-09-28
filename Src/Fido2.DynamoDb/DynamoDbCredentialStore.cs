using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;

using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Fido2NetLib.DynamoDb;

/// <summary>
/// An <see cref="ICredentialStore"/> over a single DynamoDB table, using the single-table design idiomatic to
/// DynamoDB rather than a relational shape.
/// </summary>
/// <remarks>
/// A user's item has partition key <c>USER#{username}</c> and sort key <c>METADATA</c>; each of their credentials
/// has the same partition key with sort key <c>CRED#{base64(credentialId)}</c>, so <see cref="GetCredentialsByUserAsync"/>
/// is a single <c>Query</c> by partition key. Credential items denormalize the owner's username, display name, and
/// ID, so a credential-ID-only lookup never needs a second round trip to read the user's own item.
/// <para>
/// Global credential-ID uniqueness -- required at registration -- is enforced with a strongly-consistent
/// <c>TransactWriteItems</c> call that also writes a reservation item with partition key
/// <c>CREDID#{base64(credentialId)}</c>; this does not depend on the (eventually consistent) Global Secondary
/// Indexes. <see cref="GetCredentialByIdAsync"/>, <see cref="GetUsersByCredentialIdAsync"/>,
/// <see cref="UpdateCredentialRecordAsync"/>, and <see cref="RemoveCredentialAsync"/> all resolve a credential ID
/// to its owning item through the <c>CredentialIdIndex</c> Global Secondary Index, which -- like any DynamoDB GSI
/// -- is only eventually consistent; a credential added a moment ago could briefly fail to resolve through it.
/// The sign-count-regression check itself is a conditional <c>UpdateItem</c> against the base table (strongly
/// consistent), so that guarantee does not depend on the index either.
/// </para>
/// </remarks>
/// <param name="client">The DynamoDB client.</param>
/// <param name="options">Names the table and indexes to use.</param>
public class DynamoDbCredentialStore(IAmazonDynamoDB client, DynamoDbCredentialStoreOptions options) : ICredentialStore
{
    private const string UserSortKey = "METADATA";

    private static string UserPartitionKey(string username) => $"USER#{username}";

    private static string CredentialSortKey(byte[] credentialId) => $"CRED#{Convert.ToBase64String(credentialId)}";

    private static string CredentialReservationPartitionKey(byte[] credentialId) => $"CREDID#{Convert.ToBase64String(credentialId)}";

    /// <inheritdoc/>
    public async Task<Fido2User?> GetUserAsync(string username, CancellationToken cancellationToken = default)
    {
        var response = await client.GetItemAsync(new GetItemRequest
        {
            TableName = options.TableName,
            Key = Key(UserPartitionKey(username), UserSortKey),
            ConsistentRead = true,
        }, cancellationToken);

        return response.IsItemSet ? ReadUser(response.Item) : null;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Two requests adding the same name at once cannot both succeed: the conditional <c>PutItem</c> only writes
    /// if that partition/sort key pair does not already exist, so the request that loses the race reads back the
    /// user the other one added instead of creating a second account.
    /// </remarks>
    public async Task<Fido2User> GetOrAddUserAsync(string username, Func<Fido2User> addCallback, CancellationToken cancellationToken = default)
    {
        var existing = await GetUserAsync(username, cancellationToken);
        if (existing != null)
            return existing;

        var user = addCallback();

        var item = Key(UserPartitionKey(username), UserSortKey);
        item["ItemType"] = new AttributeValue { S = "User" };
        item["Username"] = new AttributeValue { S = user.Name };
        item["DisplayName"] = new AttributeValue { S = user.DisplayName };
        item["UserId"] = new AttributeValue { B = new MemoryStream(user.Id) };

        try
        {
            await client.PutItemAsync(new PutItemRequest
            {
                TableName = options.TableName,
                Item = item,
                ConditionExpression = "attribute_not_exists(PK)",
            }, cancellationToken);

            return user;
        }
        catch (ConditionalCheckFailedException)
        {
            return await GetUserAsync(username, cancellationToken)
                ?? throw new InvalidOperationException($"Could not add or find the user '{username}'.");
        }
    }

    /// <inheritdoc/>
    public async Task<List<StoredCredential>> GetCredentialsByUserAsync(Fido2User user, CancellationToken cancellationToken = default)
    {
        var response = await client.QueryAsync(new QueryRequest
        {
            TableName = options.TableName,
            KeyConditionExpression = "PK = :pk AND begins_with(SK, :prefix)",
            ExpressionAttributeValues = new Dictionary<string, AttributeValue>
            {
                [":pk"] = new AttributeValue { S = UserPartitionKey(user.Name) },
                [":prefix"] = new AttributeValue { S = "CRED#" },
            },
        }, cancellationToken);

        return response.Items.ConvertAll(ReadCredential);
    }

    /// <inheritdoc/>
    public async Task<StoredCredential?> GetCredentialByIdAsync(byte[] id, CancellationToken cancellationToken = default)
    {
        var item = await FindByCredentialIdAsync(id, cancellationToken);
        return item is null ? null : ReadCredential(item);
    }

    /// <inheritdoc/>
    public async Task<List<StoredCredential>> GetCredentialsByUserHandleAsync(byte[] userHandle, CancellationToken cancellationToken = default)
    {
        var response = await client.QueryAsync(new QueryRequest
        {
            TableName = options.TableName,
            IndexName = options.UserHandleIndexName,
            KeyConditionExpression = "UserHandle = :handle",
            ExpressionAttributeValues = new Dictionary<string, AttributeValue>
            {
                [":handle"] = new AttributeValue { B = new MemoryStream(userHandle) },
            },
        }, cancellationToken);

        return response.Items.ConvertAll(ReadCredential);
    }

    /// <inheritdoc/>
    public async Task<List<Fido2User>> GetUsersByCredentialIdAsync(byte[] credentialId, CancellationToken cancellationToken = default)
    {
        var item = await FindByCredentialIdAsync(credentialId, cancellationToken);
        if (item is null)
            return [];

        return [new Fido2User
        {
            Id = item["UserId"].B.ToArray(),
            Name = item["Username"].S,
            DisplayName = item["OwnerDisplayName"].S,
        }];
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Writes the credential item and a global uniqueness-reservation item in one <c>TransactWriteItems</c> call,
    /// each conditioned on not already existing, so a credential ID racing to register under two different users
    /// at once can only succeed for one of them.
    /// </remarks>
    public async Task AddCredentialToUserAsync(Fido2User user, StoredCredential credential, CancellationToken cancellationToken = default)
    {
        credential.UserId = user.Id;

        var credentialItem = Key(UserPartitionKey(user.Name), CredentialSortKey(credential.Id));
        WriteCredential(credentialItem, user, credential);

        var reservationItem = Key(CredentialReservationPartitionKey(credential.Id), "REF");

        try
        {
            await client.TransactWriteItemsAsync(new TransactWriteItemsRequest
            {
                TransactItems =
                [
                    new TransactWriteItem
                    {
                        Put = new Put
                        {
                            TableName = options.TableName,
                            Item = credentialItem,
                            ConditionExpression = "attribute_not_exists(PK)",
                        },
                    },
                    new TransactWriteItem
                    {
                        Put = new Put
                        {
                            TableName = options.TableName,
                            Item = reservationItem,
                            ConditionExpression = "attribute_not_exists(PK)",
                        },
                    },
                ],
            }, cancellationToken);
        }
        catch (TransactionCanceledException ex)
        {
            throw new InvalidOperationException("This credential is already registered.", ex);
        }
    }

    /// <inheritdoc/>
    /// <remarks>
    /// The stored counter, backup state, and (once authorized) uvInitialized promotion read by the
    /// <c>CredentialIdIndex</c> query are only used to compute the new values; the actual sign-count-regression
    /// guard is the conditional <c>UpdateItem</c> against the base table below, which -- unlike the index -- is
    /// strongly consistent.
    /// </remarks>
    public async Task UpdateCredentialRecordAsync(VerifyAssertionResult assertionResult, bool uvInitializationAuthorized = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertionResult);

        var item = await FindByCredentialIdAsync(assertionResult.CredentialId, cancellationToken)
            ?? throw new InvalidOperationException("No stored credential matches the asserted credential ID.");

        var signCount = assertionResult.SignCount;
        var isBackedUp = assertionResult.IsBackedUp;
        var existingUvInitialized = item["UvInitialized"].BOOL;
        var promotedUvInitialized = existingUvInitialized || (uvInitializationAuthorized && assertionResult.IsUserVerified);

        try
        {
            await client.UpdateItemAsync(new UpdateItemRequest
            {
                TableName = options.TableName,
                Key = Key(item["PK"].S, item["SK"].S),
                UpdateExpression = "SET SignCount = :new, IsBackedUp = :backedUp, UvInitialized = :uv",
                ConditionExpression = "(SignCount < :new) OR (SignCount = :zero AND :new = :zero)",
                ExpressionAttributeValues = new Dictionary<string, AttributeValue>
                {
                    [":new"] = new AttributeValue { N = signCount.ToString() },
                    [":zero"] = new AttributeValue { N = "0" },
                    [":backedUp"] = new AttributeValue { BOOL = isBackedUp },
                    [":uv"] = new AttributeValue { BOOL = promotedUvInitialized },
                },
            }, cancellationToken);
        }
        catch (ConditionalCheckFailedException)
        {
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidSignCount, StaleSignCountMessage);
        }
    }

    internal const string StaleSignCountMessage = "Another sign-in has already stored a signature counter at or above this assertion's; it may be a replay or a cloned authenticator";

    /// <inheritdoc/>
    /// <remarks>
    /// Removes both the credential item and its global uniqueness-reservation item, so the credential ID becomes
    /// available for registration again.
    /// </remarks>
    public async Task<bool> RemoveCredentialAsync(byte[] credentialId, CancellationToken cancellationToken = default)
    {
        var item = await FindByCredentialIdAsync(credentialId, cancellationToken);
        if (item is null)
            return false;

        await client.TransactWriteItemsAsync(new TransactWriteItemsRequest
        {
            TransactItems =
            [
                new TransactWriteItem { Delete = new Delete { TableName = options.TableName, Key = Key(item["PK"].S, item["SK"].S) } },
                new TransactWriteItem { Delete = new Delete { TableName = options.TableName, Key = Key(CredentialReservationPartitionKey(credentialId), "REF") } },
            ],
        }, cancellationToken);

        return true;
    }

    private async Task<Dictionary<string, AttributeValue>?> FindByCredentialIdAsync(byte[] credentialId, CancellationToken cancellationToken)
    {
        var response = await client.QueryAsync(new QueryRequest
        {
            TableName = options.TableName,
            IndexName = options.CredentialIdIndexName,
            KeyConditionExpression = "CredentialId = :id",
            ExpressionAttributeValues = new Dictionary<string, AttributeValue>
            {
                [":id"] = new AttributeValue { B = new MemoryStream(credentialId) },
            },
            Limit = 1,
        }, cancellationToken);

        return response.Items.Count > 0 ? response.Items[0] : null;
    }

    private static Dictionary<string, AttributeValue> Key(string pk, string sk) => new()
    {
        ["PK"] = new AttributeValue { S = pk },
        ["SK"] = new AttributeValue { S = sk },
    };

    private static Fido2User ReadUser(Dictionary<string, AttributeValue> item) => new()
    {
        Id = item["UserId"].B.ToArray(),
        Name = item["Username"].S,
        DisplayName = item["DisplayName"].S,
    };

    private static void WriteCredential(Dictionary<string, AttributeValue> item, Fido2User user, StoredCredential credential)
    {
        item["ItemType"] = new AttributeValue { S = "Credential" };
        item["Username"] = new AttributeValue { S = user.Name };
        item["OwnerDisplayName"] = new AttributeValue { S = user.DisplayName };
        item["UserId"] = new AttributeValue { B = new MemoryStream(user.Id) };
        item["CredentialId"] = new AttributeValue { B = new MemoryStream(credential.Id) };
        item["UserHandle"] = new AttributeValue { B = new MemoryStream(credential.UserHandle) };
        item["PublicKey"] = new AttributeValue { B = new MemoryStream(credential.PublicKey) };
        item["SignCount"] = new AttributeValue { N = credential.SignCount.ToString() };
        item["UvInitialized"] = new AttributeValue { BOOL = credential.UvInitialized };
        item["IsBackupEligible"] = new AttributeValue { BOOL = credential.IsBackupEligible };
        item["IsBackedUp"] = new AttributeValue { BOOL = credential.IsBackedUp };
        item["AttestationFormat"] = new AttributeValue { S = credential.AttestationFormat };
        item["RegDate"] = new AttributeValue { S = credential.RegDate.ToString("O") };
        item["AaGuid"] = new AttributeValue { S = credential.AaGuid.ToString() };

        item["RpId"] = credential.RpId is null ? new AttributeValue { NULL = true } : new AttributeValue { S = credential.RpId };
        item["AttestationObject"] = credential.AttestationObject is null ? new AttributeValue { NULL = true } : new AttributeValue { B = new MemoryStream(credential.AttestationObject) };
        item["AttestationClientDataJson"] = credential.AttestationClientDataJson is null ? new AttributeValue { NULL = true } : new AttributeValue { B = new MemoryStream(credential.AttestationClientDataJson) };
        item["AuthenticatorAttachment"] = credential.AuthenticatorAttachment is null ? new AttributeValue { NULL = true } : new AttributeValue { S = credential.AuthenticatorAttachment.ToString() };
        item["IsDiscoverable"] = credential.IsDiscoverable is null ? new AttributeValue { NULL = true } : new AttributeValue { BOOL = credential.IsDiscoverable.Value };
        item["Transports"] = credential.Transports is null
            ? new AttributeValue { NULL = true }
            : new AttributeValue { L = [.. credential.Transports.Select(t => new AttributeValue { S = t.ToString() })] };
    }

    private static StoredCredential ReadCredential(Dictionary<string, AttributeValue> item) => new()
    {
        Id = item["CredentialId"].B.ToArray(),
        RpId = item["RpId"].NULL ? null : item["RpId"].S,
        PublicKey = item["PublicKey"].B.ToArray(),
        SignCount = uint.Parse(item["SignCount"].N),
        Transports = item["Transports"].NULL ? null : [.. item["Transports"].L.Select(t => Enum.Parse<AuthenticatorTransport>(t.S))],
        AuthenticatorAttachment = item["AuthenticatorAttachment"].NULL ? null : Enum.Parse<AuthenticatorAttachment>(item["AuthenticatorAttachment"].S),
        UvInitialized = item["UvInitialized"].BOOL,
        IsBackupEligible = item["IsBackupEligible"].BOOL,
        IsBackedUp = item["IsBackedUp"].BOOL,
        AttestationObject = item["AttestationObject"].NULL ? null : item["AttestationObject"].B.ToArray(),
        AttestationClientDataJson = item["AttestationClientDataJson"].NULL ? null : item["AttestationClientDataJson"].B.ToArray(),
        IsDiscoverable = item["IsDiscoverable"].NULL ? null : item["IsDiscoverable"].BOOL,
        UserId = item["UserId"].B.ToArray(),
        UserHandle = item["UserHandle"].B.ToArray(),
        AttestationFormat = item["AttestationFormat"].S,
        RegDate = DateTimeOffset.Parse(item["RegDate"].S),
        AaGuid = Guid.Parse(item["AaGuid"].S),
    };
}
