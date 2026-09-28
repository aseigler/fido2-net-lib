using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;

using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Microsoft.Extensions.DependencyInjection;

using Moq;

namespace Fido2NetLib.DynamoDb.Tests;

/// <summary>
/// Covers <see cref="DynamoDbCredentialStore"/>'s own logic in isolation, with <see cref="IAmazonDynamoDB"/>
/// mocked via Moq: the exact request shapes it builds (keys, condition expressions, index names), and how it
/// translates the AWS SDK exceptions it is written to catch (<see cref="ConditionalCheckFailedException"/>,
/// <see cref="TransactionCanceledException"/>) into this library's own exception types. This does not need Docker
/// or a real DynamoDB, unlike <see cref="DynamoDbCredentialStoreTests"/>, so it runs unconditionally.
/// </summary>
public sealed class DynamoDbCredentialStoreMockTests
{
    private readonly Mock<IAmazonDynamoDB> _client = new(MockBehavior.Strict);
    private readonly DynamoDbCredentialStoreOptions _options = new();

    private DynamoDbCredentialStore NewStore() => new(_client.Object, _options);

    private static Fido2User NewUser(string name, byte id) => new() { Name = name, Id = [id], DisplayName = name.ToUpperInvariant() };

    private static StoredCredential NewCredential(byte[]? id = null, byte[]? userHandle = null, uint signCount = 0, bool full = false) => new()
    {
        Id = id ?? Guid.NewGuid().ToByteArray(),
        PublicKey = [1, 2, 3],
        SignCount = signCount,
        Transports = full ? [AuthenticatorTransport.Internal, AuthenticatorTransport.Hybrid] : null,
        UserHandle = userHandle ?? Guid.NewGuid().ToByteArray(),
        AttestationFormat = "none",
        RegDate = DateTimeOffset.Parse("2026-01-01T00:00:00Z"),
        AaGuid = Guid.NewGuid(),
        RpId = full ? "example.com" : null,
        AttestationObject = full ? [4, 5, 6] : null,
        AttestationClientDataJson = full ? [7, 8, 9] : null,
        AuthenticatorAttachment = full ? AuthenticatorAttachment.Platform : null,
        IsDiscoverable = full ? true : null,
    };

    private static VerifyAssertionResult Assertion(byte[] credentialId, uint signCount, bool backedUp = false, bool userVerified = false) => new()
    {
        CredentialId = credentialId,
        SignCount = signCount,
        IsBackedUp = backedUp,
        IsUserVerified = userVerified,
    };

    // A full item as FindByCredentialIdAsync/GetCredentialsByUserAsync/GetCredentialsByUserHandleAsync would read
    // back, denormalized exactly as AddCredentialToUserAsync writes it.
    private static Dictionary<string, AttributeValue> CredentialItem(string username, StoredCredential credential, Fido2User owner) => new()
    {
        ["PK"] = new AttributeValue { S = $"USER#{username}" },
        ["SK"] = new AttributeValue { S = $"CRED#{Convert.ToBase64String(credential.Id)}" },
        ["ItemType"] = new AttributeValue { S = "Credential" },
        ["Username"] = new AttributeValue { S = username },
        ["OwnerDisplayName"] = new AttributeValue { S = owner.DisplayName },
        ["UserId"] = new AttributeValue { B = new MemoryStream(owner.Id) },
        ["CredentialId"] = new AttributeValue { B = new MemoryStream(credential.Id) },
        ["UserHandle"] = new AttributeValue { B = new MemoryStream(credential.UserHandle) },
        ["PublicKey"] = new AttributeValue { B = new MemoryStream(credential.PublicKey) },
        ["SignCount"] = new AttributeValue { N = credential.SignCount.ToString() },
        ["UvInitialized"] = new AttributeValue { BOOL = credential.UvInitialized },
        ["IsBackupEligible"] = new AttributeValue { BOOL = credential.IsBackupEligible },
        ["IsBackedUp"] = new AttributeValue { BOOL = credential.IsBackedUp },
        ["AttestationFormat"] = new AttributeValue { S = credential.AttestationFormat },
        ["RegDate"] = new AttributeValue { S = credential.RegDate.ToString("O") },
        ["AaGuid"] = new AttributeValue { S = credential.AaGuid.ToString() },
        ["RpId"] = credential.RpId is null ? new AttributeValue { NULL = true } : new AttributeValue { S = credential.RpId },
        ["AttestationObject"] = credential.AttestationObject is null ? new AttributeValue { NULL = true } : new AttributeValue { B = new MemoryStream(credential.AttestationObject) },
        ["AttestationClientDataJson"] = credential.AttestationClientDataJson is null ? new AttributeValue { NULL = true } : new AttributeValue { B = new MemoryStream(credential.AttestationClientDataJson) },
        ["AuthenticatorAttachment"] = credential.AuthenticatorAttachment is null ? new AttributeValue { NULL = true } : new AttributeValue { S = credential.AuthenticatorAttachment.ToString()! },
        ["IsDiscoverable"] = credential.IsDiscoverable is null ? new AttributeValue { NULL = true } : new AttributeValue { BOOL = credential.IsDiscoverable.Value },
        ["Transports"] = credential.Transports is null
            ? new AttributeValue { NULL = true }
            : new AttributeValue { L = [.. credential.Transports.Select(t => new AttributeValue { S = t.ToString() })] },
    };

    private void SetupCredentialIdIndexQuery(Dictionary<string, AttributeValue>? item)
    {
        _client
            .Setup(c => c.QueryAsync(It.Is<QueryRequest>(r => r.IndexName == _options.CredentialIdIndexName), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new QueryResponse { Items = item is null ? [] : [item] });
    }

    // --- GetUserAsync ---

    [Fact]
    public async Task GetUserAsync_ReturnsNullWhenTheItemDoesNotExistAsync()
    {
        _client
            .Setup(c => c.GetItemAsync(It.IsAny<GetItemRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new GetItemResponse { IsItemSet = false });

        Assert.Null(await NewStore().GetUserAsync("nobody"));
    }

    [Fact]
    public async Task GetUserAsync_ReadsTheUserWithAConsistentPointReadAsync()
    {
        GetItemRequest? captured = null;
        _client
            .Setup(c => c.GetItemAsync(It.IsAny<GetItemRequest>(), It.IsAny<CancellationToken>()))
            .Callback<GetItemRequest, CancellationToken>((r, _) => captured = r)
            .ReturnsAsync(new GetItemResponse
            {
                IsItemSet = true,
                Item = new Dictionary<string, AttributeValue>
                {
                    ["Username"] = new AttributeValue { S = "alice" },
                    ["DisplayName"] = new AttributeValue { S = "Alice" },
                    ["UserId"] = new AttributeValue { B = new MemoryStream([1]) },
                },
            });

        var user = await NewStore().GetUserAsync("alice");

        Assert.NotNull(captured);
        Assert.True(captured!.ConsistentRead);
        Assert.Equal("USER#alice", captured.Key["PK"].S);
        Assert.Equal("METADATA", captured.Key["SK"].S);
        Assert.Equal("alice", user!.Name);
        Assert.Equal("Alice", user.DisplayName);
        Assert.Equal([1], user.Id);
    }

    // --- GetOrAddUserAsync ---

    [Fact]
    public async Task GetOrAddUserAsync_ReturnsTheExistingUserWithoutInvokingTheCallbackAsync()
    {
        _client
            .Setup(c => c.GetItemAsync(It.IsAny<GetItemRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new GetItemResponse
            {
                IsItemSet = true,
                Item = new Dictionary<string, AttributeValue>
                {
                    ["Username"] = new AttributeValue { S = "alice" },
                    ["DisplayName"] = new AttributeValue { S = "Alice" },
                    ["UserId"] = new AttributeValue { B = new MemoryStream([1]) },
                },
            });

        var callbackInvoked = false;
        var user = await NewStore().GetOrAddUserAsync("alice", () => { callbackInvoked = true; return NewUser("alice", 9); });

        Assert.False(callbackInvoked);
        Assert.Equal([1], user.Id);
    }

    [Fact]
    public async Task GetOrAddUserAsync_AddsANewUserWithAConditionalPutAsync()
    {
        _client
            .Setup(c => c.GetItemAsync(It.IsAny<GetItemRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new GetItemResponse { IsItemSet = false });

        PutItemRequest? captured = null;
        _client
            .Setup(c => c.PutItemAsync(It.IsAny<PutItemRequest>(), It.IsAny<CancellationToken>()))
            .Callback<PutItemRequest, CancellationToken>((r, _) => captured = r)
            .ReturnsAsync(new PutItemResponse());

        var user = await NewStore().GetOrAddUserAsync("bob", () => NewUser("bob", 9));

        Assert.NotNull(captured);
        Assert.Equal("attribute_not_exists(PK)", captured!.ConditionExpression);
        Assert.Equal("USER#bob", captured.Item["PK"].S);
        Assert.Equal("METADATA", captured.Item["SK"].S);
        Assert.Equal("bob", captured.Item["Username"].S);
        Assert.Equal("BOB", captured.Item["DisplayName"].S);
        Assert.Equal([9], captured.Item["UserId"].B.ToArray());
        Assert.Equal("bob", user.Name);
    }

    [Fact]
    public async Task GetOrAddUserAsync_ARaceLoserReadsBackTheWinnersUserAsync()
    {
        var callCount = 0;
        _client
            .Setup(c => c.GetItemAsync(It.IsAny<GetItemRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(() =>
            {
                callCount++;
                return callCount == 1
                    ? new GetItemResponse { IsItemSet = false }
                    : new GetItemResponse
                    {
                        IsItemSet = true,
                        Item = new Dictionary<string, AttributeValue>
                        {
                            ["Username"] = new AttributeValue { S = "frank" },
                            ["DisplayName"] = new AttributeValue { S = "Frank" },
                            ["UserId"] = new AttributeValue { B = new MemoryStream([6]) },
                        },
                    };
            });
        _client
            .Setup(c => c.PutItemAsync(It.IsAny<PutItemRequest>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new ConditionalCheckFailedException("already exists"));

        var user = await NewStore().GetOrAddUserAsync("frank", () => NewUser("frank", 7));

        Assert.Equal([6], user.Id);
    }

    [Fact]
    public async Task GetOrAddUserAsync_ThrowsIfTheRaceLoserStillCannotFindTheUserAsync()
    {
        _client
            .Setup(c => c.GetItemAsync(It.IsAny<GetItemRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new GetItemResponse { IsItemSet = false });
        _client
            .Setup(c => c.PutItemAsync(It.IsAny<PutItemRequest>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new ConditionalCheckFailedException("already exists"));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => NewStore().GetOrAddUserAsync("grace", () => NewUser("grace", 8)));

        Assert.Contains("grace", ex.Message);
    }

    // --- GetCredentialsByUserAsync ---

    [Fact]
    public async Task GetCredentialsByUserAsync_QueriesByPartitionKeyAndCredentialPrefixAsync()
    {
        var owner = NewUser("alice", 1);
        var credential = NewCredential(full: true);

        QueryRequest? captured = null;
        _client
            .Setup(c => c.QueryAsync(It.Is<QueryRequest>(r => r.IndexName == null), It.IsAny<CancellationToken>()))
            .Callback<QueryRequest, CancellationToken>((r, _) => captured = r)
            .ReturnsAsync(new QueryResponse { Items = [CredentialItem("alice", credential, owner)] });

        var results = await NewStore().GetCredentialsByUserAsync(owner);

        Assert.NotNull(captured);
        Assert.Equal("PK = :pk AND begins_with(SK, :prefix)", captured!.KeyConditionExpression);
        Assert.Equal("USER#alice", captured.ExpressionAttributeValues[":pk"].S);
        Assert.Equal("CRED#", captured.ExpressionAttributeValues[":prefix"].S);
        var found = Assert.Single(results);
        Assert.Equal(credential.Id, found.Id);
        Assert.Equal("example.com", found.RpId);
        Assert.Equal(credential.Transports, found.Transports);
        Assert.Equal(AuthenticatorAttachment.Platform, found.AuthenticatorAttachment);
        Assert.True(found.IsDiscoverable);
        Assert.Equal(credential.AttestationObject, found.AttestationObject);
        Assert.Equal(credential.AttestationClientDataJson, found.AttestationClientDataJson);
    }

    [Fact]
    public async Task GetCredentialsByUserAsync_MapsAMinimalCredentialWithoutOptionalFieldsAsync()
    {
        var owner = NewUser("alice", 1);
        var credential = NewCredential(full: false);

        _client
            .Setup(c => c.QueryAsync(It.Is<QueryRequest>(r => r.IndexName == null), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new QueryResponse { Items = [CredentialItem("alice", credential, owner)] });

        var found = Assert.Single(await NewStore().GetCredentialsByUserAsync(owner));

        Assert.Null(found.RpId);
        Assert.Null(found.Transports);
        Assert.Null(found.AuthenticatorAttachment);
        Assert.Null(found.IsDiscoverable);
        Assert.Null(found.AttestationObject);
        Assert.Null(found.AttestationClientDataJson);
    }

    // --- GetCredentialByIdAsync ---

    [Fact]
    public async Task GetCredentialByIdAsync_ReturnsNullWhenNotFoundAsync()
    {
        SetupCredentialIdIndexQuery(null);

        Assert.Null(await NewStore().GetCredentialByIdAsync(Guid.NewGuid().ToByteArray()));
    }

    [Fact]
    public async Task GetCredentialByIdAsync_QueriesTheCredentialIdIndexWithLimitOneAsync()
    {
        var owner = NewUser("dave", 4);
        var credential = NewCredential();

        QueryRequest? captured = null;
        _client
            .Setup(c => c.QueryAsync(It.Is<QueryRequest>(r => r.IndexName == _options.CredentialIdIndexName), It.IsAny<CancellationToken>()))
            .Callback<QueryRequest, CancellationToken>((r, _) => captured = r)
            .ReturnsAsync(new QueryResponse { Items = [CredentialItem("dave", credential, owner)] });

        var found = await NewStore().GetCredentialByIdAsync(credential.Id);

        Assert.NotNull(captured);
        Assert.Equal(1, captured!.Limit);
        Assert.Equal("CredentialId = :id", captured.KeyConditionExpression);
        Assert.Equal(credential.Id, captured.ExpressionAttributeValues[":id"].B.ToArray());
        Assert.Equal(credential.Id, found!.Id);
    }

    // --- GetCredentialsByUserHandleAsync ---

    [Fact]
    public async Task GetCredentialsByUserHandleAsync_QueriesTheUserHandleIndexAsync()
    {
        var owner = NewUser("carol", 3);
        var userHandle = new byte[] { 3, 3, 3 };
        var credential = NewCredential(userHandle: userHandle);

        QueryRequest? captured = null;
        _client
            .Setup(c => c.QueryAsync(It.Is<QueryRequest>(r => r.IndexName == _options.UserHandleIndexName), It.IsAny<CancellationToken>()))
            .Callback<QueryRequest, CancellationToken>((r, _) => captured = r)
            .ReturnsAsync(new QueryResponse { Items = [CredentialItem("carol", credential, owner)] });

        var found = Assert.Single(await NewStore().GetCredentialsByUserHandleAsync(userHandle));

        Assert.NotNull(captured);
        Assert.Equal("UserHandle = :handle", captured!.KeyConditionExpression);
        Assert.Equal(userHandle, captured.ExpressionAttributeValues[":handle"].B.ToArray());
        Assert.Equal(credential.Id, found.Id);
    }

    // --- GetUsersByCredentialIdAsync ---

    [Fact]
    public async Task GetUsersByCredentialIdAsync_ReturnsEmptyWhenNotFoundAsync()
    {
        SetupCredentialIdIndexQuery(null);

        Assert.Empty(await NewStore().GetUsersByCredentialIdAsync(Guid.NewGuid().ToByteArray()));
    }

    [Fact]
    public async Task GetUsersByCredentialIdAsync_ResolvesTheOwningUserFromTheDenormalizedItemAsync()
    {
        var owner = NewUser("dave", 4);
        var credential = NewCredential();
        SetupCredentialIdIndexQuery(CredentialItem("dave", credential, owner));

        var found = Assert.Single(await NewStore().GetUsersByCredentialIdAsync(credential.Id));

        Assert.Equal("dave", found.Name);
        Assert.Equal([4], found.Id);
        Assert.Equal("DAVE", found.DisplayName);
    }

    // --- AddCredentialToUserAsync ---

    [Fact]
    public async Task AddCredentialToUserAsync_SendsATransactWriteWithTheCredentialAndItsReservationAsync()
    {
        var user = NewUser("bob", 9);
        var credential = NewCredential(full: true);

        TransactWriteItemsRequest? captured = null;
        _client
            .Setup(c => c.TransactWriteItemsAsync(It.IsAny<TransactWriteItemsRequest>(), It.IsAny<CancellationToken>()))
            .Callback<TransactWriteItemsRequest, CancellationToken>((r, _) => captured = r)
            .ReturnsAsync(new TransactWriteItemsResponse());

        await NewStore().AddCredentialToUserAsync(user, credential);

        Assert.Equal([9], credential.UserId);
        Assert.NotNull(captured);
        Assert.Equal(2, captured!.TransactItems.Count);

        var credentialPut = captured.TransactItems[0].Put;
        Assert.Equal("USER#bob", credentialPut.Item["PK"].S);
        Assert.Equal($"CRED#{Convert.ToBase64String(credential.Id)}", credentialPut.Item["SK"].S);
        Assert.Equal("attribute_not_exists(PK)", credentialPut.ConditionExpression);
        Assert.Equal("example.com", credentialPut.Item["RpId"].S);

        var reservationPut = captured.TransactItems[1].Put;
        Assert.Equal($"CREDID#{Convert.ToBase64String(credential.Id)}", reservationPut.Item["PK"].S);
        Assert.Equal("REF", reservationPut.Item["SK"].S);
        Assert.Equal("attribute_not_exists(PK)", reservationPut.ConditionExpression);
    }

    [Fact]
    public async Task AddCredentialToUserAsync_WritesAMinimalCredentialsNullOptionalFieldsAsync()
    {
        var user = NewUser("bob", 9);
        var credential = NewCredential(full: false);

        TransactWriteItemsRequest? captured = null;
        _client
            .Setup(c => c.TransactWriteItemsAsync(It.IsAny<TransactWriteItemsRequest>(), It.IsAny<CancellationToken>()))
            .Callback<TransactWriteItemsRequest, CancellationToken>((r, _) => captured = r)
            .ReturnsAsync(new TransactWriteItemsResponse());

        await NewStore().AddCredentialToUserAsync(user, credential);

        var item = captured!.TransactItems[0].Put.Item;
        Assert.True(item["RpId"].NULL);
        Assert.True(item["AttestationObject"].NULL);
        Assert.True(item["AttestationClientDataJson"].NULL);
        Assert.True(item["AuthenticatorAttachment"].NULL);
        Assert.True(item["IsDiscoverable"].NULL);
        Assert.True(item["Transports"].NULL);
    }

    [Fact]
    public async Task AddCredentialToUserAsync_TranslatesATransactionCancellationIntoAlreadyRegisteredAsync()
    {
        var inner = new TransactionCanceledException("condition failed");
        _client
            .Setup(c => c.TransactWriteItemsAsync(It.IsAny<TransactWriteItemsRequest>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(inner);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => NewStore().AddCredentialToUserAsync(NewUser("bob", 9), NewCredential()));

        Assert.Same(inner, ex.InnerException);
        Assert.Contains("already registered", ex.Message);
    }

    // --- UpdateCredentialRecordAsync ---

    [Fact]
    public async Task UpdateCredentialRecordAsync_ThrowsOnANullAssertionResultAsync()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() => NewStore().UpdateCredentialRecordAsync(null!));
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_ThrowsWhenNoCredentialMatchesAsync()
    {
        SetupCredentialIdIndexQuery(null);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => NewStore().UpdateCredentialRecordAsync(Assertion(Guid.NewGuid().ToByteArray(), 1)));
    }

    private static Dictionary<string, AttributeValue> UpdatableItem(bool existingUvInitialized) => new()
    {
        ["PK"] = new AttributeValue { S = "USER#erin" },
        ["SK"] = new AttributeValue { S = "CRED#abc" },
        ["UvInitialized"] = new AttributeValue { BOOL = existingUvInitialized },
    };

    [Fact]
    public async Task UpdateCredentialRecordAsync_SendsAConditionalUpdateEncodingTheSignCountRuleAsync()
    {
        SetupCredentialIdIndexQuery(UpdatableItem(existingUvInitialized: false));

        UpdateItemRequest? captured = null;
        _client
            .Setup(c => c.UpdateItemAsync(It.IsAny<UpdateItemRequest>(), It.IsAny<CancellationToken>()))
            .Callback<UpdateItemRequest, CancellationToken>((r, _) => captured = r)
            .ReturnsAsync(new UpdateItemResponse());

        var credentialId = Guid.NewGuid().ToByteArray();
        await NewStore().UpdateCredentialRecordAsync(Assertion(credentialId, 2, backedUp: true));

        Assert.NotNull(captured);
        Assert.Equal("USER#erin", captured!.Key["PK"].S);
        Assert.Equal("CRED#abc", captured.Key["SK"].S);
        Assert.Equal("SET SignCount = :new, IsBackedUp = :backedUp, UvInitialized = :uv", captured.UpdateExpression);
        Assert.Equal("(SignCount < :new) OR (SignCount = :zero AND :new = :zero)", captured.ConditionExpression);
        Assert.Equal("2", captured.ExpressionAttributeValues[":new"].N);
        Assert.Equal("0", captured.ExpressionAttributeValues[":zero"].N);
        Assert.True(captured.ExpressionAttributeValues[":backedUp"].BOOL);
        Assert.False(captured.ExpressionAttributeValues[":uv"].BOOL);
    }

    [Theory]
    // existingUvInitialized, uvInitializationAuthorized, isUserVerified, expected :uv
    [InlineData(false, false, true, false)]
    [InlineData(false, true, false, false)]
    [InlineData(false, true, true, true)]
    [InlineData(true, false, false, true)]
    public async Task UpdateCredentialRecordAsync_ComputesUvInitializedPromotionCorrectlyAsync(
        bool existingUvInitialized, bool uvInitializationAuthorized, bool isUserVerified, bool expectedUv)
    {
        SetupCredentialIdIndexQuery(UpdatableItem(existingUvInitialized));

        UpdateItemRequest? captured = null;
        _client
            .Setup(c => c.UpdateItemAsync(It.IsAny<UpdateItemRequest>(), It.IsAny<CancellationToken>()))
            .Callback<UpdateItemRequest, CancellationToken>((r, _) => captured = r)
            .ReturnsAsync(new UpdateItemResponse());

        await NewStore().UpdateCredentialRecordAsync(
            Assertion(Guid.NewGuid().ToByteArray(), 1, userVerified: isUserVerified),
            uvInitializationAuthorized);

        Assert.Equal(expectedUv, captured!.ExpressionAttributeValues[":uv"].BOOL);
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_TranslatesAFailedConditionIntoInvalidSignCountAsync()
    {
        SetupCredentialIdIndexQuery(UpdatableItem(existingUvInitialized: false));
        _client
            .Setup(c => c.UpdateItemAsync(It.IsAny<UpdateItemRequest>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new ConditionalCheckFailedException("condition failed"));

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => NewStore().UpdateCredentialRecordAsync(Assertion(Guid.NewGuid().ToByteArray(), 1)));

        Assert.Equal(Fido2ErrorCode.InvalidSignCount, ex.Code);
    }

    // --- RemoveCredentialAsync ---

    [Fact]
    public async Task RemoveCredentialAsync_ReturnsFalseAndSendsNoWriteWhenNotFoundAsync()
    {
        SetupCredentialIdIndexQuery(null);

        Assert.False(await NewStore().RemoveCredentialAsync(Guid.NewGuid().ToByteArray()));

        _client.Verify(c => c.TransactWriteItemsAsync(It.IsAny<TransactWriteItemsRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task RemoveCredentialAsync_DeletesBothTheItemAndItsReservationAsync()
    {
        var credentialId = Guid.NewGuid().ToByteArray();
        SetupCredentialIdIndexQuery(UpdatableItem(existingUvInitialized: false));

        TransactWriteItemsRequest? captured = null;
        _client
            .Setup(c => c.TransactWriteItemsAsync(It.IsAny<TransactWriteItemsRequest>(), It.IsAny<CancellationToken>()))
            .Callback<TransactWriteItemsRequest, CancellationToken>((r, _) => captured = r)
            .ReturnsAsync(new TransactWriteItemsResponse());

        Assert.True(await NewStore().RemoveCredentialAsync(credentialId));

        Assert.NotNull(captured);
        Assert.Equal(2, captured!.TransactItems.Count);
        Assert.Equal("USER#erin", captured.TransactItems[0].Delete.Key["PK"].S);
        Assert.Equal("CRED#abc", captured.TransactItems[0].Delete.Key["SK"].S);
        Assert.Equal($"CREDID#{Convert.ToBase64String(credentialId)}", captured.TransactItems[1].Delete.Key["PK"].S);
        Assert.Equal("REF", captured.TransactItems[1].Delete.Key["SK"].S);
    }

    // --- DI registration ---

    [Fact]
    public void AddFido2DynamoDbStore_RegistersTheStoreWithConfiguredOptions()
    {
        var services = new ServiceCollection();
        services.AddSingleton(_client.Object);
        services.AddFido2DynamoDbStore(o => o.TableName = "CustomTable");

        using var provider = services.BuildServiceProvider();
        var store = provider.GetRequiredService<ICredentialStore>();
        var options = provider.GetRequiredService<DynamoDbCredentialStoreOptions>();

        Assert.IsType<DynamoDbCredentialStore>(store);
        Assert.Equal("CustomTable", options.TableName);
    }
}
