using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;

using Moq;

namespace Fido2NetLib.DynamoDb.Tests;

/// <summary>
/// Covers <see cref="DynamoDbTableSchema.EnsureTableExistsAsync"/> with <see cref="IAmazonDynamoDB"/> mocked via
/// Moq, so the create-if-missing check and the active-table/active-index polling loop are exercised without
/// Docker or a real DynamoDB.
/// </summary>
public sealed class DynamoDbTableSchemaTests
{
    private readonly Mock<IAmazonDynamoDB> _client = new(MockBehavior.Strict);
    private readonly DynamoDbCredentialStoreOptions _options = new();

    private static TableDescription ActiveTable(string name, bool indexesActive = true) => new()
    {
        TableName = name,
        TableStatus = TableStatus.ACTIVE,
        GlobalSecondaryIndexes =
        [
            new GlobalSecondaryIndexDescription { IndexStatus = indexesActive ? IndexStatus.ACTIVE : IndexStatus.CREATING },
        ],
    };

    [Fact]
    public async Task EnsureTableExistsAsync_ThrowsOnNullArgumentsAsync()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() => DynamoDbTableSchema.EnsureTableExistsAsync(null!, _options));
        await Assert.ThrowsAsync<ArgumentNullException>(() => DynamoDbTableSchema.EnsureTableExistsAsync(_client.Object, null!));
    }

    [Fact]
    public async Task EnsureTableExistsAsync_CreatesTheTableAndIndexesWhenMissingAsync()
    {
        _client
            .Setup(c => c.ListTablesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ListTablesResponse { TableNames = [] });

        CreateTableRequest? captured = null;
        _client
            .Setup(c => c.CreateTableAsync(It.IsAny<CreateTableRequest>(), It.IsAny<CancellationToken>()))
            .Callback<CreateTableRequest, CancellationToken>((r, _) => captured = r)
            .ReturnsAsync(new CreateTableResponse());

        _client
            .Setup(c => c.DescribeTableAsync(_options.TableName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DescribeTableResponse { Table = ActiveTable(_options.TableName) });

        await DynamoDbTableSchema.EnsureTableExistsAsync(_client.Object, _options);

        Assert.NotNull(captured);
        Assert.Equal(_options.TableName, captured!.TableName);
        Assert.Equal(BillingMode.PAY_PER_REQUEST, captured.BillingMode);
        Assert.Equal(2, captured.KeySchema.Count);
        Assert.Contains(captured.AttributeDefinitions, a => a.AttributeName == "PK" && a.AttributeType == ScalarAttributeType.S);
        Assert.Contains(captured.AttributeDefinitions, a => a.AttributeName == "UserHandle" && a.AttributeType == ScalarAttributeType.B);
        Assert.Contains(captured.AttributeDefinitions, a => a.AttributeName == "CredentialId" && a.AttributeType == ScalarAttributeType.B);
        Assert.Equal(2, captured.GlobalSecondaryIndexes.Count);
        Assert.Contains(captured.GlobalSecondaryIndexes, i => i.IndexName == _options.UserHandleIndexName);
        Assert.Contains(captured.GlobalSecondaryIndexes, i => i.IndexName == _options.CredentialIdIndexName);
    }

    [Fact]
    public async Task EnsureTableExistsAsync_SkipsCreationWhenTheTableAlreadyExistsAsync()
    {
        _client
            .Setup(c => c.ListTablesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ListTablesResponse { TableNames = [_options.TableName] });
        _client
            .Setup(c => c.DescribeTableAsync(_options.TableName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DescribeTableResponse { Table = ActiveTable(_options.TableName) });

        await DynamoDbTableSchema.EnsureTableExistsAsync(_client.Object, _options);

        _client.Verify(c => c.CreateTableAsync(It.IsAny<CreateTableRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task EnsureTableExistsAsync_PollsUntilTheTableAndItsIndexesAreActiveAsync()
    {
        _client
            .Setup(c => c.ListTablesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ListTablesResponse { TableNames = [_options.TableName] });

        var callCount = 0;
        _client
            .Setup(c => c.DescribeTableAsync(_options.TableName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(() =>
            {
                callCount++;
                return callCount switch
                {
                    // Table still creating, then table active but its index still building, then both active.
                    1 => new DescribeTableResponse { Table = new TableDescription { TableName = _options.TableName, TableStatus = TableStatus.CREATING, GlobalSecondaryIndexes = [] } },
                    2 => new DescribeTableResponse { Table = ActiveTable(_options.TableName, indexesActive: false) },
                    _ => new DescribeTableResponse { Table = ActiveTable(_options.TableName) },
                };
            });

        await DynamoDbTableSchema.EnsureTableExistsAsync(_client.Object, _options);

        Assert.Equal(3, callCount);
    }
}
