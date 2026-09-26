using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;

namespace Fido2NetLib.DynamoDb;

/// <summary>
/// Creates the DynamoDB table and Global Secondary Indexes <see cref="DynamoDbCredentialStore"/> requires.
/// </summary>
/// <remarks>
/// Provisioning a table is an infrastructure decision many teams make through IaC (CloudFormation, CDK,
/// Terraform) rather than at application startup. This helper is provided for development, testing, and simple
/// deployments; it is not called automatically by <see cref="DynamoDbCredentialStore"/>.
/// <para>
/// Table schema: partition key <c>PK</c> (String), sort key <c>SK</c> (String). Two Global Secondary Indexes,
/// each projecting all attributes: one keyed on <c>UserHandle</c> (Binary) for the discoverable-credential
/// ceremony, and one keyed on <c>CredentialId</c> (Binary) for credential-ID-only lookups. Billing mode is
/// pay-per-request, since access patterns for an authentication store are bursty rather than steady.
/// </para>
/// </remarks>
public static class DynamoDbTableSchema
{
    /// <summary>
    /// Creates the table described in the <see cref="DynamoDbTableSchema"/> remarks if it does not already exist,
    /// and waits for it (and its indexes) to become active.
    /// </summary>
    /// <param name="client">The DynamoDB client.</param>
    /// <param name="options">Names the table and indexes to create.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    public static async Task EnsureTableExistsAsync(IAmazonDynamoDB client, DynamoDbCredentialStoreOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(options);

        var existing = await client.ListTablesAsync(cancellationToken);
        if (!existing.TableNames.Contains(options.TableName))
        {
            await client.CreateTableAsync(new CreateTableRequest
            {
                TableName = options.TableName,
                BillingMode = BillingMode.PAY_PER_REQUEST,
                AttributeDefinitions =
                [
                    new AttributeDefinition("PK", ScalarAttributeType.S),
                    new AttributeDefinition("SK", ScalarAttributeType.S),
                    new AttributeDefinition("UserHandle", ScalarAttributeType.B),
                    new AttributeDefinition("CredentialId", ScalarAttributeType.B),
                ],
                KeySchema =
                [
                    new KeySchemaElement("PK", KeyType.HASH),
                    new KeySchemaElement("SK", KeyType.RANGE),
                ],
                GlobalSecondaryIndexes =
                [
                    new GlobalSecondaryIndex
                    {
                        IndexName = options.UserHandleIndexName,
                        KeySchema = [new KeySchemaElement("UserHandle", KeyType.HASH), new KeySchemaElement("CredentialId", KeyType.RANGE)],
                        Projection = new Projection { ProjectionType = ProjectionType.ALL },
                    },
                    new GlobalSecondaryIndex
                    {
                        IndexName = options.CredentialIdIndexName,
                        KeySchema = [new KeySchemaElement("CredentialId", KeyType.HASH)],
                        Projection = new Projection { ProjectionType = ProjectionType.ALL },
                    },
                ],
            }, cancellationToken);
        }

        await WaitForActiveAsync(client, options.TableName, cancellationToken);
    }

    private static async Task WaitForActiveAsync(IAmazonDynamoDB client, string tableName, CancellationToken cancellationToken)
    {
        while (true)
        {
            var description = await client.DescribeTableAsync(tableName, cancellationToken);
            var table = description.Table;
            var indexesActive = table.GlobalSecondaryIndexes.TrueForAll(i => i.IndexStatus == IndexStatus.ACTIVE);

            if (table.TableStatus == TableStatus.ACTIVE && indexesActive)
                return;

            await Task.Delay(TimeSpan.FromMilliseconds(500), cancellationToken);
        }
    }
}
