# Fido2.DynamoDb

An `ICredentialStore` over a single DynamoDB table, single-table design, with `TransactWriteItems`-backed
global credential-ID uniqueness.

```csharp
services.AddSingleton<IAmazonDynamoDB>(_ => new AmazonDynamoDBClient());
services.AddFido2DynamoDbStore();
```

See the [full quickstart](https://github.com/passwordless-lib/fido2-net-lib/blob/main/Documentation/credential-store-dynamodb.md)
for table/index provisioning (a helper is included for dev/test) and design notes, and
[Documentation/credential-stores.md](https://github.com/passwordless-lib/fido2-net-lib/blob/main/Documentation/credential-stores.md)
for how this compares to the other `ICredentialStore` packages.
