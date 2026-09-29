# Fido2.Cosmos

An `ICredentialStore` backed by a single Azure Cosmos DB container, using the native `Microsoft.Azure.Cosmos`
SDK, with deliberate per-user partitioning.

```csharp
services.AddSingleton(_ => new CosmosClient(connectionString));
services.AddFido2CosmosStore(sp => sp.GetRequiredService<CosmosClient>().GetContainer("fido2", "credentials"));
```

The container must already exist, with partition key path `/partitionKey`, before this store is used. See the
[full quickstart](https://github.com/passwordless-lib/fido2-net-lib/blob/main/Documentation/credential-store-cosmos.md)
for container provisioning and the partitioning tradeoffs, and
[Documentation/credential-stores.md](https://github.com/passwordless-lib/fido2-net-lib/blob/main/Documentation/credential-stores.md)
for how this compares to the other `ICredentialStore` packages (including when to prefer this over
`Fido2.EntityFrameworkCore` on Cosmos).
