# Fido2.Cosmos

An `ICredentialStore` backed by a single Azure Cosmos DB container, using the native `Microsoft.Azure.Cosmos`
SDK -- not the generic EF Core Cosmos provider (`Fido2.EntityFrameworkCore` can also target Cosmos, but its
partitioning falls out of EF's generic mapping rather than being modeled deliberately). Prefer this package
over the EF Core store specifically when you're on Cosmos and want that deliberate partitioning; see
[Documentation/credential-stores.md](credential-stores.md) for the full comparison.

## Install

```bash
dotnet add package Fido2.Cosmos
```

## Quickstart

### 1. Create the container

The container must already exist, with partition key path `/partitionKey`, before this store is used --
provisioning throughput (or autoscale) is a deployment concern, not something the store does at startup.

```bash
az cosmosdb sql container create \
    --account-name my-account --database-name fido2 --name credentials \
    --resource-group my-group --partition-key-path /partitionKey
```

### 2. Register a client and the store

A `CosmosClient` is expensive to construct and meant to be a long-lived singleton, so register one and resolve
the `Container` from it rather than constructing a new client per call:

```csharp
services.AddSingleton(_ => new CosmosClient(connectionString));

services.AddFido2CosmosStore(sp =>
    sp.GetRequiredService<CosmosClient>().GetContainer("fido2", "credentials"));
```

### 3. Register and authenticate

```csharp
services.AddFido2(options =>
{
    options.ServerDomain = "example.com";
    options.ServerName = "Example App";
    options.Origins = new HashSet<string> { "https://example.com" };
});
services.AddFido2Simple();
```

```csharp
public class AccountController(ISimpleFido2Authentication fido2) : Controller
{
    [HttpPost("register/begin")]
    public async Task<CredentialCreateOptions> BeginRegister(string username)
        => await fido2.InitiateRegistrationAsync(username);

    [HttpPost("register/finish")]
    public async Task<IActionResult> FinishRegister(CredentialCreateOptions options, AuthenticatorAttestationRawResponse response)
    {
        await fido2.CompleteRegistrationAsync(options, response);
        return Ok();
    }
}
```

### Local development

The Cosmos DB Linux emulator runs in Docker:

```bash
docker run -d -p 8081:8081 -p 10250-10255:10250-10255 \
    mcr.microsoft.com/cosmosdb/linux/azure-cosmos-emulator
```

```csharp
services.AddSingleton(_ => new CosmosClient(
    "https://localhost:8081",
    "C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==", // well-known emulator key
    new CosmosClientOptions { HttpClientFactory = () => new HttpClient(new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator, // emulator's self-signed cert
    }) }));
```

## Design notes

- **Partitioning is deliberate, not incidental.** The container holds three kinds of items, discriminated by a
  `type` field: a username-lookup item (partitioned by the username itself, so a username can be claimed
  exactly once cluster-wide), a user item, and one item per credential -- both of the latter two partitioned by
  the owning user's ID (base64url-encoded), so looking up a user's credentials is a single-partition query and
  registering or removing a credential is a point operation.
- **The real tradeoff: credential-ID-only lookups are cross-partition.** `GetCredentialByIdAsync`,
  `GetUsersByCredentialIdAsync`, and `GetCredentialsByUserHandleAsync` all look a credential up by something
  other than its partition key. Cosmos indexes every property by default, so these queries still use the
  index -- they're just not confined to one partition, which costs more RUs and latency as the container
  grows. This is the same class of tradeoff DynamoDB's global secondary indexes make; it's not something this
  store tries to eliminate.
- **Credential-ID uniqueness is per-partition, not global.** `AddCredentialToUserAsync` uses
  `CreateItemAsync`, which rejects a duplicate item ID *within a partition* -- nothing in the container itself
  enforces global uniqueness of a credential ID across every user's partition. The caller (via `Fido2`'s own
  ceremony verification) still runs the cross-user uniqueness check before registration, the same as with any
  other store; this store doesn't add a second enforcement layer the way `Fido2.DynamoDb`'s reservation item
  does.
- **Conditional sign-count updates use Cosmos's `If-Match` precondition**, not a database-native conditional
  statement (Cosmos has none): the store reads the credential, checks the sign-count rule in code, and writes
  it back with an `If-Match` precondition on the ETag it just read. If another write got there first, the
  precondition fails (HTTP 412) and the read-check-write cycle retries, bounded, against whatever is current.
