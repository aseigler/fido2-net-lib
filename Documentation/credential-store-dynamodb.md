# Fido2.DynamoDb

An `ICredentialStore` over a single DynamoDB table, using a single-table design idiomatic to DynamoDB rather
than one table per entity. Credential items denormalize their owner's identity, so a credential-ID-only lookup
never needs a second round trip, and a `TransactWriteItems` call gives strongly-consistent global credential-ID
uniqueness across every user's items -- no *partitioning* tradeoff to document here, unlike Cosmos or Redis.
There's still a consistency tradeoff, just a different one: see [Design notes](#design-notes) below.

See [Documentation/credential-stores.md](credential-stores.md) for how it compares to the other packages.

## Install

```bash
dotnet add package Fido2.DynamoDb
dotnet add package AWSSDK.DynamoDBv2
```

## Quickstart

### 1. Register a client and the store

```csharp
services.AddSingleton<IAmazonDynamoDB>(_ => new AmazonDynamoDBClient());
services.AddFido2DynamoDbStore();
```

Table and index names default to `Fido2Credentials`, `UserHandleIndex`, and `CredentialIdIndex`; override them
if you need to:

```csharp
services.AddFido2DynamoDbStore(options =>
{
    options.TableName = "MyApp-Fido2Credentials";
});
```

### 2. Create the table

Provisioning a table is often an infrastructure decision made through IaC (CloudFormation, CDK, Terraform)
rather than at application startup. For development, testing, or simple deployments, the package includes a
helper that creates it directly:

```csharp
var client = new AmazonDynamoDBClient();
await DynamoDbTableSchema.EnsureTableExistsAsync(client, new DynamoDbCredentialStoreOptions());
```

The schema it creates: partition key `PK` (String), sort key `SK` (String), plus two Global Secondary Indexes
(each projecting all attributes) -- one keyed on `UserHandle` for the discoverable-credential ceremony, one
keyed on `CredentialId` for credential-ID-only lookups. Billing mode is pay-per-request, since an
authentication store's access pattern is bursty, not steady.

If you provision the table yourself via IaC instead, match this schema exactly -- the store's queries depend
on the index names and key structure, not just the table existing.

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

```bash
docker run -d -p 8000:8000 amazon/dynamodb-local
```

```csharp
services.AddSingleton<IAmazonDynamoDB>(_ => new AmazonDynamoDBClient(
    new AmazonDynamoDBConfig { ServiceURL = "http://localhost:8000" }));
```

Setting `RegionEndpoint` alongside a custom `ServiceURL` here is a common AWS SDK footgun -- the SDK silently
prefers the real regional AWS endpoint over your local container if both are set. Use `ServiceURL` alone for
local development.

## Design notes

- **`AddFido2DynamoDbStore` registers the store as a singleton**, not scoped like the other stores -- there's
  no per-request connection state to isolate; `IAmazonDynamoDB` is itself meant to be a long-lived singleton.
- **Credential-ID uniqueness is enforced globally**, not just per-user, via a `TransactWriteItems` call that
  atomically creates the credential item and a reservation item together -- if the reservation already exists,
  the whole transaction fails, so two concurrent registrations can never both succeed with the same credential
  ID.
- **Credential-ID and user-handle lookups are only eventually consistent.** `GetCredentialByIdAsync`,
  `GetUsersByCredentialIdAsync`, `UpdateCredentialRecordAsync`, and `RemoveCredentialAsync` all resolve a
  credential through a Global Secondary Index, and DynamoDB GSIs do not support strongly-consistent reads at
  all -- a credential registered a moment ago can briefly fail to resolve through one. The uniqueness
  guarantee above and the sign-count-regression check in `UpdateCredentialRecordAsync` don't depend on the
  index either way (both go through the base table, which is strongly consistent); only *finding* a
  credential by its ID or user handle has this window.
