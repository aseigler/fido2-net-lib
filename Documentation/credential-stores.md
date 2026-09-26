# Credential stores

`ICredentialStore` is the contract a storage backend implements to persist `Fido2User` accounts and their
`StoredCredential`s: looking users and credentials up by name, ID, or user handle; registering a new
credential; applying the signature-counter/backup-state update after a successful assertion; and removing a
credential. `Fido2` itself does not persist anything -- it verifies ceremonies and hands you the results, and
an `ICredentialStore` is where those results actually live between requests.

`Fido2NetLib.Development.DevelopmentInMemoryStore` (in the `Fido2.Development` package) is a reference
implementation used by the demos. It is not a production store: nothing survives a process restart.

## Available stores

| Package | Backend | Pitch | Main tradeoff |
|---|---|---|---|
| `Fido2.EntityFrameworkCore` | SQL Server, PostgreSQL, SQLite, MySQL, Cosmos DB -- any EF Core provider | One store, whichever relational database you already run | Generic: Cosmos DB via EF's own provider has partitioning limitations the native `Fido2.Cosmos` store below avoids |
| `Fido2.MongoDb` | MongoDB | Two collections (users, credentials); a unique index on the username makes `GetOrAddUserAsync` race-safe the same way the EF Core store relies on a database constraint | Call `EnsureIndexesCreatedAsync()` once at startup before using the store |
| `Fido2.DynamoDb` | DynamoDB | Single-table design idiomatic to DynamoDB; credential items denormalize the owner's identity so a credential-ID lookup never needs a second round trip; a `TransactWriteItems` call gives strongly-consistent global credential-ID uniqueness | None major -- this is the cleanest of the four to operate |
| `Fido2.Cosmos` | Azure Cosmos DB, native SDK | Deliberate partitioning (credentials and user items partitioned by user ID, so per-user reads/writes are single-partition point operations), instead of what falls out of the generic EF Core Cosmos provider | Credential-ID-only lookups (not scoped to a known user) are cross-partition queries |
| `Fido2.Redis` | Redis | Simple and fast; `AddCredentialToUserAsync`/`RemoveCredentialAsync` keep the credential record and all of its indexes consistent inside one Redis transaction | Redis has no native secondary index -- every lookup by credential ID or user handle depends on hand-maintained index Sets/keys rather than a query |

## How to pick one

- Already running a relational database (or Cosmos DB, and the cross-partition tradeoff below doesn't matter
  to you) → `Fido2.EntityFrameworkCore`.
- Already running MongoDB, DynamoDB, Cosmos DB, or Redis → the matching native package. Prefer `Fido2.Cosmos`
  over `Fido2.EntityFrameworkCore` on Cosmos specifically if you want deliberate partitioning rather than
  whatever EF's provider does with it.
- None of the above, or just evaluating the library → `Fido2.Development`'s `DevelopmentInMemoryStore`, then
  swap it out before going to production.

## Usage

Every store registers itself as the scoped `ICredentialStore` through its own `AddFido2*Store` extension
method on `IServiceCollection`. For example, MongoDB:

```csharp
services.AddSingleton<IMongoDatabase>(_ => new MongoClient(connectionString).GetDatabase("fido2"));
services.AddFido2MongoDbStore();
```

The other packages follow the same shape, with the registration call each one needs:

```csharp
// Fido2.EntityFrameworkCore -- over a context registered separately, e.g. with AddDbContext<TContext>()
services.AddFido2EntityFrameworkCoreStore<MyDbContext>();

// Fido2.DynamoDb
services.AddFido2DynamoDbStore(options => { /* table name, region, etc. */ });

// Fido2.Cosmos -- you provide the Container, so you control how it's constructed/configured
services.AddFido2CosmosStore(sp => sp.GetRequiredService<CosmosClient>().GetContainer("fido2", "credentials"));

// Fido2.Redis
services.AddFido2RedisStore(); // optionally a keyPrefix other than the default "fido2:"
```

Whichever you choose, resolve `ICredentialStore` from the container as usual -- the rest of your integration
(the `IFido2` calls in the [Quick Start](../README.md#quick-start)) does not change based on which store is
behind it.

Each store's own XML doc comments (and, for `Fido2.Redis`, the design tradeoffs in the table above) go into
more depth than this page does; start there if you need to understand exactly how a specific store behaves
under concurrent writers.
