# Fido2.EntityFrameworkCore

An `ICredentialStore` over any EF Core `DbContext` -- SQL Server, PostgreSQL, SQLite, MySQL, or any other
relational provider. The one native store here that isn't backend-specific: you bring whichever EF Core
provider you already use, and this package supplies the entity configurations and the store implementation on
top of it.

If you're specifically on Azure Cosmos DB, prefer [`Fido2.Cosmos`](credential-store-cosmos.md) instead --
its deliberate per-user partitioning avoids limitations of EF Core's generic Cosmos provider. See
[Documentation/credential-stores.md](credential-stores.md) for how the packages compare.

## Install

```bash
dotnet add package Fido2.EntityFrameworkCore
dotnet add package Microsoft.EntityFrameworkCore.SqlServer   # or .Sqlite, Npgsql.EntityFrameworkCore.PostgreSQL, Pomelo.EntityFrameworkCore.MySql, ...
```

## Quickstart

### 1. Use the built-in context, or add the configurations to your own

The package ships `Fido2DbContext`, a context holding only the two FIDO2 tables:

```csharp
services.AddDbContext<Fido2DbContext>(options =>
    options.UseSqlServer(connectionString));

services.AddFido2EntityFrameworkCoreStore<Fido2DbContext>();
```

To keep the FIDO2 tables inside a context you already have instead of a separate one, apply the
configurations in your own `OnModelCreating`:

```csharp
protected override void OnModelCreating(ModelBuilder modelBuilder)
{
    modelBuilder.ApplyConfigurationsFromAssembly(typeof(Fido2DbContext).Assembly);
    // ... the rest of your model
}
```

```csharp
services.AddDbContext<AppDbContext>(options => options.UseSqlServer(connectionString));
services.AddFido2EntityFrameworkCoreStore<AppDbContext>();
```

### 2. Create the schema

Schema changes are yours to manage with EF Core migrations, the same as the rest of your model:

```bash
dotnet ef migrations add AddFido2Tables
dotnet ef database update
```

This creates two tables: `Fido2Users` (keyed by user handle, unique index on username) and `Fido2Credentials`
(a database-generated surrogate key, with a unique index on the credential ID -- credential IDs can be up to
1023 bytes, more than some databases allow in a clustered key, which is why the credential ID isn't the
primary key itself). `Fido2Credentials.UserId` is a foreign key to `Fido2Users`, cascade-deleted with it.

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

See [Fido2.Simple's own docs](../README.md#quick-start) for the authentication half, or use `IFido2` directly
if you need WebAuthn extensions or other controls the simple facade doesn't expose.

### Local development

Any relational database works for local dev; SQLite is the least ceremony:

```csharp
services.AddDbContext<Fido2DbContext>(options => options.UseSqlite("Data Source=fido2.db"));
```

## Concurrency and design notes

- **`GetOrAddUserAsync` is race-safe** via the unique index on username, not application-level locking: if two
  requests try to create the same username at once, the loser's insert fails with `DbUpdateException`, and the
  store re-reads the row the winner just created instead of throwing.
- **`UpdateCredentialRecordAsync` needs a relational provider.** It's a single conditional `UPDATE` (the
  sign-count check happens in the same statement as the write, not as a separate read-then-write), so the EF
  Core InMemory provider can't run it -- use SQLite for tests that need real store behavior, not InMemory.
- **The EF Core InMemory provider is not a substitute for a real database in tests of this store for the same
  reason.** `Tests/Fido2.EntityFrameworkCore.Tests` runs against SQLite.
