# Fido2.EntityFrameworkCore

An `ICredentialStore` over any EF Core `DbContext` -- SQL Server, PostgreSQL, SQLite, MySQL, or any other
relational provider.

```csharp
services.AddDbContext<Fido2DbContext>(options => options.UseSqlServer(connectionString));
services.AddFido2EntityFrameworkCoreStore<Fido2DbContext>();
```

See the [full quickstart](https://github.com/passwordless-lib/fido2-net-lib/blob/main/Documentation/credential-store-entityframeworkcore.md)
for schema/migrations setup and design notes, and
[Documentation/credential-stores.md](https://github.com/passwordless-lib/fido2-net-lib/blob/main/Documentation/credential-stores.md)
for how this compares to the other `ICredentialStore` packages.
