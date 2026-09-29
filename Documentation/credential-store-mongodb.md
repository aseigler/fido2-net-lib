# Fido2.MongoDb

An `ICredentialStore` over MongoDB: two collections, `fido2.users` and `fido2.credentials` by default, mapped
almost 1:1 onto `Fido2User` and `StoredCredential` -- there's no impedance mismatch to work around, which
makes this one of the simpler stores to reason about.

See [Documentation/credential-stores.md](credential-stores.md) for how it compares to the other packages.

## Install

```bash
dotnet add package Fido2.MongoDb
```

## Quickstart

### 1. Register a database and the store

```csharp
services.AddSingleton<IMongoClient>(_ => new MongoClient(connectionString));
services.AddSingleton<IMongoDatabase>(sp => sp.GetRequiredService<IMongoClient>().GetDatabase("fido2"));
services.AddFido2MongoDbStore();
```

Collection names default to `fido2.users` and `fido2.credentials`; override them if you want to share a
database with other data:

```csharp
services.AddFido2MongoDbStore(new MongoDbCredentialStoreOptions
{
    UsersCollectionName = "auth.fido2_users",
    CredentialsCollectionName = "auth.fido2_credentials",
});
```

### 2. Create the indexes once at startup

**This step is not optional.** The unique index on username is what makes `GetOrAddUserAsync` race-safe --
without it, two concurrent sign-ups for the same username can both succeed as two different accounts.

```csharp
var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var store = (MongoDbCredentialStore)scope.ServiceProvider.GetRequiredService<ICredentialStore>();
    await store.EnsureIndexesCreatedAsync();
}
```

It's idempotent, so calling it on every application startup (rather than as a one-time migration step) is the
expected usage -- that's also what makes it safe in a multi-instance deployment where more than one instance
might run it concurrently on boot.

This creates: a unique index on `Fido2User.Name`, and two lookup indexes on `StoredCredential.UserId` and
`StoredCredential.UserHandle`.

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
docker run -d -p 27017:27017 mongo:7.0
```

```csharp
services.AddSingleton<IMongoClient>(_ => new MongoClient("mongodb://localhost:27017"));
```

## Design notes

- **Why a unique index instead of application-level locking:** the same pattern the EF Core store uses (a
  database constraint, not a check-then-insert race) -- it's simpler and it's correct under real concurrency,
  where a check-then-insert in application code is not.
- **BSON class maps are registered once, automatically**, the first time a `MongoDbCredentialStore` is
  constructed (`Fido2MongoDbClassMaps.EnsureRegistered()`) -- nothing to configure yourself.
- **A sign-count regression is rejected**, not silently accepted: `UpdateCredentialRecordAsync` throws if an
  assertion's counter isn't greater than what's stored (unless both are zero, for authenticators that don't
  implement counters at all), the same replay/clone-detection behavior every other store here implements.
