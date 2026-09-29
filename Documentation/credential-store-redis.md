# Fido2.Redis

An `ICredentialStore` backed by Redis: simple and fast, with `AddCredentialToUserAsync` and
`RemoveCredentialAsync` keeping the credential record and all of its indexes consistent inside one Redis
transaction. Redis has no native secondary index, so this is the one native store where every non-primary-key
lookup depends on hand-maintained index structures rather than a query the database itself can answer -- read
[Design notes](#design-notes) before relying on this in production.

See [Documentation/credential-stores.md](credential-stores.md) for how it compares to the other packages.

## Install

```bash
dotnet add package Fido2.Redis
dotnet add package StackExchange.Redis
```

## Quickstart

### 1. Register a connection and the store

```csharp
services.AddSingleton<IConnectionMultiplexer>(_ =>
    ConnectionMultiplexer.Connect("localhost:6379"));

services.AddFido2RedisStore();
```

There's no schema or index to create up front -- every key this store writes is created on first use. An
optional `keyPrefix` (default `"fido2:"`) lets you share a Redis instance with other data:

```csharp
services.AddFido2RedisStore(keyPrefix: "myapp:auth:");
```

### 2. Register and authenticate

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
docker run -d -p 6379:6379 redis
```

## Design notes

- **Every lookup this interface needs -- by user, by credential ID, by user handle, and the reverse "who owns
  this credential ID" lookup -- is served by a hand-maintained index**: a Redis Set of credential IDs per user
  or per user handle, and a single owner-username key per credential. `AddCredentialToUserAsync` and
  `RemoveCredentialAsync` are the only places that write these indexes, and they do so inside a single Redis
  transaction together with the credential record itself, so the indexes can never drift out of sync with what
  they index -- as long as nothing bypasses this class to write to Redis directly.
- **Durability is entirely a deployment concern.** This store is only as durable as the Redis deployment it
  points at: unless the server has RDB or AOF persistence enabled, credentials stored here do not survive a
  Redis restart. That's not something this class can enforce or detect.
- **Sign-count updates are a single Lua script** run server-side (`EVAL`), so the read-compare-write for the
  counter check happens atomically in one round trip, the same conditional-update guarantee the EF Core store
  gets from a database `UPDATE ... WHERE` and Cosmos gets from an `If-Match` precondition retry loop.
