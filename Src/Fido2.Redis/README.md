# Fido2.Redis

An `ICredentialStore` backed by Redis: simple and fast, with hand-maintained indexes kept consistent inside a
single Redis transaction per write.

```csharp
services.AddSingleton<IConnectionMultiplexer>(_ => ConnectionMultiplexer.Connect("localhost:6379"));
services.AddFido2RedisStore();
```

Redis has no native secondary index, so every non-primary-key lookup depends on those hand-maintained
indexes -- read the [full quickstart](https://github.com/passwordless-lib/fido2-net-lib/blob/main/Documentation/credential-store-redis.md)'s
design notes before relying on this in production, and see
[Documentation/credential-stores.md](https://github.com/passwordless-lib/fido2-net-lib/blob/main/Documentation/credential-stores.md)
for how this compares to the other `ICredentialStore` packages.
