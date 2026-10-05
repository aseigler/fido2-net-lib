# Fido2.Simple

A thin, opinionated facade over `IFido2` and `ICredentialStore`: four methods covering the common
registration and authentication ceremonies, with the storage lookups and callbacks `IFido2` otherwise asks
the caller to supply done internally against whichever `ICredentialStore` is registered.

```csharp
services.AddFido2(options => { /* ... */ });
services.AddFido2MongoDbStore(); // or any other ICredentialStore package
services.AddFido2Simple();
```

Does not replace `IFido2` -- both are fully supported side by side; drop to `IFido2` directly the moment you
need something this facade doesn't expose. See the
[full quickstart](https://github.com/passwordless-lib/fido2-net-lib/blob/main/Documentation/fido2-simple.md)
for the four methods, what's configurable, and when to use `IFido2` directly instead.
