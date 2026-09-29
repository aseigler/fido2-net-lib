# Fido2.MongoDb

An `ICredentialStore` over MongoDB: two collections, mapped almost 1:1 onto `Fido2User` and `StoredCredential`.

```csharp
services.AddSingleton<IMongoDatabase>(_ => new MongoClient(connectionString).GetDatabase("fido2"));
services.AddFido2MongoDbStore();
```

Call `EnsureIndexesCreatedAsync()` once at startup before using the store -- it's what makes user registration
race-safe. See the [full quickstart](https://github.com/passwordless-lib/fido2-net-lib/blob/main/Documentation/credential-store-mongodb.md)
for details, and
[Documentation/credential-stores.md](https://github.com/passwordless-lib/fido2-net-lib/blob/main/Documentation/credential-stores.md)
for how this compares to the other `ICredentialStore` packages.
