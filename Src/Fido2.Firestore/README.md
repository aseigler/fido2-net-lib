# Fido2.Firestore

An `ICredentialStore` over Google Cloud Firestore: three collections (usernames, users, credentials), each
keyed so that every lookup is a direct document read rather than a query.

```csharp
services.AddSingleton(_ => FirestoreDb.Create(projectId));
services.AddFido2FirestoreStore();
```

A credential ID and a username are each a document's own ID, so Firestore's own per-collection ID uniqueness
is what makes both claimable exactly once -- no secondary index or reservation item needed. See the
[full quickstart](https://github.com/passwordless-lib/fido2-net-lib/blob/main/Documentation/credential-store-firestore.md)
for details, and
[Documentation/credential-stores.md](https://github.com/passwordless-lib/fido2-net-lib/blob/main/Documentation/credential-stores.md)
for how this compares to the other `ICredentialStore` packages.
