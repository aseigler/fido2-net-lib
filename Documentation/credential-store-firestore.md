# Fido2.Firestore

An `ICredentialStore` backed by Google Cloud Firestore: three collections (usernames, users, credentials),
each keyed so that every lookup is a direct document read instead of a query. See
[Documentation/credential-stores.md](credential-stores.md) for how this compares to the other
`ICredentialStore` packages.

## Install

```bash
dotnet add package Fido2.Firestore
```

## Quickstart

### 1. Register a `FirestoreDb` and the store

A `FirestoreDb` is meant to be a long-lived singleton, the same way an `IMongoDatabase` is for
`Fido2.MongoDb`:

```csharp
services.AddSingleton(_ => FirestoreDb.Create(projectId));
services.AddFido2FirestoreStore();
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

The Firestore emulator runs in Docker, bundled with the Google Cloud SDK image:

```bash
docker run -d -p 8080:8080 gcr.io/google.com/cloudsdktool/cloud-sdk:emulators \
    gcloud emulators firestore start --host-port=0.0.0.0:8080
```

The client only ever looks at the `FIRESTORE_EMULATOR_HOST` environment variable to decide whether to use the
emulator -- there is no settable property for it on `FirestoreDbBuilder` -- so point it there before building:

```csharp
Environment.SetEnvironmentVariable("FIRESTORE_EMULATOR_HOST", "localhost:8080");

services.AddSingleton(_ => new FirestoreDbBuilder
{
    ProjectId = "my-project",
    EmulatorDetection = EmulatorDetection.EmulatorOnly,
}.Build());
```

## Design notes

- **No partition key to design around.** Unlike `Fido2.Cosmos`, Firestore scales a collection natively, and a
  document ID is unique across the *whole* collection, not merely within a partition or shard. That makes a
  credential ID globally unique the instant `AddCredentialToUserAsync` creates its document, with no further
  enforcement layer needed (unlike `Fido2.DynamoDb`'s reservation item or `Fido2.Cosmos`'s per-partition-only
  guarantee) -- and a username is claimed exactly once the same way, via the usernames collection's own
  document-ID uniqueness.
- **Almost every lookup is a direct document read.** A username, a user ID, and a credential ID are each the
  relevant document's own ID, so `GetUserAsync`, `GetCredentialByIdAsync`, and `GetUsersByCredentialIdAsync`
  never run a query at all. Only `GetCredentialsByUserAsync` and `GetCredentialsByUserHandleAsync` do, since
  neither a user ID nor a user handle is a credential's own document ID.
- **Conditional sign-count updates use a Firestore transaction, not a hand-rolled retry loop.**
  `UpdateCredentialRecordAsync` reads the current sign count and writes the updated one inside one
  `RunTransactionAsync` call. Firestore itself detects a conflicting concurrent write at commit time and
  retries the whole callback against the then-current document, bounded to a handful of attempts --
  `Fido2.Cosmos`'s equivalent needs its own explicit ETag-precondition retry loop because Cosmos has no
  transaction primitive that does this for it; Firestore does.
- **Binary fields are stored as `Blob`, not `byte[]`.** Firestore's POCO mapping (`[FirestoreData]`) has no
  built-in support for a raw `byte[]` property; every byte-array field on `StoredCredential` (the credential
  ID, public key, user handle, and so on) is wrapped as a `Google.Cloud.Firestore.Blob` in the store's
  internal document shape and converted at the boundary. This is purely an internal mapping detail -- nothing
  about it is visible through `ICredentialStore`.
- **No separate mock-based unit test layer.** `Fido2.Cosmos.Tests` has one because `Microsoft.Azure.Cosmos`'s
  types are explicitly designed to be mockable; the Firestore SDK's equivalents (`FirestoreDb`,
  `DocumentReference`, `Transaction`) are not, so this store's only test coverage runs against a real
  Firestore emulator instead.
