# Analyzers

The `Fido2` package bundles a small set of Roslyn analyzers that catch integration mistakes specific to this
library -- ones a general-purpose linter has no way to know about. They ship automatically with `Fido2` itself
(see [Bundling](#bundling)); there's no separate package to install.

## FIDO001: `MakeAssertionAsync` result is discarded

```csharp
await fido2.MakeAssertionAsync(request); // FIDO001: the result is not used
```

WebAuthn Level 3 step 24 requires storing the credential record's updated signature counter (and backup
state) after a successful assertion. `MakeAssertionAsync` returns that update as a `VerifyAssertionResult`;
if the call site discards it, an authenticator that later replays a stale counter -- the actual signal a
cloned authenticator produces -- is never caught.

Fix: capture the result and persist its `SignCount`, `IsBackedUp`, and `IsUserVerified` fields (via
`ICredentialStore.UpdateCredentialRecordAsync`, or your own storage call if you're not using one of the
`ICredentialStore` packages):

```csharp
var result = await fido2.MakeAssertionAsync(request);
await credentialStore.UpdateCredentialRecordAsync(result);
```

## FIDO002: `IsCredentialIdUniqueToUserCallback` always reports the credential ID as unique

```csharp
IsCredentialIdUniqueToUserCallback = (args, ct) => Task.FromResult(true), // FIDO002
```

WebAuthn Level 3 step 26 requires rejecting registration when the credential ID is already registered to any
user. A callback that unconditionally returns `true` -- a common development-time stub left in place -- never
enforces this: an attacker who obtained a credential ID and public key (e.g. from a data breach of a
*different* relying party using the same authenticator) could register a victim's credential as their own on
your Relying Party too.

Fix: actually check the store.

```csharp
IsCredentialIdUniqueToUserCallback = async (args, ct) =>
    (await credentialStore.GetUsersByCredentialIdAsync(args.CredentialId, ct)).Count == 0,
```

If you're using one of the `ICredentialStore` packages, `Fido2.Simple`'s `InitiateRegistrationAsync` does this
correctly for you already -- see [Documentation/fido2-simple.md](fido2-simple.md).

## Bundling

Both rules ship inside the `Fido2` package itself (`analyzers/dotnet/cs`), not as a separate `Fido2.Analyzers`
package -- every consumer of `Fido2` gets them automatically, in the IDE and in `dotnet build`, with nothing
extra to install or reference. `Fido2.Analyzers` still exists as its own project in this repo (with its own
test suite, `Tests/Fido2.Analyzers.Tests`), but it isn't published separately; `Fido2.csproj` references it
with `ReferenceOutputAssembly="false"` so consumers never get an assembly reference to it, only the analyzer.

Both diagnostics default to a warning, not an error, and can be adjusted like any other analyzer in your own
`.editorconfig`:

```ini
[*.cs]
dotnet_diagnostic.FIDO001.severity = error
dotnet_diagnostic.FIDO002.severity = error
```
