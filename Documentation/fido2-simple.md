# Fido2.Simple

A thin, opinionated facade over `IFido2` and `ICredentialStore`: four methods covering the common
registration and authentication ceremonies, with the storage lookups and the uniqueness/ownership callbacks
`IFido2` otherwise asks the caller to supply done internally against whichever `ICredentialStore` is
registered.

This does not replace `IFido2` -- both are fully supported side by side. Reach for `Fido2.Simple` first if
you're building an ordinary sign-up/sign-in flow; drop to `IFido2` directly the moment you need something this
facade doesn't expose (see [When to use `IFido2` directly](#when-to-use-ifido2-directly)).

## Install

```bash
dotnet add package Fido2.Simple
```

It depends on `Fido2` and `ICredentialStore` (see [Documentation/credential-stores.md](credential-stores.md)
for which store package to add) -- both must already be registered.

## Quickstart

```csharp
services.AddFido2(options =>
{
    options.ServerDomain = "example.com";
    options.ServerName = "Example App";
    options.Origins = new HashSet<string> { "https://example.com" };
});
services.AddFido2MongoDbStore(); // or any other ICredentialStore package
services.AddFido2Simple();
```

```csharp
public class AccountController(ISimpleFido2Authentication fido2) : Controller
{
    [HttpPost("register/begin")]
    public async Task<CredentialCreateOptions> BeginRegister(string username)
    {
        var options = await fido2.InitiateRegistrationAsync(username);
        HttpContext.Session.SetString("fido2.options", options.ToJson());
        return options;
    }

    [HttpPost("register/finish")]
    public async Task<IActionResult> FinishRegister(AuthenticatorAttestationRawResponse response)
    {
        var options = CredentialCreateOptions.FromJson(HttpContext.Session.GetString("fido2.options")!);
        HttpContext.Session.Remove("fido2.options"); // hold options server-side and discard them before completing
        await fido2.CompleteRegistrationAsync(options, response);
        return Ok();
    }

    [HttpPost("login/begin")]
    public async Task<AssertionOptions> BeginLogin(string? username)
    {
        var options = await fido2.InitiateAuthenticationAsync(username);
        HttpContext.Session.SetString("fido2.options", options.ToJson());
        return options;
    }

    [HttpPost("login/finish")]
    public async Task<IActionResult> FinishLogin(AuthenticatorAssertionRawResponse response)
    {
        var options = AssertionOptions.FromJson(HttpContext.Session.GetString("fido2.options")!);
        HttpContext.Session.Remove("fido2.options");
        var user = await fido2.CompleteAuthenticationAsync(options, response);
        // sign the user in
        return Ok();
    }
}
```

A ceremony is inherently two-step and stateless in between: hold the options returned by `InitiateRegistrationAsync`/
`InitiateAuthenticationAsync` somewhere server-side (session state above; a short-lived cache entry keyed by a
correlation ID also works) and pass them back to the matching `Complete*Async` call -- the same shape as using
`IFido2` directly.

## The four methods

| Method | What it does |
|---|---|
| `InitiateRegistrationAsync(username, displayName?, options?)` | Starts a registration ceremony, creating the account if it doesn't already exist (via `ICredentialStore.GetOrAddUserAsync`). If the account already has credentials, they're added to the exclude list so the client doesn't create a redundant one on an authenticator that already holds one. |
| `CompleteRegistrationAsync(originalOptions, attestationResponse)` | Verifies the response, then persists the new credential via `ICredentialStore.AddCredentialToUserAsync`. |
| `InitiateAuthenticationAsync(username?)` | Starts an authentication ceremony. Give a username for a named sign-in (that account's credentials become the allow-list); omit it for a discoverable-credential ("usernameless"/passkey) ceremony -- both are first-class, not a fallback path. A username that doesn't match any account throws, rather than silently falling back to a discoverable ceremony. |
| `CompleteAuthenticationAsync(originalOptions, assertionResponse, uvInitializationAuthorized?)` | Verifies the response against the stored credential, then applies the resulting signature-counter/backup-state update via `ICredentialStore.UpdateCredentialRecordAsync`. |

`uvInitializationAuthorized` is never defaulted to `true` and never hidden behind a convenience overload: WebAuthn's
spec text says promoting a credential's `uvInitialized` flag "SHOULD require authorization by an additional
authentication factor equivalent to WebAuthn user verification" -- a real Relying Party security decision, not
something this facade should make for you.

## What's configurable

`SimpleRegistrationOptions`, passed to `InitiateRegistrationAsync`, is deliberately small:

```csharp
var options = await fido2.InitiateRegistrationAsync(username, options: new SimpleRegistrationOptions
{
    AttestationPreference = AttestationConveyancePreference.Direct,
    PubKeyCredParams = [PubKeyCredParam.ES256],
    AuthenticatorSelection = AuthenticatorSelection.PlatformOnly,
});
```

- `AttestationPreference` -- defaults to `None` (requesting attestation adds privacy prompts and verification
  complexity most callers of this simplified surface don't want).
- `PubKeyCredParams` -- the key types/algorithms to accept, most preferred first. Defaults to `PubKeyCredParam.Defaults`.
- `AuthenticatorSelection` -- which authenticators are eligible. Defaults to `AuthenticatorSelection.Default`.

Everything else about a ceremony (WebAuthn extensions, attestation formats/hints, and every other `IFido2`
knob) is intentionally not exposed here.

## When to use `IFido2` directly

This facade's four methods cover an ordinary sign-up/sign-in flow and nothing else. Use `IFido2` instead the
moment you need:

- **WebAuthn extensions** -- PRF, `credProtect`, `largeBlob`, and so on. None of them are reachable through
  this facade's options.
- **Attestation formats or hints** beyond the single `AttestationPreference` knob above.
- **Adding a credential to an already-authenticated user's account** without going through a sign-up flow
  (`InitiateRegistrationAsync` is for creating an account or adding to one that isn't authenticated yet in the
  current request -- see the caution below).
- **Any other control** `IFido2`'s own, more granular API exposes that these four methods don't.

Exceptions are unchanged either way: everything this facade's methods can throw is the same types `IFido2` and
`ICredentialStore` already throw (chiefly `Fido2VerificationException`) -- there's no separate error-handling
convention to learn switching between the two.

**A caution on `InitiateRegistrationAsync`:** it's meant for sign-up. If your application wires it to a form
reachable regardless of whether the caller is already authenticated, treat that the same way you'd treat any
other endpoint that can create or modify accounts -- verify who's calling before trusting a client-supplied
username. This facade does not perform authentication itself; it's a WebAuthn ceremony helper, not an identity
provider.
