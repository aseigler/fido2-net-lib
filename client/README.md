# @fido2-net-lib/client

Browser client for [fido2-net-lib](https://github.com/passwordless-lib/fido2-net-lib). Runs WebAuthn
registration and authentication ceremonies and returns exactly the JSON shapes the .NET server library
(`Fido2.MakeNewCredentialAsync`/`Fido2.MakeAssertionAsync`) expects, so there's nothing to hand-encode.

This package does not make HTTP requests itself -- fetch your options from your server, pass them in here, and
POST the result back wherever your API expects it. It has no server-specific endpoint names or UI baked in.

## Install

```sh
npm install @fido2-net-lib/client
```

## Usage

```ts
import { startRegistration, startAuthentication } from "@fido2-net-lib/client";

// Registration
const optionsJSON = await fetch("/makeCredentialOptions", { method: "POST" /* ... */ }).then((r) => r.json());
const registrationResponse = await startRegistration(optionsJSON);
await fetch("/makeCredential", { method: "POST", body: JSON.stringify(registrationResponse) });

// Authentication
const assertionOptionsJSON = await fetch("/assertionOptions", { method: "POST" /* ... */ }).then((r) => r.json());
const authenticationResponse = await startAuthentication(assertionOptionsJSON);
await fetch("/makeAssertion", { method: "POST", body: JSON.stringify(authenticationResponse) });
```

`startRegistration`/`startAuthentication` use the browser's native
`PublicKeyCredential.parseCreationOptionsFromJSON()`/`parseRequestOptionsFromJSON()`/`toJSON()` (WebAuthn Level
3 §5.1.8/§5.1.9) when available, and fall back to manual base64url conversion on older browsers -- callers
don't need to know which path ran.

A cancelled prompt (the user pressed Escape, or the platform had nothing to offer) raises
`WebAuthnCancellationError` rather than a raw `DOMException`, so you can tell "nothing happened" apart from an
actual failure.

### Signal API (WebAuthn Level 3 §5.1.10)

```ts
import { signalUnknownCredential, signalAllAcceptedCredentials, signalCurrentUserDetails, supportsSignalApi } from "@fido2-net-lib/client";

if (supportsSignalApi()) {
  const options = await fetch("/signal/unknownCredential", { method: "POST" /* ... */ }).then((r) => r.json());
  await signalUnknownCredential(options);
}
```

Each `options` argument is exactly what your server's `UnknownCredentialOptions.ToJson()` /
`AllAcceptedCredentialsOptions.ToJson()` / `CurrentUserDetailsOptions.ToJson()` produces
(`Src/Fido2.Models/Objects/SignalOptions.cs`).

### Feature detection

```ts
import { browserSupportsWebAuthn, browserSupportsWebAuthnAutofill, getClientCapabilities } from "@fido2-net-lib/client";

if (!browserSupportsWebAuthn()) {
  // fall back to a password form
}

if (await browserSupportsWebAuthnAutofill()) {
  // offer startAuthentication({ mediation: "conditional" }) alongside the username field
}
```

## Development

```sh
npm install
npm run build      # emits dist/ (JS + .d.ts)
npm run typecheck  # type-checks without emitting
```
