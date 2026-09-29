import { base64UrlToBuffer, bufferToBase64Url } from "./base64url.js";
import { extendedPublicKeyCredential, supportsJsonMethods } from "./browser.js";
import { isWebAuthnCancellation, WebAuthnCancellationError } from "./errors.js";
import type { CredentialCreationOptionsJSON, RegistrationResponseJSON } from "./types.js";

export interface StartRegistrationOptions {
  /** `'conditional'` for a conditional create (WebAuthn Level 3 §5.1.3); omit for a normal, modal registration. */
  mediation?: CredentialMediationRequirement;
  /** Aborts the ceremony, e.g. from an `AbortController` shared with a concurrent conditional authentication. */
  signal?: AbortSignal;
}

/** `CredentialCreationOptions` predates the `mediation`/`signal` members `lib.dom.d.ts` may still be missing. */
type CreateRequest = CredentialCreationOptions & { mediation?: CredentialMediationRequirement; signal?: AbortSignal };

function optionsFromJsonFallback(options: CredentialCreationOptionsJSON): CredentialCreationOptions {
  return {
    publicKey: {
      ...options,
      challenge: base64UrlToBuffer(options.challenge),
      user: { ...options.user, id: base64UrlToBuffer(options.user.id) },
      excludeCredentials: options.excludeCredentials?.map((credential) => ({
        ...credential,
        id: base64UrlToBuffer(credential.id),
      })),
    } as PublicKeyCredentialCreationOptions,
  };
}

function credentialToJsonFallback(credential: PublicKeyCredential): RegistrationResponseJSON {
  const response = credential.response as AuthenticatorAttestationResponse;

  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: "public-key",
    authenticatorAttachment: (credential as { authenticatorAttachment?: string }).authenticatorAttachment,
    response: {
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
      attestationObject: bufferToBase64Url(response.attestationObject),
      transports: response.getTransports?.(),
    },
    clientExtensionResults: credential.getClientExtensionResults() as Record<string, unknown>,
  };
}

/**
 * Runs a WebAuthn registration ceremony: turns the server's creation options into a browser prompt via
 * `navigator.credentials.create()`, and returns the JSON shape `Fido2.MakeNewCredentialAsync` expects.
 *
 * Uses the browser's native `PublicKeyCredential.parseCreationOptionsFromJSON()`/`toJSON()` (WebAuthn Level 3
 * §5.1.8/§5.1.9) when available, falling back to manual base64url conversion on older browsers.
 */
export async function startRegistration(
  optionsJSON: CredentialCreationOptionsJSON,
  { mediation, signal }: StartRegistrationOptions = {},
): Promise<RegistrationResponseJSON> {
  const request: CreateRequest = supportsJsonMethods()
    ? { publicKey: extendedPublicKeyCredential().parseCreationOptionsFromJSON!(optionsJSON) }
    : optionsFromJsonFallback(optionsJSON);

  if (mediation) {
    request.mediation = mediation;
  }

  if (signal) {
    request.signal = signal;
  }

  let credential: Credential | null;

  try {
    credential = await navigator.credentials.create(request);
  } catch (error) {
    if (isWebAuthnCancellation(error)) {
      throw new WebAuthnCancellationError(error);
    }
    throw error;
  }

  if (!credential) {
    throw new Error("navigator.credentials.create() returned no credential.");
  }

  const publicKeyCredential = credential as PublicKeyCredential;

  return supportsJsonMethods()
    ? ((publicKeyCredential as unknown as { toJSON(): RegistrationResponseJSON }).toJSON())
    : credentialToJsonFallback(publicKeyCredential);
}
