import { base64UrlToBuffer, bufferToBase64Url } from "./base64url.js";
import { extendedPublicKeyCredential, supportsJsonMethods } from "./browser.js";
import { isWebAuthnCancellation, WebAuthnCancellationError } from "./errors.js";
import type { AssertionOptionsJSON, AuthenticationResponseJSON } from "./types.js";

export interface StartAuthenticationOptions {
  /** `'conditional'` offers sign-in quietly alongside a form field (WebAuthn autofill UI). */
  mediation?: CredentialMediationRequirement;
  /** Aborts the ceremony, e.g. when the user starts typing after a conditional request was issued. */
  signal?: AbortSignal;
}

function optionsFromJsonFallback(options: AssertionOptionsJSON): CredentialRequestOptions {
  return {
    publicKey: {
      ...options,
      challenge: base64UrlToBuffer(options.challenge),
      allowCredentials: options.allowCredentials?.map((credential) => ({
        ...credential,
        id: base64UrlToBuffer(credential.id),
      })),
    } as PublicKeyCredentialRequestOptions,
  };
}

function credentialToJsonFallback(credential: PublicKeyCredential): AuthenticationResponseJSON {
  const response = credential.response as AuthenticatorAssertionResponse;

  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: "public-key",
    authenticatorAttachment: (credential as { authenticatorAttachment?: string }).authenticatorAttachment,
    response: {
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
      authenticatorData: bufferToBase64Url(response.authenticatorData),
      signature: bufferToBase64Url(response.signature),
      userHandle: response.userHandle ? bufferToBase64Url(response.userHandle) : undefined,
    },
    clientExtensionResults: credential.getClientExtensionResults() as Record<string, unknown>,
  };
}

/**
 * Runs a WebAuthn authentication ceremony: turns the server's assertion options into a browser prompt via
 * `navigator.credentials.get()`, and returns the JSON shape `Fido2.MakeAssertionAsync` expects.
 *
 * Uses the browser's native `PublicKeyCredential.parseRequestOptionsFromJSON()`/`toJSON()` (WebAuthn Level 3
 * §5.1.8/§5.1.9) when available, falling back to manual base64url conversion on older browsers.
 */
export async function startAuthentication(
  optionsJSON: AssertionOptionsJSON,
  { mediation, signal }: StartAuthenticationOptions = {},
): Promise<AuthenticationResponseJSON> {
  const request: CredentialRequestOptions = supportsJsonMethods()
    ? { publicKey: extendedPublicKeyCredential().parseRequestOptionsFromJSON!(optionsJSON).publicKey }
    : optionsFromJsonFallback(optionsJSON);

  if (mediation) {
    request.mediation = mediation;
  }

  if (signal) {
    request.signal = signal;
  }

  let credential: Credential | null;

  try {
    credential = await navigator.credentials.get(request);
  } catch (error) {
    if (isWebAuthnCancellation(error)) {
      throw new WebAuthnCancellationError(error);
    }
    throw error;
  }

  if (!credential) {
    throw new Error("navigator.credentials.get() returned no credential.");
  }

  const publicKeyCredential = credential as PublicKeyCredential;

  return supportsJsonMethods()
    ? ((publicKeyCredential as unknown as { toJSON(): AuthenticationResponseJSON }).toJSON())
    : credentialToJsonFallback(publicKeyCredential);
}
