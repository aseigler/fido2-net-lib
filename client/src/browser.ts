import type { ClientCapabilities } from "./types.js";

/**
 * The parts of the `PublicKeyCredential` static surface this package uses that are newer than what the
 * installed TypeScript's `lib.dom.d.ts` may declare (WebAuthn Level 3 additions). Declared locally and
 * accessed through `extendedPublicKeyCredential()` rather than via global augmentation, so this package
 * compiles against any reasonably recent `lib.dom` without depending on exactly which L3 members it has
 * already picked up.
 */
export interface ExtendedPublicKeyCredentialStatic {
  /**
   * Returns `PublicKeyCredentialCreationOptions` itself (WebAuthn L3 §5.1.8) -- the value to assign to
   * `CredentialCreationOptions.publicKey`, not `CredentialCreationOptions` already wrapping it.
   */
  parseCreationOptionsFromJSON?: (options: unknown) => PublicKeyCredentialCreationOptions;
  /**
   * Returns `PublicKeyCredentialRequestOptions` itself (WebAuthn L3 §5.1.8) -- the value to assign to
   * `CredentialRequestOptions.publicKey`, not `CredentialRequestOptions` already wrapping it.
   */
  parseRequestOptionsFromJSON?: (options: unknown) => PublicKeyCredentialRequestOptions;
  getClientCapabilities?: () => Promise<ClientCapabilities>;
  signalUnknownCredential?: (options: unknown) => Promise<void>;
  signalAllAcceptedCredentials?: (options: unknown) => Promise<void>;
  signalCurrentUserDetails?: (options: unknown) => Promise<void>;
  isConditionalMediationAvailable?: () => Promise<boolean>;
}

export function extendedPublicKeyCredential(): ExtendedPublicKeyCredentialStatic {
  if (typeof PublicKeyCredential === "undefined") {
    throw new Error("This browser does not support WebAuthn (no PublicKeyCredential).");
  }

  return PublicKeyCredential as unknown as ExtendedPublicKeyCredentialStatic;
}

/** Whether this browser can create or use WebAuthn credentials at all. */
export function browserSupportsWebAuthn(): boolean {
  return typeof PublicKeyCredential !== "undefined" && typeof navigator?.credentials?.create === "function";
}

/**
 * Whether this browser natively supports `parseCreationOptionsFromJSON()`/`parseRequestOptionsFromJSON()`/
 * `toJSON()` (WebAuthn Level 3 §5.1.8/§5.1.9), so options/response conversion doesn't need the base64url
 * fallback in this package.
 */
export function supportsJsonMethods(): boolean {
  if (!browserSupportsWebAuthn()) {
    return false;
  }

  const pkc = extendedPublicKeyCredential();
  return typeof pkc.parseCreationOptionsFromJSON === "function" && typeof pkc.parseRequestOptionsFromJSON === "function";
}

/**
 * Whether this browser supports conditional mediation (WebAuthn autofill UI), so a registration or
 * authentication request may be offered quietly alongside a form field rather than in a modal prompt.
 */
export async function browserSupportsWebAuthnAutofill(): Promise<boolean> {
  if (!browserSupportsWebAuthn()) {
    return false;
  }

  const isAvailable = extendedPublicKeyCredential().isConditionalMediationAvailable;
  return typeof isAvailable === "function" && (await isAvailable());
}
