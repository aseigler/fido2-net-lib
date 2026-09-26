/**
 * Wire-contract types mirroring the DTOs in Src/Fido2.Models, as serialized by the server (camelCase,
 * byte arrays as unpadded base64url strings). These are also exactly the shapes the browser's native
 * `PublicKeyCredential.parseCreationOptionsFromJSON()`/`parseRequestOptionsFromJSON()`/`toJSON()` consume and
 * produce, per WebAuthn Level 3 §5.1.8/§5.1.9.
 */

/** An unpadded base64url-encoded byte string, e.g. a challenge, credential ID, or user handle. */
export type Base64URLString = string;

export interface PublicKeyCredentialRpEntityJSON {
  id: string;
  name: string;
}

export interface PublicKeyCredentialUserEntityJSON {
  id: Base64URLString;
  name: string;
  displayName: string;
}

export interface PublicKeyCredentialParametersJSON {
  type: "public-key";
  alg: number;
}

export interface PublicKeyCredentialDescriptorJSON {
  id: Base64URLString;
  type: "public-key";
  transports?: string[];
}

export interface AuthenticatorSelectionCriteriaJSON {
  authenticatorAttachment?: string;
  residentKey?: string;
  requireResidentKey?: boolean;
  userVerification?: string;
}

/** Matches Src/Fido2.Models/CredentialCreateOptions.cs. */
export interface CredentialCreationOptionsJSON {
  rp: PublicKeyCredentialRpEntityJSON;
  user: PublicKeyCredentialUserEntityJSON;
  challenge: Base64URLString;
  pubKeyCredParams: PublicKeyCredentialParametersJSON[];
  timeout?: number;
  excludeCredentials?: PublicKeyCredentialDescriptorJSON[];
  authenticatorSelection?: AuthenticatorSelectionCriteriaJSON;
  hints?: string[];
  attestation?: string;
  attestationFormats?: string[];
  extensions?: Record<string, unknown>;
}

/** Matches Src/Fido2.Models/AssertionOptions.cs. */
export interface AssertionOptionsJSON {
  challenge: Base64URLString;
  timeout?: number;
  rpId?: string;
  allowCredentials?: PublicKeyCredentialDescriptorJSON[];
  userVerification?: string;
  hints?: string[];
  extensions?: Record<string, unknown>;
}

/** Matches Src/Fido2.Models/Objects/AuthenticatorAttestationRawResponse.cs. */
export interface RegistrationResponseJSON {
  id: string;
  rawId: Base64URLString;
  type: "public-key";
  authenticatorAttachment?: string;
  response: {
    clientDataJSON: Base64URLString;
    attestationObject: Base64URLString;
    authenticatorData?: Base64URLString;
    transports?: string[];
    publicKey?: Base64URLString;
    publicKeyAlgorithm?: number;
  };
  clientExtensionResults: Record<string, unknown>;
}

/** Matches Src/Fido2.Models/Objects/AuthenticatorAssertionRawResponse.cs. */
export interface AuthenticationResponseJSON {
  id: string;
  rawId: Base64URLString;
  type: "public-key";
  authenticatorAttachment?: string;
  response: {
    clientDataJSON: Base64URLString;
    authenticatorData: Base64URLString;
    signature: Base64URLString;
    userHandle?: Base64URLString;
  };
  clientExtensionResults: Record<string, unknown>;
}

/** Matches Src/Fido2.Models/Objects/SignalOptions.cs: UnknownCredentialOptions. */
export interface UnknownCredentialOptionsJSON {
  rpId: string;
  credentialId: Base64URLString;
}

/** Matches Src/Fido2.Models/Objects/SignalOptions.cs: AllAcceptedCredentialsOptions. */
export interface AllAcceptedCredentialsOptionsJSON {
  rpId: string;
  userId: Base64URLString;
  allAcceptedCredentialIds: Base64URLString[];
}

/** Matches Src/Fido2.Models/Objects/SignalOptions.cs: CurrentUserDetailsOptions. */
export interface CurrentUserDetailsOptionsJSON {
  rpId: string;
  userId: Base64URLString;
  name: string;
  displayName: string;
}

/** WebAuthn Level 3 §5.1.7: the browser's answer to `PublicKeyCredential.getClientCapabilities()`. */
export type ClientCapabilities = Record<string, boolean>;
