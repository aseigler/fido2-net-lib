export { startRegistration } from "./registration.js";
export type { StartRegistrationOptions } from "./registration.js";

export { startAuthentication } from "./authentication.js";
export type { StartAuthenticationOptions } from "./authentication.js";

export { WebAuthnCancellationError, isWebAuthnCancellation } from "./errors.js";

export {
  signalUnknownCredential,
  signalAllAcceptedCredentials,
  signalCurrentUserDetails,
  supportsSignalApi,
} from "./signal.js";

export { getClientCapabilities } from "./capabilities.js";

export {
  browserSupportsWebAuthn,
  browserSupportsWebAuthnAutofill,
  supportsJsonMethods,
} from "./browser.js";

export { base64UrlToBuffer, bufferToBase64Url } from "./base64url.js";

export type {
  Base64URLString,
  CredentialCreationOptionsJSON,
  AssertionOptionsJSON,
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  PublicKeyCredentialRpEntityJSON,
  PublicKeyCredentialUserEntityJSON,
  PublicKeyCredentialParametersJSON,
  PublicKeyCredentialDescriptorJSON,
  AuthenticatorSelectionCriteriaJSON,
  UnknownCredentialOptionsJSON,
  AllAcceptedCredentialsOptionsJSON,
  CurrentUserDetailsOptionsJSON,
  ClientCapabilities,
} from "./types.js";
