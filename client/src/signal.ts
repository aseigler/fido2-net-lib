import { extendedPublicKeyCredential } from "./browser.js";
import type {
  AllAcceptedCredentialsOptionsJSON,
  CurrentUserDetailsOptionsJSON,
  UnknownCredentialOptionsJSON,
} from "./types.js";

/**
 * WebAuthn Level 3 §5.1.10 signal methods: the server produces the options payload (see
 * `Src/Fido2.Models/Objects/SignalOptions.cs`), and these wrappers hand it to the browser. They are
 * best-effort and report nothing back -- a resolved promise means only that the browser accepted the call,
 * not that any authenticator acted on it. Each throws if the browser doesn't support the given method; check
 * with `supportsSignalApi()` first if you need to degrade gracefully.
 */

export function supportsSignalApi(): boolean {
  const pkc = extendedPublicKeyCredential();
  return (
    typeof pkc.signalUnknownCredential === "function" &&
    typeof pkc.signalAllAcceptedCredentials === "function" &&
    typeof pkc.signalCurrentUserDetails === "function"
  );
}

/** Tells the platform a credential ID it offered is not one this Relying Party recognizes. */
export async function signalUnknownCredential(options: UnknownCredentialOptionsJSON): Promise<void> {
  const signal = extendedPublicKeyCredential().signalUnknownCredential;
  if (!signal) {
    throw new Error("This browser does not support PublicKeyCredential.signalUnknownCredential().");
  }
  await signal(options);
}

/**
 * Gives the platform the complete set of credential IDs this Relying Party still accepts for a user.
 *
 * The list must be exhaustive: the platform may delete anything missing from it, so only call this when the
 * Relying Party can enumerate every credential registered to the user.
 */
export async function signalAllAcceptedCredentials(options: AllAcceptedCredentialsOptionsJSON): Promise<void> {
  const signal = extendedPublicKeyCredential().signalAllAcceptedCredentials;
  if (!signal) {
    throw new Error("This browser does not support PublicKeyCredential.signalAllAcceptedCredentials().");
  }
  await signal(options);
}

/** Refreshes the name and display name the platform shows for a user's credentials. */
export async function signalCurrentUserDetails(options: CurrentUserDetailsOptionsJSON): Promise<void> {
  const signal = extendedPublicKeyCredential().signalCurrentUserDetails;
  if (!signal) {
    throw new Error("This browser does not support PublicKeyCredential.signalCurrentUserDetails().");
  }
  await signal(options);
}
