import { extendedPublicKeyCredential } from "./browser.js";
import type { ClientCapabilities } from "./types.js";

/**
 * WebAuthn Level 3 §5.1.7: asks the browser what it supports, so a page can offer only the ceremonies that
 * will actually work. Returns `null` on browsers that predate the method, rather than throwing, since the
 * whole point of this call is to be safe to make unconditionally.
 */
export async function getClientCapabilities(): Promise<ClientCapabilities | null> {
  const getCapabilities = extendedPublicKeyCredential().getClientCapabilities;

  if (!getCapabilities) {
    return null;
  }

  try {
    return await getCapabilities();
  } catch {
    return null;
  }
}
