/**
 * Unpadded base64url encode/decode, used only as a fallback for browsers that predate
 * `PublicKeyCredential.parseCreationOptionsFromJSON()`/`parseRequestOptionsFromJSON()`/`toJSON()`
 * (WebAuthn Level 3 §5.1.8/§5.1.9). Modern browsers do this conversion natively; see `supportsJsonMethods()`
 * in `browser.ts`.
 */

export function base64UrlToBuffer(value: string): ArrayBuffer {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  const binary = atob(padded + padding);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}

export function bufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
