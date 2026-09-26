/** Thrown when the user dismisses the browser's prompt, as opposed to anything actually going wrong. */
export class WebAuthnCancellationError extends Error {
  constructor(cause: unknown) {
    super("The user cancelled the WebAuthn ceremony.");
    this.name = "WebAuthnCancellationError";
    this.cause = cause;
  }
}

export function isWebAuthnCancellation(error: unknown): boolean {
  return error instanceof DOMException && (error.name === "NotAllowedError" || error.name === "AbortError");
}
