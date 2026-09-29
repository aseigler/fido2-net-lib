import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";

import { startAuthentication } from "../dist/authentication.js";
import type { AssertionOptionsJSON, AuthenticationResponseJSON } from "../dist/types.js";
import { resetTestGlobals, setGlobalNavigator } from "./helpers.ts";

const optionsJSON: AssertionOptionsJSON = {
  challenge: "Y2hhbGxlbmdl",
  rpId: "example.com",
};

afterEach(resetTestGlobals);

describe("startAuthentication, native JSON methods available", () => {
  it("passes exactly what parseRequestOptionsFromJSON returned as request.publicKey", async () => {
    // Regression test for the mirror of the registration bug: the call site used to do
    // `{ publicKey: parseRequestOptionsFromJSON(json).publicKey }`, which is `undefined` because
    // parseRequestOptionsFromJSON returns PublicKeyCredentialRequestOptions itself.
    const parsedOptions = { sentinel: "parsed" };
    let capturedRequest: CredentialRequestOptions | undefined;

    (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential = {
      parseCreationOptionsFromJSON: () => ({}),
      parseRequestOptionsFromJSON: () => parsedOptions,
    };
    setGlobalNavigator({
      credentials: {
        // browserSupportsWebAuthn() checks for .create as a general feature-support signal, the same as a
        // real browser always exposing both -- mock both even though only .get is exercised here.
        create: async () => { throw new Error("not used in this test"); },
        get: async (request: CredentialRequestOptions) => {
          capturedRequest = request;
          return {
            id: "abc",
            rawId: new Uint8Array([1]).buffer,
            getClientExtensionResults: () => ({}),
            toJSON: (): AuthenticationResponseJSON => ({
              id: "abc",
              rawId: "AQ",
              type: "public-key",
              response: { clientDataJSON: "", authenticatorData: "", signature: "" },
              clientExtensionResults: {},
            }),
          };
        },
      },
    });

    const result = await startAuthentication(optionsJSON);

    assert.equal(capturedRequest?.publicKey, parsedOptions);
    assert.equal(result.id, "abc");
  });

  it("maps a cancellation-shaped DOMException to WebAuthnCancellationError", async () => {
    (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential = {
      parseCreationOptionsFromJSON: () => ({}),
      parseRequestOptionsFromJSON: () => ({}),
    };
    setGlobalNavigator({
      credentials: {
        get: async () => {
          throw new DOMException("The user aborted the request.", "AbortError");
        },
      },
    });

    await assert.rejects(() => startAuthentication(optionsJSON), { name: "WebAuthnCancellationError" });
  });
});

describe("startAuthentication, no native JSON methods (fallback path)", () => {
  it("base64url-decodes the challenge before calling get()", async () => {
    let capturedRequest: CredentialRequestOptions | undefined;

    setGlobalNavigator({
      credentials: {
        get: async (request: CredentialRequestOptions) => {
          capturedRequest = request;
          return {
            id: "abc",
            rawId: new Uint8Array([1]).buffer,
            response: {
              clientDataJSON: new Uint8Array([2]).buffer,
              authenticatorData: new Uint8Array([3]).buffer,
              signature: new Uint8Array([4]).buffer,
              userHandle: null,
            },
            getClientExtensionResults: () => ({}),
          };
        },
      },
    });

    await startAuthentication(optionsJSON);

    assert.ok(capturedRequest?.publicKey?.challenge instanceof ArrayBuffer);
  });
});
