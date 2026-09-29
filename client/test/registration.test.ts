import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";

import { startRegistration } from "../dist/registration.js";
import type { CredentialCreationOptionsJSON, RegistrationResponseJSON } from "../dist/types.js";
import { resetTestGlobals, setGlobalNavigator } from "./helpers.ts";

const optionsJSON: CredentialCreationOptionsJSON = {
  rp: { id: "example.com", name: "Example" },
  user: { id: "dXNlci1pZA", name: "alice", displayName: "Alice" },
  challenge: "Y2hhbGxlbmdl",
  pubKeyCredParams: [{ type: "public-key", alg: -7 }],
};

afterEach(resetTestGlobals);

describe("startRegistration, native JSON methods available", () => {
  it("passes exactly what parseCreationOptionsFromJSON returned as request.publicKey", async () => {
    // This is the regression test for the bug where the call site did
    // `{ publicKey: parseCreationOptionsFromJSON(json).publicKey }` -- parseCreationOptionsFromJSON returns
    // PublicKeyCredentialCreationOptions itself (WebAuthn L3 5.1.8), not something with its own .publicKey, so
    // that produced `{ publicKey: undefined }` and every registration failed. If this assertion ever sees
    // `undefined` again, that bug is back.
    const parsedOptions = { rp: optionsJSON.rp, sentinel: "parsed" };
    let capturedRequest: CredentialCreationOptions | undefined;

    const fakeCredential = {
      id: "abc",
      rawId: new Uint8Array([1, 2, 3]).buffer,
      response: {},
      getClientExtensionResults: () => ({}),
      toJSON: (): RegistrationResponseJSON => ({
        id: "abc",
        rawId: "AQID",
        type: "public-key",
        response: { clientDataJSON: "", attestationObject: "" },
        clientExtensionResults: {},
      }),
    };

    (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential = {
      parseCreationOptionsFromJSON: () => parsedOptions,
      parseRequestOptionsFromJSON: () => ({}),
    };
    setGlobalNavigator({
      credentials: {
        create: async (request: CredentialCreationOptions) => {
          capturedRequest = request;
          return fakeCredential;
        },
      },
    });

    const result = await startRegistration(optionsJSON);

    assert.equal(capturedRequest?.publicKey, parsedOptions);
    assert.equal(result.id, "abc");
  });

  it("forwards mediation and signal onto the request", async () => {
    let capturedRequest: (CredentialCreationOptions & { mediation?: string; signal?: AbortSignal }) | undefined;

    (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential = {
      parseCreationOptionsFromJSON: () => ({}),
      parseRequestOptionsFromJSON: () => ({}),
    };
    const controller = new AbortController();
    setGlobalNavigator({
      credentials: {
        create: async (request: typeof capturedRequest) => {
          capturedRequest = request;
          return {
            getClientExtensionResults: () => ({}),
            toJSON: () => ({ id: "x", rawId: "", type: "public-key", response: {}, clientExtensionResults: {} }),
          };
        },
      },
    });

    await startRegistration(optionsJSON, { mediation: "conditional", signal: controller.signal });

    assert.equal(capturedRequest?.mediation, "conditional");
    assert.equal(capturedRequest?.signal, controller.signal);
  });

  it("maps a cancellation-shaped DOMException to WebAuthnCancellationError", async () => {
    (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential = {
      parseCreationOptionsFromJSON: () => ({}),
      parseRequestOptionsFromJSON: () => ({}),
    };
    setGlobalNavigator({
      credentials: {
        create: async () => {
          throw new DOMException("The operation either timed out or was not allowed.", "NotAllowedError");
        },
      },
    });

    await assert.rejects(() => startRegistration(optionsJSON), { name: "WebAuthnCancellationError" });
  });
});

describe("startRegistration, no native JSON methods (fallback path)", () => {
  it("base64url-decodes the challenge and user id before calling create()", async () => {
    let capturedRequest: CredentialCreationOptions | undefined;

    setGlobalNavigator({
      credentials: {
        create: async (request: CredentialCreationOptions) => {
          capturedRequest = request;
          return {
            id: "abc",
            rawId: new Uint8Array([1]).buffer,
            response: {
              clientDataJSON: new Uint8Array([2]).buffer,
              attestationObject: new Uint8Array([3]).buffer,
              getTransports: () => [],
            },
            getClientExtensionResults: () => ({}),
          };
        },
      },
    });
    // No PublicKeyCredential.parseCreationOptionsFromJSON -> supportsJsonMethods() is false.

    await startRegistration(optionsJSON);

    const publicKey = capturedRequest?.publicKey;
    assert.ok(publicKey?.challenge instanceof ArrayBuffer);
    assert.ok(publicKey?.user.id instanceof ArrayBuffer);
  });
});
