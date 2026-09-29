import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";

import { browserSupportsWebAuthn, extendedPublicKeyCredential, supportsJsonMethods } from "../dist/browser.js";
import { resetTestGlobals, setGlobalNavigator } from "./helpers.ts";

afterEach(resetTestGlobals);

describe("browserSupportsWebAuthn", () => {
  it("is false with no PublicKeyCredential global", () => {
    assert.equal(browserSupportsWebAuthn(), false);
  });

  it("is true once PublicKeyCredential and navigator.credentials.create exist", () => {
    (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential = function () {};
    setGlobalNavigator({ credentials: { create: () => {} } });
    assert.equal(browserSupportsWebAuthn(), true);
  });
});

describe("extendedPublicKeyCredential", () => {
  it("throws when the browser has no PublicKeyCredential", () => {
    assert.throws(() => extendedPublicKeyCredential(), /does not support WebAuthn/);
  });

  it("returns the PublicKeyCredential global when present", () => {
    const fake = { parseCreationOptionsFromJSON: () => {} };
    (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential = fake;
    assert.equal(extendedPublicKeyCredential(), fake);
  });
});

describe("supportsJsonMethods", () => {
  it("is false with no PublicKeyCredential global at all", () => {
    assert.equal(supportsJsonMethods(), false);
  });

  it("is false when PublicKeyCredential exists but lacks the L3 JSON methods", () => {
    (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential = function () {};
    assert.equal(supportsJsonMethods(), false);
  });

  it("is true once both parseCreationOptionsFromJSON and parseRequestOptionsFromJSON exist", () => {
    (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential = {
      parseCreationOptionsFromJSON: () => {},
      parseRequestOptionsFromJSON: () => {},
    };
    setGlobalNavigator({ credentials: { create: () => {} } });
    assert.equal(supportsJsonMethods(), true);
  });

  it("is false when only one of the two JSON methods exists", () => {
    (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential = {
      parseCreationOptionsFromJSON: () => {},
    };
    assert.equal(supportsJsonMethods(), false);
  });
});
