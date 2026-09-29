/**
 * Node defines `navigator` as its own non-writable-but-configurable global getter (unrelated to the browser
 * `Navigator` these tests fake), so a plain `globalThis.navigator = ...` throws, and simply deleting it leaves
 * later code that reads the bare `navigator` identifier throwing `ReferenceError`. Redefine it for the
 * duration of a test, then restore Node's original descriptor.
 */
const originalNavigatorDescriptor = Object.getOwnPropertyDescriptor(globalThis, "navigator");

export function setGlobalNavigator(value: unknown): void {
  Object.defineProperty(globalThis, "navigator", { value, configurable: true, writable: true });
}

export function resetTestGlobals(): void {
  delete (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential;

  if (originalNavigatorDescriptor) {
    Object.defineProperty(globalThis, "navigator", originalNavigatorDescriptor);
  } else {
    Reflect.deleteProperty(globalThis, "navigator");
  }
}
