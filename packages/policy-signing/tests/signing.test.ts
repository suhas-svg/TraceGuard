import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  generateSigningKey,
  keyIdFor,
  signPayload,
  verifyPayload
} from "../src/index.js";

describe("Ed25519 policy signing", () => {
  it("round-trips a canonical payload", () => {
    const keys = generateSigningKey();
    const payload = { version: 3, rules: [{ id: "allow-1", effect: "allow" }], note: "é" };
    const signed = signPayload(payload, keys.privateKeyPem);
    expect(signed.keyId).toBe(keys.keyId);
    expect(verifyPayload(payload, signed.signature, keys.publicKeyPem)).toBe(true);
  });

  it("verifies independently of object insertion order", () => {
    const keys = generateSigningKey();
    const signed = signPayload({ b: 2, a: 1 }, keys.privateKeyPem);
    expect(verifyPayload({ a: 1, b: 2 }, signed.signature, keys.publicKeyPem)).toBe(true);
  });

  it("rejects a tampered payload", () => {
    const keys = generateSigningKey();
    const signed = signPayload({ effect: "allow" }, keys.privateKeyPem);
    expect(verifyPayload({ effect: "deny" }, signed.signature, keys.publicKeyPem)).toBe(false);
  });

  it("rejects a signature from a different key", () => {
    const signer = generateSigningKey();
    const other = generateSigningKey();
    const signed = signPayload({ a: 1 }, signer.privateKeyPem);
    expect(verifyPayload({ a: 1 }, signed.signature, other.publicKeyPem)).toBe(false);
  });

  it("derives a stable key id from the public key", () => {
    const keys = generateSigningKey();
    expect(keyIdFor(keys.publicKeyPem)).toBe(keys.keyId);
    expect(keyIdFor(`  ${keys.publicKeyPem}\n`)).toBe(keys.keyId);
  });

  it("refuses non-Ed25519 keys", () => {
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const privatePem = rsa.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const publicPem = rsa.publicKey.export({ type: "spki", format: "pem" }).toString();
    expect(() => signPayload({ a: 1 }, privatePem)).toThrow(/Ed25519/);
    expect(verifyPayload({ a: 1 }, "AAAA", publicPem)).toBe(false);
  });

  it("returns false for malformed signatures instead of throwing", () => {
    const keys = generateSigningKey();
    expect(verifyPayload({ a: 1 }, "not-base64", keys.publicKeyPem)).toBe(false);
    expect(verifyPayload({ a: 1 }, "", keys.publicKeyPem)).toBe(false);
  });
});
