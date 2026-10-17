import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject
} from "node:crypto";
import { canonicalBytes } from "@traceguard/canonical-json";

// Ed25519 signatures over RFC 8785 canonical bytes. The key id is derived from
// the public key, so a bundle cannot claim a key it was not signed with: the
// verifier recomputes it from the pinned public key and compares.
//
// Private keys are PKCS#8 PEM files owned by the operator; they never enter
// PostgreSQL or a service container. Public keys are SPKI PEM.

export interface SigningKeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
  keyId: string;
}

function asPrivateKey(pem: string): KeyObject {
  const key = createPrivateKey(pem);
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error("signing key must be Ed25519");
  }
  return key;
}

function asPublicKey(pem: string): KeyObject {
  const key = createPublicKey(pem);
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error("verification key must be Ed25519");
  }
  return key;
}

export function keyIdFor(publicKeyPem: string): string {
  return createHash("sha256").update(publicKeyPem.trim()).digest("hex");
}

export function generateSigningKey(): SigningKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  return { privateKeyPem, publicKeyPem, keyId: keyIdFor(publicKeyPem) };
}

export interface PayloadSignature {
  signature: string; // base64
  keyId: string;
}

export function signPayload(payload: unknown, privateKeyPem: string): PayloadSignature {
  const privateKey = asPrivateKey(privateKeyPem);
  const signature = sign(null, Buffer.from(canonicalBytes(payload)), privateKey).toString("base64");
  const publicKeyPem = createPublicKey(privateKey).export({ type: "spki", format: "pem" }).toString();
  return { signature, keyId: keyIdFor(publicKeyPem) };
}

export function verifyPayload(
  payload: unknown,
  signatureBase64: string,
  publicKeyPem: string
): boolean {
  try {
    return verify(
      null,
      Buffer.from(canonicalBytes(payload)),
      asPublicKey(publicKeyPem),
      Buffer.from(signatureBase64, "base64")
    );
  } catch {
    // Malformed keys or signatures are a failed verification, never a throw
    // the caller might accidentally treat as success.
    return false;
  }
}
