import { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from "node:crypto";

// Sealed box for pending approval arguments: AES-256-GCM with the call's
// request hash as associated data, so a sealed blob cannot be transplanted
// onto a different call. Key comes from APPROVAL_ARGS_KEY (32 bytes, hex).
const KEY_BYTES = 32;

export function parseKey(hex: string): Buffer {
  const key = Buffer.from((hex ?? "").trim(), "hex");
  if (key.length !== KEY_BYTES) {
    throw new Error("APPROVAL_ARGS_KEY must be 32 bytes as hex (generate: node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\")");
  }
  return key;
}

export function seal(key: Buffer, obj: Record<string, unknown>, aad: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const data = Buffer.concat([cipher.update(JSON.stringify(obj), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ["v1", iv.toString("hex"), tag.toString("hex"), data.toString("hex")].join(":");
}

export function open(key: Buffer, sealed: string, aad: string): Record<string, unknown> {
  const parts = sealed.split(":");
  if (parts.length !== 4 || parts[0] !== "v1") throw new Error("unknown sealed format");
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(parts[1], "hex"));
  decipher.setAAD(Buffer.from(aad, "utf8"));
  decipher.setAuthTag(Buffer.from(parts[2], "hex"));
  const data = Buffer.concat([decipher.update(Buffer.from(parts[3], "hex")), decipher.final()]);
  const parsed: unknown = JSON.parse(data.toString("utf8"));
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("sealed payload is not an object");
  }
  return parsed as Record<string, unknown>;
}

// Constant-shape comparison helper for callers that check hashes first.
export function hashesEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}
