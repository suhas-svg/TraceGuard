import { describe, expect, it } from "vitest";
import { hashesEqual, open, parseKey, seal, tryOpen } from "../src/seal.js";

const KEY = parseKey("ab".repeat(32));
const ARGS = { target: "/tmp/x", mode: "write" };

// A seal that opens for anyone, or that survives tampering, is decoration.
// Each property below breaks exactly that.
describe("approval seal", () => {
  it("round-trips through seal and open", () => {
    expect(open(KEY, seal(KEY, ARGS, "req-1"), "req-1")).toEqual(ARGS);
  });

  it("refuses the wrong key and the wrong call binding", () => {
    const sealed = seal(KEY, ARGS, "req-1");
    expect(() => open(parseKey("cd".repeat(32)), sealed, "req-1")).toThrow();
    expect(() => open(KEY, sealed, "req-2")).toThrow();
  });

  it("refuses tampered blobs and bad envelopes", () => {
    const sealed = seal(KEY, ARGS, "req-1");
    const tampered = sealed.slice(0, -1) + (sealed.endsWith("0") ? "1" : "0");
    expect(() => open(KEY, tampered, "req-1")).toThrow();
    expect(() => open(KEY, "garbage", "req-1")).toThrow();
  });

  it("opens old rows with the previous key during rotation", () => {
    const oldKey = parseKey("cd".repeat(32));
    const sealed = seal(oldKey, ARGS, "req-9");
    expect(tryOpen([KEY, oldKey], sealed, "req-9")).toEqual(ARGS);
    expect(() => tryOpen([KEY], sealed, "req-9")).toThrow();
    expect(() => tryOpen([], sealed, "req-9")).toThrow();
  });

  it("rejects short keys at startup", () => {
    expect(() => parseKey("")).toThrow();
    expect(() => parseKey("ab".repeat(16))).toThrow();
    expect(hashesEqual("abc", "abc")).toBe(true);
    expect(hashesEqual("abc", "abd")).toBe(false);
  });
});
