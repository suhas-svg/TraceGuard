import { describe, expect, it } from "vitest";
import { canonicalize } from "../src/index.js";

describe("RFC 8785 canonical JSON", () => {
  it("sorts object keys and preserves array order", () => {
    expect(canonicalize({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
    expect(canonicalize({ z: [{ b: 1, a: 2 }, 3] })).toBe('{"z":[{"a":2,"b":1},3]}');
    expect(canonicalize(["b", "a"])).toBe('["b","a"]');
  });

  it("is independent of insertion order", () => {
    expect(canonicalize({ a: 1, b: { d: 4, c: 3 } }))
      .toBe(canonicalize({ b: { c: 3, d: 4 }, a: 1 }));
  });

  it("uses ECMAScript number serialization", () => {
    expect(canonicalize(1e21)).toBe("1e+21");
    expect(canonicalize(1e-7)).toBe("1e-7");
    expect(canonicalize(0.000001)).toBe("0.000001");
    expect(canonicalize(-0)).toBe("0");
    expect(canonicalize(10)).toBe("10");
  });

  it("escapes strings the way JCS requires", () => {
    expect(canonicalize("é")).toBe('"é"');
    expect(canonicalize("€")).toBe('"€"');
    expect(canonicalize("line\nbreak")).toBe('"line\\nbreak"');
    expect(canonicalize('quote"slash\\')).toBe('"quote\\"slash\\\\"');
    expect(canonicalize("\u0008")).toBe('"\\b"');
    expect(canonicalize("\u001f")).toBe('"\\u001f"');
    expect(canonicalize("/")).toBe('"/"'); // no gratuitous escaping
  });

  it("orders keys by UTF-16 code units", () => {
    // "a" (U+0061) sorts before "€" (U+20AC); a codepoint-ordered
    // implementation without surrogates agrees, but the UTF-16 rule matters
    // above the BMP.
    expect(canonicalize({ "€": 2, a: 1 })).toBe('{"a":1,"€":2}');
    expect(canonicalize({ "\uffff": 2, "\u0001": 1 })).toBe('{"\\u0001":1,"\uffff":2}');
  });

  it("rejects values JSON cannot represent", () => {
    expect(() => canonicalize(Number.NaN)).toThrow(TypeError);
    expect(() => canonicalize(Number.POSITIVE_INFINITY)).toThrow(TypeError);
    expect(() => canonicalize(undefined)).toThrow(TypeError);
    expect(() => canonicalize({ a: undefined })).toThrow(TypeError);
    expect(() => canonicalize(10n)).toThrow(TypeError);
    expect(() => canonicalize(() => 1)).toThrow(TypeError);
    expect(() => canonicalize("\ud800")).toThrow(TypeError);
  });

  it("handles nesting depth and empty containers", () => {
    expect(canonicalize({})).toBe("{}");
    expect(canonicalize([])).toBe("[]");
    expect(canonicalize({ a: {}, b: [] })).toBe('{"a":{},"b":[]}');
  });
});
