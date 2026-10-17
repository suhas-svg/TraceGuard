// RFC 8785 JSON Canonicalization Scheme (JCS). Policy bundles, tool pins and
// audit-adjacent hashes must be computed over exactly one byte sequence, or two
// implementations will disagree about the same document.
//
// Implemented over the subset JSON accepts: values outside JSON (undefined,
// functions, symbols, BigInt, NaN, Infinity) are rejected rather than coerced,
// because a silent coercion changes the signed bytes.

function canonicalString(value: string): string {
  // Reject lone surrogates: they cannot be represented in valid Unicode, and
  // JSON.stringify would invent an escape that no other implementation agrees
  // on.
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError("lone surrogate in string");
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new TypeError("lone surrogate in string");
    }
  }
  return JSON.stringify(value);
}

function canonicalNumber(value: number): string {
  if (!Number.isFinite(value)) throw new TypeError("non-finite number");
  // JCS serializes -0 as "0" (ECMAScript Number::toString).
  if (Object.is(value, -0)) return "0";
  // JSON.stringify uses ECMAScript Number::toString, which is what JCS
  // specifies (including exponents such as 1e+21).
  return JSON.stringify(value);
}

export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      return canonicalNumber(value);
    case "string":
      return canonicalString(value);
    case "object":
      break;
    default:
      throw new TypeError(`cannot canonicalize ${typeof value}`);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  // JCS sorts object keys by UTF-16 code units; the default sort comparator
  // does exactly that. Duplicate keys cannot exist on a JS object.
  const keys = Object.keys(record).sort();
  const parts = keys.map((key) => {
    const item = record[key];
    if (item === undefined) throw new TypeError(`undefined value at key ${key}`);
    return `${canonicalString(key)}:${canonicalize(item)}`;
  });
  return `{${parts.join(",")}}`;
}

// Convenience for hashing/signing: canonical bytes, UTF-8.
export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}
