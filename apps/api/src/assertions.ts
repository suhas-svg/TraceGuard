// Deterministic checks only. No model judging in v1: every assertion is a
// pure function of the recorded output, tool sequence, and final status.
export interface AssertCtx {
  output: string;
  tools: string[];
  status: string;
}

export interface AssertOutcome {
  passed: boolean;
  message: string;
}

// Deterministic checks only. No model judging in v1: every assertion is a
// pure function of the recorded output, tool sequence, and final status.
export function runAssertion(a: Record<string, unknown>, ctx: AssertCtx): AssertOutcome {
  switch (a.type) {
    case "exact":
      return a.value === ctx.output
        ? { passed: true, message: "exact match" }
        : { passed: false, message: `expected exactly ${JSON.stringify(a.value)}` };
    case "contains":
      return typeof a.value === "string" && ctx.output.includes(a.value)
        ? { passed: true, message: `contains ${JSON.stringify(a.value)}` }
        : { passed: false, message: `missing ${JSON.stringify(a.value)}` };
    case "regex": {
      let re: RegExp;
      try {
        re = new RegExp(String(a.pattern));
      } catch {
        return { passed: false, message: "invalid regex in assertion" };
      }
      return re.test(ctx.output)
        ? { passed: true, message: `matches ${a.pattern}` }
        : { passed: false, message: `no match for ${a.pattern}` };
    }
    case "json_schema": {
      // Recursive subset: primitive types (incl. "integer"), nested objects,
      // arrays with item schemas, and enums. Property specs may be a type
      // string ("number") or a nested schema object.
      let parsed: unknown;
      try {
        parsed = JSON.parse(ctx.output);
      } catch {
        return { passed: false, message: "output is not JSON" };
      }
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        return { passed: false, message: "output is not a JSON object" };
      }
      const schema = (a.schema ?? {}) as string | SchemaSpec;
      const failure = validate(parsed, schema, "output");
      return failure
        ? { passed: false, message: failure }
        : { passed: true, message: "schema satisfied" };
    }
    case "tools": {
      // Two deterministic forms: an ordered `sequence` (exact full equality)
      // or a `names` multiset (the same tool names in any order).
      if (Array.isArray(a.names)) {
        const want = (a.names as string[]).slice().sort();
        const got = ctx.tools.slice().sort();
        const same = want.length === got.length && want.every((t, i) => t === got[i]);
        return same
          ? { passed: true, message: `tool names [${want.join(", ")}]` }
          : { passed: false, message: `expected names [${want.join(", ")}], got [${got.join(", ")}]` };
      }
      const want = (a.sequence ?? []) as string[];
      const same = want.length === ctx.tools.length && want.every((t, i) => t === ctx.tools[i]);
      return same
        ? { passed: true, message: `tool sequence [${want.join(", ")}]` }
        : { passed: false, message: `expected [${want.join(", ")}], got [${ctx.tools.join(", ")}]` };
    }
    case "status":
      return ctx.status === a.value
        ? { passed: true, message: `status ${a.value}` }
        : { passed: false, message: `expected status ${a.value}, got ${ctx.status}` };
    default:
      return { passed: false, message: `unknown assertion ${(a as { type: unknown }).type}` };
  }
}

interface SchemaSpec {
  type?: string;
  required?: string[];
  properties?: Record<string, string | SchemaSpec>;
  items?: string | SchemaSpec;
  enum?: unknown[];
}

function typeOf(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (typeof v === "number") return Number.isInteger(v) ? "integer" : "number";
  return typeof v;
}

// Returns a message describing the first mismatch, or null when the value
// satisfies the spec.
function validate(v: unknown, spec: string | SchemaSpec, path: string): string | null {
  if (typeof spec === "string") {
    const t = typeOf(v);
    const fits = t === spec || (spec === "number" && t === "integer");
    return fits ? null : `${path} is not ${spec}`;
  }
  if (spec.enum && !spec.enum.some((e) => JSON.stringify(e) === JSON.stringify(v))) {
    return `${path} is not one of the allowed values`;
  }
  if (spec.type) {
    const t = typeOf(v);
    if (t !== spec.type && !(spec.type === "number" && t === "integer")) {
      return `${path} is not ${spec.type}`;
    }
  }
  if (v !== null && typeof v === "object" && !Array.isArray(v)) {
    const obj = v as Record<string, unknown>;
    for (const k of spec.required ?? []) {
      if (obj[k] === undefined) return `missing field ${k}`;
    }
    for (const [k, sub] of Object.entries(spec.properties ?? {})) {
      if (obj[k] === undefined) continue;
      const err = validate(obj[k], sub, k);
      if (err) return err;
    }
  } else if (spec.required || spec.properties) {
    return `${path} is not a JSON object`;
  }
  if (spec.items !== undefined || spec.type === "array") {
    if (!Array.isArray(v)) return `${path} is not an array`;
    for (let i = 0; i < v.length; i++) {
      const err = validate(v[i], spec.items ?? {}, `${path}[${i}]`);
      if (err) return err;
    }
  }
  return null;
}

