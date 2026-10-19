// FR-010 / §8.4: JSON Schema (2020-12 dialect) validation for pinned tool
// arguments and for `schema` argument constraints. The schemas come from
// signed policy bundles and pinned tool definitions, so they are trusted for
// integrity but still bounded here: a catastrophic pattern or an oversized
// document must not become a natural DoS at decision time.
import { Ajv2020, type ValidateFunction } from "ajv/dist/2020.js";
import { canonicalize } from "@traceguard/canonical-json";
import { unsafeRegexPattern } from "@traceguard/schemas";

const MAX_SCHEMA_BYTES = 65_536;
const MAX_SCHEMA_DEPTH = 40;
const MAX_SCHEMA_NODES = 4096;
const SCHEMA_CACHE_MAX = 500;

const REF_KEYS = new Set(["$ref", "$dynamicRef", "$recursiveRef"]);

// strict:false — published schemas carry vendor annotations (icons, execution
// hints) that ajv would otherwise reject; validateFormats:false — format
// annotations (email, uri…) are advisory in 2020-12 and must not deny a call.
const ajv = new Ajv2020({ strict: false, validateFormats: false, allErrors: false });

const compiled = new Map<string, ValidateFunction>();

function schemaSafetyIssue(schema: unknown): string | null {
  let json: string;
  try {
    json = JSON.stringify(schema);
  } catch {
    return "schema is not serializable";
  }
  if (json.length > MAX_SCHEMA_BYTES) return "schema exceeds the byte bound";
  let nodes = 0;
  const walk = (node: unknown, depth: number): string | null => {
    if (depth > MAX_SCHEMA_DEPTH) return "schema exceeds the depth bound";
    if (++nodes > MAX_SCHEMA_NODES) return "schema exceeds the node bound";
    if (Array.isArray(node)) {
      for (const item of node) {
        const issue = walk(item, depth + 1);
        if (issue) return issue;
      }
      return null;
    }
    if (node && typeof node === "object") {
      for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
        if (REF_KEYS.has(key)) return `external ${key} values are not allowed`;
        if (key === "pattern" && typeof value === "string" && unsafeRegexPattern(value)) {
          return "pattern uses a shape that can backtrack catastrophically";
        }
        const issue = walk(value, depth + 1);
        if (issue) return issue;
      }
    }
    return null;
  };
  return walk(schema, 0);
}

function compile(schema: Record<string, unknown>): ValidateFunction | null {
  // Published definitions travel with their drafted `$schema` dialect tag
  // (the tools SDK emits draft-07). Ajv2020 compiles the 2020-12 dialect and
  // refuses documents that announce another meta-schema, so the tag is
  // dropped for compilation only — the accepted keywords are shared by both
  // dialects, and the guards above already bound what can enter here.
  const candidate = typeof schema.$schema === "string" ? { ...schema } : schema;
  if (candidate !== schema) delete candidate.$schema;
  const key = canonicalize(candidate);
  const cached = compiled.get(key);
  if (cached) return cached;
  let validate: ValidateFunction;
  try {
    validate = ajv.compile(candidate);
  } catch {
    return null;
  }
  if (compiled.size >= SCHEMA_CACHE_MAX) {
    const oldest = compiled.keys().next().value;
    if (oldest !== undefined) compiled.delete(oldest);
  }
  compiled.set(key, validate);
  return validate;
}

// Fail closed on anything the checker itself cannot trust (unsafe shape,
// compile failure): an unverifiable schema denies the call rather than
// waving the argument through.
export function validateAgainstSchema(
  schema: Record<string, unknown>,
  value: unknown
): { ok: true } | { ok: false; reason: string } {
  const issue = schemaSafetyIssue(schema);
  if (issue) return { ok: false, reason: issue };
  const validate = compile(schema);
  if (!validate) return { ok: false, reason: "schema failed to compile" };
  if (validate(value)) return { ok: true };
  const first = validate.errors?.[0];
  const detail = first ? `${first.instancePath || "/"} ${first.message ?? "is invalid"}` : "does not match";
  return { ok: false, reason: detail.trim() };
}
