import { createHash } from "node:crypto";
import { posix } from "node:path";
import { canonicalize } from "@traceguard/canonical-json";
import { validateAgainstSchema } from "./schema-check.js";

export type Effect = "allow" | "deny" | "require_approval";
export type Decision = "allow" | "deny" | "need_approval";

export interface PolicyRule {
  id: string;
  version: number;
  name: string;
  enabled: boolean;
  priority: number;
  agent_id: string | null;
  server_id: string | null;
  tool_name: string | null;
  effect: Effect;
  conditions: ArgConditions;
}

export interface CallCtx {
  caller: string;
  agent_id?: string | null;
  server_id: string;
  tool_name: string;
  args: Record<string, unknown>;
}

export interface ArgConditions {
  required?: string[];
  arguments?: Record<string, FieldConstraint>;
}

export interface FieldConstraint {
  path_within?: string;
  schema?: Record<string, unknown>;
  regex?: string;
  enum?: unknown[];
  max_length?: number;
}

export interface EvalResult {
  decision: Decision;
  rule: PolicyRule | null;
  matched: { id: string; version: number; name: string; effect: Effect }[];
  reason: string;
}

// Stable stringify: same object always hashes the same way regardless of key order.
export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`);
  return `{${entries.join(",")}}`;
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

// Args hash for decision records, over RFC 8785 canonical bytes.
export function argsHash(args: Record<string, unknown>): string {
  return sha256Hex(canonicalize(args));
}

// Binds an approval to one exact call (§9.1): any change of caller, target,
// args, logical request id, or tool-definition pin produces a different hash
// and the approval will not apply. RFC 8785 canonical JSON, so two
// implementations agree on the bytes.
export function requestHash(
  caller: string,
  serverId: string,
  toolName: string,
  args: Record<string, unknown>,
  requestId: string,
  pinHash: string
): string {
  return sha256Hex(canonicalize([caller, serverId, toolName, args, requestId, pinHash]));
}

// path_within canonicalizes .. and duplicate separators before comparing, so
// "data/../etc" cannot pass a "/data" prefix rule through string matching.
// shortcut: symlinks are not resolved here; run the gateway where the tool
// host resolves paths, or add realpath checks before production use.
export function pathWithin(value: string, allowedDir: string): boolean {
  if (typeof value !== "string" || value.length === 0) return false;
  const clean = (p: string) => (p.startsWith("/") ? posix.normalize(p) : posix.normalize("/" + p));
  const v = clean(value);
  const base = clean(allowedDir);
  return v === base || v.startsWith(base.endsWith("/") ? base : base + "/");
}

// T8: a rule pattern is bounded on both sides. The schema refuses invalid,
// oversized, backreference and nested-quantifier patterns where a rule is
// stored or a bundle is loaded; this caps the subject so a match cannot run
// away on a huge argument, and an unusable pattern denies instead of throwing.
// shortcut: the caps bound the cost, they do not prove linear time for every
// pattern inside them; a real timeout needs worker threads. Upgrade if policy
// authors are not trusted.
export const MAX_REGEX_SUBJECT = 4096;

export function regexMatches(pattern: string, value: string): boolean {
  try {
    return new RegExp(pattern).test(value.slice(0, MAX_REGEX_SUBJECT));
  } catch {
    return false;
  }
}

export function checkField(value: unknown, rule: FieldConstraint): boolean {
  if (rule.max_length !== undefined) {
    if (typeof value !== "string" || value.length > rule.max_length) return false;
  }
  if (rule.enum !== undefined) {
    if (!rule.enum.some((e) => stableStringify(e) === stableStringify(value))) return false;
  }
  if (rule.regex !== undefined) {
    if (typeof value !== "string") return false;
    if (!regexMatches(rule.regex, value)) return false;
  }
  if (rule.path_within !== undefined) {
    if (!pathWithin(String(value ?? ""), rule.path_within)) return false;
  }
  if (rule.schema !== undefined) {
    if (!validateAgainstSchema(rule.schema as Record<string, unknown>, value).ok) return false;
  }
  return true;
}

export function checkConditions(args: Record<string, unknown>, cond: ArgConditions): boolean {
  for (const name of cond.required ?? []) {
    if (args[name] === undefined || args[name] === null) return false;
  }
  for (const [name, rule] of Object.entries(cond.arguments ?? {})) {
    if (args[name] === undefined) continue;
    if (!checkField(args[name], rule)) return false;
  }
  return true;
}

function scopeMatches(rule: PolicyRule, ctx: CallCtx): boolean {
  if (rule.agent_id && rule.agent_id !== ctx.agent_id) return false;
  if (rule.server_id && rule.server_id !== ctx.server_id) return false;
  if (rule.tool_name && rule.tool_name !== ctx.tool_name) return false;
  return checkConditions(ctx.args, rule.conditions ?? {});
}

// Deny-overrides: any matching deny wins. Priority only orders rules that
// share the same effect, and picks which one gets cited in the decision row.
export function evaluate(rules: PolicyRule[], ctx: CallCtx): EvalResult {
  const matched = rules
    .filter((r) => r.enabled && scopeMatches(r, ctx))
    .sort((a, b) => b.priority - a.priority)
    .map((r) => ({ id: r.id, version: r.version, name: r.name, effect: r.effect }));
  const pick = (effect: Effect) => matched.find((m) => m.effect === effect) ?? null;
  const byId = new Map(rules.map((r) => [r.id, r]));

  const denied = pick("deny");
  if (denied) {
    return {
      decision: "deny",
      rule: byId.get(denied.id) ?? null,
      matched,
      reason: `denied by rule "${denied.name}"`
    };
  }
  const approval = pick("require_approval");
  if (approval) {
    return {
      decision: "need_approval",
      rule: byId.get(approval.id) ?? null,
      matched,
      reason: `approval required by rule "${approval.name}"`
    };
  }
  const allowed = pick("allow");
  if (allowed) {
    return {
      decision: "allow",
      rule: byId.get(allowed.id) ?? null,
      matched,
      reason: `allowed by rule "${allowed.name}"`
    };
  }
  return { decision: "deny", rule: null, matched, reason: "no matching allow rule" };
}
