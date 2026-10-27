import { z } from "zod";

// Identifier fields use .guid(), not .uuid(). zod 4 tightened .uuid() to the
// RFC 9562 version and variant nibbles; zod 3 accepted any 8-4-4-4-12 hex
// GUID, which is also what the Postgres uuid type stores. Keeping .guid()
// means the upgrade does not reject identifiers that parsed before, including
// legacy signed bundles and agent-supplied telemetry.

// Single parse boundary. API and SDK validate here, interior trusts the type.
export const eventEnvelopeSchema = z.object({
  schema_version: z.literal("1"),
  event_id: z.string().min(1).max(128),
  workspace_id: z.string().guid().optional(),
  workspace_name: z.string().min(1).max(128).optional(),
  project_id: z.string().guid().optional(),
  project_name: z.string().min(1).max(128).optional(),
  agent_id: z.string().guid().optional(),
  agent_name: z.string().min(1).max(128).optional(),
  run_id: z.string().guid(),
  span_id: z.string().guid(),
  parent_span_id: z.string().guid().nullable().optional(),
  event_type: z.enum([
    "run.started",
    "run.completed",
    "run.failed",
    "model.request",
    "tool.invocation",
    "agent.message"
  ]),
  timestamp: z.string().datetime(),
  duration_ms: z.number().int().min(0).nullable().optional(),
  status: z.enum(["success", "failed", "denied", "cancelled"]).default("success"),
  provider: z.string().max(64).nullable().optional(),
  model: z.string().max(128).nullable().optional(),
  input_tokens: z.number().int().min(0).nullable().optional(),
  output_tokens: z.number().int().min(0).nullable().optional(),
  cached_tokens: z.number().int().min(0).nullable().optional(),
  usage_source: z.enum(["provider_reported", "estimated", "unavailable"]).nullable().optional(),
  error_type: z.string().max(128).nullable().optional(),
  attributes: z.record(z.string(), z.unknown()).default({})
});

export type EventEnvelope = z.infer<typeof eventEnvelopeSchema>;

export const ingestBodySchema = z.object({
  events: eventEnvelopeSchema.array().min(1).max(500)
});

// ---- Signed policy bundle (§13.3) --------------------------------------
//
// The bundle is the entire trusted policy: the rule set, the upstream server
// manifest, and the tool-pin manifest, signed by the operator-controlled
// publisher key. Everything the gateway enforces comes from here; anything
// not in the bundle is not executable. Parsed at both edges — the publisher
// before signing, the gateway after verification — and never from partial
// data.

export const BUNDLE_VERSION = 2;
// Version 1 bundles predate immutable pin identities. They remain readable so
// an upgrade does not strand the active signed policy, but new publications
// always use BUNDLE_VERSION. Once a v2 bundle is active, pin_id/pin_version are
// enforced against the gateway's current rows.
export const LEGACY_BUNDLE_VERSION = 1;
export const PROTOCOL_PROFILE = "mcp-2026-07-28";

// The fixed operator set of §8.4, nothing else: no expressions, no code.
// A regex is validated here rather than at match time because this schema runs
// on both paths that matter: the draft API that stores a rule, and the bundle
// loader that enforces one.
// Backreferences, and an unbounded quantifier (+ * {n,}) over a group that
// itself repeats or alternates: the shapes that backtrack catastrophically.
// Bounded repetition over such a group ((a|b){1,3}, (ab+){2}) stays allowed,
// because the bound caps the work.
const UNSAFE_REGEX = /\\[1-9]|\([^()]*[|+*}][^()]*\)(?:\+|\*|\{\d+,\})/;

// Exposed for the runtime schema checker (FR-010): a JSON Schema constraint
// may carry `pattern`, and a catastrophic pattern inside one must be refused
// by the same rule that governs policy regex constraints.
export function unsafeRegexPattern(pattern: string): boolean {
  return UNSAFE_REGEX.test(pattern);
}
const regexSchema = z
  .string()
  .min(1)
  .max(512)
  .refine((p) => {
    try {
      new RegExp(p);
      return true;
    } catch {
      return false;
    }
  }, "pattern is not a valid regular expression")
  .refine(
    (p) => !UNSAFE_REGEX.test(p),
    "backreferences and nested quantifiers are not supported (T8: they are the shapes that backtrack catastrophically)"
  );

export const fieldConstraintSchema = z.object({
  path_within: z.string().min(1).max(4096).optional(),
  // §8.4 / FR-010: a full JSON Schema the argument must satisfy, in addition
  // to the fixed operators above. Checked for safe shapes at bundle load.
  schema: z.record(z.string(), z.unknown()).optional(),
  regex: regexSchema.optional(),
  enum: z.array(z.unknown()).max(256).optional(),
  max_length: z.number().int().min(0).max(1_000_000).optional()
}).strict();

// Shared with the control API so a draft is refused at creation rather than
// only when a bundle carrying it is loaded (fail-closed, but late is worse).
export const argConditionsSchema = z.object({
  required: z.array(z.string().min(1).max(128)).max(128).default([]),
  arguments: z.record(z.string(), fieldConstraintSchema).optional()
}).strict();

// FR-010 / §16.3 T9: a path constraint is only accepted when the executor
// itself attests that it confines paths to a root. The gateway's string
// comparison is a fast pre-check, never the enforcement boundary. The
// attestation travels inside the tool's pinned definition so it is covered
// by the signed bundle's pin hash and cannot be changed after publication.
export const PATH_CONFINEMENT_META_KEY = "io.traceguard/path-confinement";

export const pathConfinementMetaSchema = z.object({
  root: z.string().min(1).max(4096),
  enforcement: z.literal("executor")
}).strict();

type ConditionsShape = { arguments?: Record<string, { path_within?: unknown } | undefined> } | null | undefined;

export function hasPathWithin(conditions: ConditionsShape): boolean {
  return Object.values(conditions?.arguments ?? {}).some(
    (constraint) => constraint?.path_within !== undefined
  );
}

export const bundleRuleSchema = z.object({
  id: z.string().guid(),
  name: z.string().min(1).max(128),
  enabled: z.boolean(),
  priority: z.number().int().min(-1_000_000).max(1_000_000),
  agent_id: z.string().guid().nullable(),
  server_id: z.string().guid().nullable(),
  tool_name: z.string().min(1).max(128).nullable(),
  effect: z.enum(["allow", "deny", "require_approval"]),
  // prefault, not default: zod 4 types default() against the output type, and
  // prefault still parses the empty input so `required` keeps its [] default.
  conditions: argConditionsSchema.prefault({})
}).strict().superRefine((rule, ctx) => {
  if (hasPathWithin(rule.conditions) && (!rule.server_id || !rule.tool_name)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["conditions"],
      message: "path_within requires a server- and tool-scoped rule so the executor attestation can be checked"
    });
  }
});

export const bundleServerSchema = z.object({
  server_id: z.string().guid(),
  alias: z.string().min(1).max(64).regex(/^[a-z0-9_]+$/),
  base_url: z.string().url(),
  // Only the reference is signed; the credential value never enters the
  // bundle or the database. Required on every server in a v2 bundle.
  secret_ref: z.string().max(512).nullable().optional(),
  // Secret values never enter the bundle; only how the gateway authenticates.
  auth_mode: z.enum(["gateway_secret", "none"])
}).strict();

export const bundlePinSchema = z.object({
  server_id: z.string().guid(),
  tool_name: z.string().min(1).max(128),
  // Absent only in legacy v1 bundles. New bundles always carry both.
  pin_id: z.string().guid().optional(),
  pin_version: z.number().int().positive().optional(),
  definition_hash: z.string().regex(/^[0-9a-f]{64}$/)
}).strict().superRefine((pin, ctx) => {
  if ((pin.pin_id === undefined) !== (pin.pin_version === undefined)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "pin_id and pin_version must be present together"
    });
  }
});

export const policyBundleSchema = z.object({
  bundle_version: z.union([z.literal(LEGACY_BUNDLE_VERSION), z.literal(BUNDLE_VERSION)]),
  protocol_profile: z.literal(PROTOCOL_PROFILE),
  workspace_id: z.string().guid(),
  // Legacy bundles predate project-scoped publication. New bundles always
  // carry it; the gateway only accepts a legacy bundle for the default project.
  project_id: z.string().guid().optional(),
  version: z.number().int().positive(),
  previous_version_hash: z.string().regex(/^[0-9a-f]{64}$/).nullable(),
  rules: z.array(bundleRuleSchema).max(500),
  servers: z.array(bundleServerSchema).max(100),
  pins: z.array(bundlePinSchema).max(5000)
}).strict().superRefine((bundle, ctx) => {
  if (bundle.bundle_version < BUNDLE_VERSION) return;
  bundle.pins.forEach((pin, index) => {
    if (pin.pin_id === undefined || pin.pin_version === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["pins", index],
        message: "v2 bundles require pin_id and pin_version"
      });
    }
  });
  bundle.servers.forEach((server, index) => {
    if (!("secret_ref" in server)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["servers", index],
        message: "v2 bundles require secret_ref on every server (null when credential-less)"
      });
    }
  });
});

export type PolicyBundle = z.infer<typeof policyBundleSchema>;
export type BundleRule = z.infer<typeof bundleRuleSchema>;
export type BundleServer = z.infer<typeof bundleServerSchema>;
export type BundlePin = z.infer<typeof bundlePinSchema>;
