import { z } from "zod";

// Single parse boundary. API and SDK validate here, interior trusts the type.
export const eventEnvelopeSchema = z.object({
  schema_version: z.literal("1"),
  event_id: z.string().min(1).max(128),
  workspace_id: z.string().uuid().optional(),
  workspace_name: z.string().min(1).max(128).optional(),
  agent_id: z.string().uuid().optional(),
  agent_name: z.string().min(1).max(128).optional(),
  run_id: z.string().uuid(),
  span_id: z.string().uuid(),
  parent_span_id: z.string().uuid().nullable().optional(),
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
  attributes: z.record(z.unknown()).default({})
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

export const BUNDLE_VERSION = 1;
export const PROTOCOL_PROFILE = "mcp-2026-07-28";

// The fixed operator set of §8.4, nothing else: no expressions, no code.
const fieldConstraintSchema = z.object({
  path_within: z.string().min(1).max(4096).optional(),
  regex: z.string().min(1).max(512).optional(),
  enum: z.array(z.unknown()).max(256).optional(),
  max_length: z.number().int().min(0).max(1_000_000).optional()
}).strict();

const argConditionsSchema = z.object({
  required: z.array(z.string().min(1).max(128)).max(128).default([]),
  arguments: z.record(fieldConstraintSchema).optional()
}).strict();

export const bundleRuleSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1).max(128),
  enabled: z.boolean(),
  priority: z.number().int().min(-1_000_000).max(1_000_000),
  agent_id: z.string().uuid().nullable(),
  server_id: z.string().uuid().nullable(),
  tool_name: z.string().min(1).max(128).nullable(),
  effect: z.enum(["allow", "deny", "require_approval"]),
  conditions: argConditionsSchema.default({})
}).strict();

export const bundleServerSchema = z.object({
  server_id: z.string().uuid(),
  alias: z.string().min(1).max(64).regex(/^[a-z0-9_]+$/),
  base_url: z.string().url(),
  // Secret values never enter the bundle; only how the gateway authenticates.
  auth_mode: z.enum(["gateway_secret", "none"])
}).strict();

export const bundlePinSchema = z.object({
  server_id: z.string().uuid(),
  tool_name: z.string().min(1).max(128),
  definition_hash: z.string().regex(/^[0-9a-f]{64}$/)
}).strict();

export const policyBundleSchema = z.object({
  bundle_version: z.literal(BUNDLE_VERSION),
  protocol_profile: z.literal(PROTOCOL_PROFILE),
  workspace_id: z.string().uuid(),
  version: z.number().int().positive(),
  previous_version_hash: z.string().regex(/^[0-9a-f]{64}$/).nullable(),
  rules: z.array(bundleRuleSchema).max(500),
  servers: z.array(bundleServerSchema).max(100),
  pins: z.array(bundlePinSchema).max(5000)
}).strict();

export type PolicyBundle = z.infer<typeof policyBundleSchema>;
export type BundleRule = z.infer<typeof bundleRuleSchema>;
export type BundleServer = z.infer<typeof bundleServerSchema>;
export type BundlePin = z.infer<typeof bundlePinSchema>;
