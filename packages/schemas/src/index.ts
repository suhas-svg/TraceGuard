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
  usage_source: z.enum(["provider_reported", "estimated", "unavailable"]).nullable().optional(),
  error_type: z.string().max(128).nullable().optional(),
  attributes: z.record(z.unknown()).default({})
});

export type EventEnvelope = z.infer<typeof eventEnvelopeSchema>;

export const ingestBodySchema = z.object({
  events: eventEnvelopeSchema.array().min(1).max(500)
});
