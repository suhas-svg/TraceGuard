import { createHash } from "node:crypto";

// OTLP/HTTP JSON receiver for OpenTelemetry GenAI spans. Supports the JSON
// encoding only (exporters: OTEL_EXPORTER_OTLP_PROTOCOL=http/json). Binary
// protobuf arrives in a later change, not silently misread.
// Pinned subset of the GenAI conventions: gen_ai.system, gen_ai.request.model,
// gen_ai.response.model, gen_ai.usage.input_tokens, gen_ai.usage.output_tokens,
// gen_ai.tool.name, plus exception events. Unknown attributes ride along in
// the span attributes column untouched.

export interface OtlpKeyValue {
  key: string;
  value?: { stringValue?: string; intValue?: string; boolValue?: boolean };
}

export interface OtlpSpan {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  name: string;
  kind?: number;
  startTimeUnixNano?: string;
  endTimeUnixNano?: string;
  attributes?: OtlpKeyValue[];
  status?: { code?: number };
  events?: { name?: string; attributes?: OtlpKeyValue[] }[];
}

export interface MappedSpan {
  runId: string;
  spanId: string;
  parentSpanId: string | null;
  eventId: string;
  operationType: string;
  name: string;
  startedAt: string;
  durationMs: number | null;
  status: string;
  provider: string | null;
  model: string | null;
  inputTokens: number | null;
  outputTokens: number | null;
  usageSource: string;
  errorType: string | null;
  agentName: string;
  workspaceName: string;
  attributes: Record<string, unknown>;
}

// UUID v5 (SHA-1 namespace + name). OTel ids are 32-hex trace and 16-hex
// span ids; mapping them deterministically means re-sent traces upsert the
// same rows instead of duplicating them.
export function uuidV5(namespace: string, name: string): string {
  const ns = Buffer.from(namespace.replace(/-/g, ""), "hex");
  const hash = createHash("sha1").update(ns).update(name, "utf8").digest();
  hash[6] = (hash[6] & 0x0f) | 0x50;
  hash[8] = (hash[8] & 0x3f) | 0x80;
  const hex = hash.subarray(0, 16).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export const TRACE_NAMESPACE = "6ba7b811-9dad-11d1-80b4-00c04fd430c8";

export function attrValue(v: OtlpKeyValue["value"]): unknown {
  if (!v) return null;
  if (v.stringValue !== undefined) return v.stringValue;
  if (v.intValue !== undefined) return Number(v.intValue);
  if (v.boolValue !== undefined) return v.boolValue;
  return null;
}

export function attrsToObject(list?: OtlpKeyValue[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const kv of list ?? []) out[kv.key] = attrValue(kv.value);
  return out;
}

function nanoToIso(nano?: string): string {
  const n = BigInt(nano ?? "0");
  return new Date(Number(n / 1_000_000n)).toISOString();
}

export function mapOtlpSpan(
  span: OtlpSpan,
  resource: Record<string, unknown>
): MappedSpan | null {
  if (!span.traceId || !span.spanId) return null;
  const attrs = attrsToObject(span.attributes);
  const get = (k: string): unknown => attrs[k] ?? resource[k];

  const toolName = get("gen_ai.tool.name");
  const system = get("gen_ai.system");
  const operationType =
    typeof toolName === "string" && toolName ? "tool.invocation"
    : span.name === "gen_ai.execute_tool" ? "tool.invocation"
    : "model.request";

  let errorType: string | null = null;
  for (const e of span.events ?? []) {
    if (e.name === "exception") {
      const ea = attrsToObject(e.attributes);
      errorType = (ea["exception.type"] as string) ?? "error";
    }
  }
  const failed = span.status?.code === 2 || errorType !== null;

  const start = nanoToIso(span.startTimeUnixNano);
  const endMs = span.endTimeUnixNano ? Number(BigInt(span.endTimeUnixNano) / 1_000_000n) : null;
  const startMs = span.startTimeUnixNano ? Number(BigInt(span.startTimeUnixNano) / 1_000_000n) : null;
  const inTok = get("gen_ai.usage.input_tokens");
  const outTok = get("gen_ai.usage.output_tokens");
  const inputTokens = typeof inTok === "number" ? inTok : null;
  const outputTokens = typeof outTok === "number" ? outTok : null;

  return {
    runId: uuidV5(TRACE_NAMESPACE, span.traceId),
    spanId: uuidV5(TRACE_NAMESPACE, span.spanId),
    parentSpanId: span.parentSpanId ? uuidV5(TRACE_NAMESPACE, span.parentSpanId) : null,
    eventId: uuidV5(TRACE_NAMESPACE, `${span.traceId}:${span.spanId}`),
    operationType,
    name: typeof toolName === "string" && toolName ? toolName : span.name,
    startedAt: start,
    durationMs: endMs !== null && startMs !== null ? Math.max(0, endMs - startMs) : null,
    status: failed ? "failed" : "success",
    provider: typeof system === "string" ? system : null,
    model:
      (get("gen_ai.response.model") as string | undefined) ??
      (get("gen_ai.request.model") as string | undefined) ??
      null,
    inputTokens,
    outputTokens,
    usageSource: inputTokens === null && outputTokens === null ? "unavailable" : "provider_reported",
    errorType,
    agentName: (resource["service.name"] as string | undefined) ?? "otel-agent",
    workspaceName: (resource["traceguard.workspace"] as string | undefined) ?? "default",
    attributes: attrs
  };
}
