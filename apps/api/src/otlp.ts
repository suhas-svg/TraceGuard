import { createHash } from "node:crypto";
import { captureRawEnabled, redactDeep } from "./redact.js";

// OTLP trace mapping. Both wire encodings (binary protobuf and http/json)
// normalize into this shape, so the store path is identical for either kind
// of exporter.
// Pinned subset of the GenAI conventions: gen_ai.system, gen_ai.request.model,
// gen_ai.response.model, gen_ai.usage.input_tokens, gen_ai.usage.output_tokens,
// gen_ai.tool.name, plus exception events. Unknown attributes ride along in
// the span attributes column after secret redaction and the capture policy.

export interface OtlpKeyValue {
  key: string;
  value?: { stringValue?: string; intValue?: string; doubleValue?: number; boolValue?: boolean };
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
  clockSkew: boolean;
  status: string;
  provider: string | null;
  model: string | null;
  inputTokens: number | null;
  outputTokens: number | null;
  cachedTokens: number | null;
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
  // A provider that reports usage as a double must not lose it: silently
  // dropping it records usage_source 'unavailable' and the span is never costed.
  if (v.doubleValue !== undefined) return Number(v.doubleValue);
  if (v.boolValue !== undefined) return v.boolValue;
  return null;
}

export function attrsToObject(list?: OtlpKeyValue[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const kv of list ?? []) out[kv.key] = attrValue(kv.value);
  return out;
}

// Nanosecond stamps arrive as strings. Anything absent, unparseable, or
// negative yields null rather than a substituted value: defaulting to zero
// records the span at the epoch, which then feeds duration, cost windows, and
// retention age downstream.
export function nanoToMs(nano?: string): number | null {
  if (nano === undefined || nano === null || nano === "") return null;
  let ms: bigint;
  try {
    ms = BigInt(nano) / 1_000_000n;
  } catch {
    return null;
  }
  const asNumber = Number(ms);
  return Number.isFinite(asNumber) && asNumber >= 0 ? asNumber : null;
}

function nanoToIso(nano?: string): string | null {
  const ms = nanoToMs(nano);
  return ms === null ? null : new Date(ms).toISOString();
}

// Ingestion limits (§11.1). Read per request so tests and operators can
// retune without a restart; each value falls back to its documented default.
export interface OtlpLimits {
  maxBodyBytes: number;
  maxSpans: number;
  maxAttributes: number;
  maxAttrString: number;
  skewThresholdMs: number;
  lateWindowMs: number;
  rateSpansPerMinute: number;
}

export function otlpLimits(env: NodeJS.ProcessEnv = process.env): OtlpLimits {
  const num = (raw: string | undefined, fallback: number): number => {
    const n = Number(raw);
    return Number.isFinite(n) && n > 0 ? n : fallback;
  };
  return {
    maxBodyBytes: num(env.OTLP_MAX_BODY_BYTES, 1_048_576),
    maxSpans: num(env.OTLP_MAX_SPANS, 2000),
    maxAttributes: num(env.OTLP_MAX_ATTRIBUTES, 64),
    maxAttrString: num(env.OTLP_MAX_ATTR_STRING, 4096),
    skewThresholdMs: num(env.OTLP_SKEW_THRESHOLD_MS, 5 * 60_000),
    lateWindowMs: num(env.OTLP_LATE_WINDOW_MS, 24 * 60 * 60_000),
    rateSpansPerMinute: num(env.OTLP_RATE_SPANS_PER_MINUTE, 60_000)
  };
}

// In-process fixed-window limiter keyed per authenticated caller. One gateway
// process is the boundary here; a multi-process deploy would move the counter
// to shared storage.
const rateWindows = new Map<string, { startMs: number; spans: number }>();

export function otlpRateLimited(
  key: string,
  spans: number,
  perMinute: number,
  nowMs = Date.now()
): boolean {
  const w = rateWindows.get(key);
  if (!w || nowMs - w.startMs >= 60_000) {
    rateWindows.set(key, { startMs: nowMs, spans });
    return spans > perMinute;
  }
  w.spans += spans;
  return w.spans > perMinute;
}

export function resetOtlpRateWindows(): void {
  rateWindows.clear();
}

export interface MapOptions {
  receivedAtMs?: number;
  maxAttributes?: number;
  maxAttrString?: number;
  skewThresholdMs?: number;
}

export function mapOtlpSpan(
  span: OtlpSpan,
  resource: Record<string, unknown>,
  options: MapOptions = {}
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
  // No usable start time means this is not a trace record worth storing: it
  // would land at the epoch and poison every later window. Without this the
  // row reaches runs.started_at as NULL and the whole batch 500s.
  if (start === null) return null;

  const endMs = nanoToMs(span.endTimeUnixNano);
  const startMs = nanoToMs(span.startTimeUnixNano);
  // Clock discipline: a start after the receive time (beyond the threshold)
  // or an end before the start means the producer's clock disagrees with
  // ours. The duration never goes negative; the flag records the mismatch.
  const receivedAtMs = options.receivedAtMs ?? Date.now();
  const skewThresholdMs = options.skewThresholdMs ?? 5 * 60_000;
  let durationMs: number | null = null;
  let clockSkew = false;
  if (endMs !== null && startMs !== null) {
    const raw = endMs - startMs;
    durationMs = raw < 0 ? 0 : raw;
    if (raw < 0) clockSkew = true;
  }
  if (startMs !== null && startMs > receivedAtMs + skewThresholdMs) clockSkew = true;

  const inTok = get("gen_ai.usage.input_tokens");
  const outTok = get("gen_ai.usage.output_tokens");
  const cacheTok = get("gen_ai.usage.cache_read_input_tokens") ?? get("gen_ai.usage.cached_input_tokens");
  const inputTokens = typeof inTok === "number" ? inTok : null;
  const outputTokens = typeof outTok === "number" ? outTok : null;
  const cachedTokens = typeof cacheTok === "number" ? cacheTok : null;

  // Bounded records: exporters can attach unbounded attribute lists, so the
  // stored span keeps a fixed number of keys and truncates string values.
  // Redaction runs first, so a truncated remainder can never hold a secret
  // whose pattern straddled the cut.
  const redacted = redactDeep(attrs, { captureRaw: captureRawEnabled() }) as Record<string, unknown>;
  const maxAttributes = options.maxAttributes ?? 64;
  const maxAttrString = options.maxAttrString ?? 4096;
  const attributes: Record<string, unknown> = {};
  let kept = 0;
  for (const [key, value] of Object.entries(redacted)) {
    if (kept >= maxAttributes) break;
    attributes[key] = typeof value === "string" && value.length > maxAttrString
      ? value.slice(0, maxAttrString)
      : value;
    kept++;
  }

  return {
    runId: uuidV5(TRACE_NAMESPACE, span.traceId),
    spanId: uuidV5(TRACE_NAMESPACE, span.spanId),
    parentSpanId: span.parentSpanId ? uuidV5(TRACE_NAMESPACE, span.parentSpanId) : null,
    eventId: uuidV5(TRACE_NAMESPACE, `${span.traceId}:${span.spanId}`),
    operationType,
    name: typeof toolName === "string" && toolName ? toolName : span.name,
    startedAt: start,
    durationMs,
    clockSkew,
    status: failed ? "failed" : "success",
    provider: typeof system === "string" ? system : null,
    model:
      (get("gen_ai.response.model") as string | undefined) ??
      (get("gen_ai.request.model") as string | undefined) ??
      null,
    inputTokens,
    outputTokens,
    cachedTokens,
    usageSource: inputTokens === null && outputTokens === null ? "unavailable" : "provider_reported",
    errorType,
    agentName: (resource["service.name"] as string | undefined) ?? "otel-agent",
    workspaceName: (resource["traceguard.workspace"] as string | undefined) ?? "default",
    attributes
  };
}
