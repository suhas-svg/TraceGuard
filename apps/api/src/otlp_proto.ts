import protobuf from "protobufjs";

// Minimal subset of opentelemetry-proto trace service, enough to decode what
// exporters send and nothing more. Field numbers match the official schema;
// unknown fields are skipped by the decoder, so newer exporters still parse.
const TRACE_PROTO = `
syntax = "proto3";
package opentelemetry.proto.trace.v1;

message ExportTraceServiceRequest {
  repeated ResourceSpans resource_spans = 1;
}
message ResourceSpans {
  opentelemetry.proto.resource.v1.Resource resource = 1;
  repeated ScopeSpans scope_spans = 2;
  string schema_url = 3;
}
message ScopeSpans {
  opentelemetry.proto.common.v1.InstrumentationScope scope = 1;
  repeated Span spans = 2;
  string schema_url = 3;
}
message Span {
  bytes trace_id = 1;
  bytes span_id = 2;
  string trace_state = 3;
  bytes parent_span_id = 4;
  string name = 5;
  enum SpanKind {
    SPAN_KIND_UNSPECIFIED = 0;
    INTERNAL = 1;
    SERVER = 2;
    CLIENT = 3;
    PRODUCER = 4;
    CONSUMER = 5;
  }
  SpanKind kind = 6;
  fixed64 start_time_unix_nano = 7;
  fixed64 end_time_unix_nano = 8;
  repeated opentelemetry.proto.common.v1.KeyValue attributes = 9;
  message Event {
    fixed64 time_unix_nano = 1;
    string name = 2;
    repeated opentelemetry.proto.common.v1.KeyValue attributes = 3;
  }
  repeated Event events = 11;
  Status status = 15;
}
message Status {
  string message = 2;
  enum StatusCode {
    STATUS_CODE_UNSET = 0;
    STATUS_CODE_OK = 1;
    STATUS_CODE_ERROR = 2;
  }
  StatusCode code = 3;
}
`;
const COMMON_PROTO = `
syntax = "proto3";
package opentelemetry.proto.common.v1;

message AnyValue {
  oneof value {
    string string_value = 1;
    bool bool_value = 2;
    int64 int_value = 3;
    double double_value = 4;
    ArrayValue array_value = 5;
    KeyValueList kvlist_value = 6;
    bytes bytes_value = 7;
  }
}
message ArrayValue {
  repeated AnyValue values = 1;
}
message KeyValueList {
  repeated KeyValue values = 1;
}
message KeyValue {
  string key = 1;
  AnyValue value = 2;
}
message InstrumentationScope {
  string name = 1;
  string version = 2;
}
`;
const RESOURCE_PROTO = `
syntax = "proto3";
package opentelemetry.proto.resource.v1;

message Resource {
  repeated opentelemetry.proto.common.v1.KeyValue attributes = 1;
}
`;

let requestType: protobuf.Type | null = null;

function getRequestType(): protobuf.Type {
  if (!requestType) {
    const root = new protobuf.Root();
    for (const text of [COMMON_PROTO, RESOURCE_PROTO, TRACE_PROTO]) {
      protobuf.parse(text, root);
    }
    root.resolveAll();
    requestType = root.lookupType("opentelemetry.proto.trace.v1.ExportTraceServiceRequest");
  }
  return requestType;
}

export interface JsonShape {
  resourceSpans: {
    resource?: { attributes?: { key: string; value?: Record<string, unknown> }[] };
    scopeSpans?: { spans?: Record<string, unknown>[] }[];
  }[];
}

function hex(b: unknown): string | undefined {
  if (!b) return undefined;
  if (Buffer.isBuffer(b)) return b.toString("hex");
  if (b instanceof Uint8Array) return Buffer.from(b).toString("hex");
  return undefined;
}

// Normalizes decoded protobuf into the same JSON shape the /v1/traces route
// already validates and stores, so both encodings share one code path.
export function decodeTraceRequest(bytes: Buffer): JsonShape {
  const msg = getRequestType().decode(bytes);
  const obj = getRequestType().toObject(msg, { bytes: Buffer, longs: String, enums: Number, defaults: false });
  const out: JsonShape = { resourceSpans: [] };
  for (const rs of (obj.resourceSpans ?? []) as Record<string, unknown>[]) {
    const resource = rs.resource as { attributes?: { key: string; value?: Record<string, unknown> }[] } | undefined;
    const scopeSpans = ((rs.scopeSpans ?? []) as Record<string, unknown>[]).map((ss) => ({
      spans: ((ss.spans ?? []) as Record<string, unknown>[]).map((s) => normalizeSpan(s))
    }));
    out.resourceSpans.push({
      resource: resource ? { attributes: (resource.attributes ?? []).map(normalizeAttr) } : undefined,
      scopeSpans
    });
  }
  return out;
}

function normalizeAttr(kv: { key: string; value?: Record<string, unknown> }): {
  key: string; value?: Record<string, unknown>;
} {
  return { key: kv.key, value: normalizeAnyValue(kv.value) };
}

function normalizeAnyValue(v: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!v || typeof v !== "object") return undefined;
  if (typeof v.stringValue === "string") return { stringValue: v.stringValue };
  if (typeof v.boolValue === "boolean") return { boolValue: v.boolValue };
  if (v.intValue !== undefined) return { intValue: String(v.intValue) };
  if (typeof v.doubleValue === "number") return { stringValue: String(v.doubleValue) };
  const bytes = hex((v as { bytesValue?: unknown }).bytesValue);
  if (bytes !== undefined) return { stringValue: bytes };
  return undefined;
}

function normalizeSpan(s: Record<string, unknown>): Record<string, unknown> {
  const events = ((s.events ?? []) as Record<string, unknown>[]).map((e) => ({
    name: e.name,
    attributes: ((e.attributes ?? []) as { key: string; value?: Record<string, unknown> }[]).map(normalizeAttr)
  }));
  const st = s.status as { code?: number } | undefined;
  return {
    traceId: hex(s.traceId),
    spanId: hex(s.spanId),
    parentSpanId: hex(s.parentSpanId),
    name: s.name,
    kind: s.kind,
    startTimeUnixNano: s.startTimeUnixNano !== undefined ? String(s.startTimeUnixNano) : undefined,
    endTimeUnixNano: s.endTimeUnixNano !== undefined ? String(s.endTimeUnixNano) : undefined,
    attributes: ((s.attributes ?? []) as { key: string; value?: Record<string, unknown> }[]).map(normalizeAttr),
    status: st ? { code: st.code } : undefined,
    events
  };
}

export function encodeEmptyTraceResponse(): Buffer {
  return Buffer.from([0x0a, 0x00]);
}

// Test and tooling helper: builds binary bytes from a plain object using the
// same schema the decoder reads. Not part of the serving path.
export function encodeTraceRequest(obj: Record<string, unknown>): Buffer {
  try {
    return Buffer.from(getRequestType().encode(getRequestType().fromObject(obj)).finish());
  } catch (err) {
    throw new Error(`invalid trace object: ${err instanceof Error ? err.message : err}`);
  }
}
