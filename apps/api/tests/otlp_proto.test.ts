import { describe, expect, it } from "vitest";
import { decodeTraceRequest, encodeTraceRequest } from "../src/otlp_proto.js";
import { mapOtlpSpan, attrsToObject, type OtlpSpan } from "../src/otlp.js";

function sampleJson() {
  return {
    resourceSpans: [{
      resource: { attributes: [
        { key: "service.name", value: { stringValue: "proto-bot" } },
        { key: "gen_ai.system", value: { stringValue: "openai" } }
      ]},
      scopeSpans: [{ spans: [{
        traceId: Buffer.from("ab".repeat(16), "hex"),
        spanId: Buffer.from("cd".repeat(8), "hex"),
        name: "gen_ai.chat",
        kind: 3,
        startTimeUnixNano: "1760371200000000000",
        endTimeUnixNano: "1760371200842000000",
        attributes: [
          { key: "gen_ai.request.model", value: { stringValue: "gpt-x" } },
          { key: "gen_ai.usage.input_tokens", value: { intValue: "100" } },
          { key: "gen_ai.usage.output_tokens", value: { intValue: "20" } }
        ],
        status: { code: 1 }
      }]}]
    }]
  };
}

// A decoder that guesses would pass a JSON-shaped test. These cases force
// real protobuf handling: binary framing, byte ids, and 64-bit timestamps.
describe("otlp protobuf", () => {
  it("round-trips binary through the real codec", () => {
    const bytes = encodeTraceRequest(sampleJson());
    expect(bytes.length).toBeGreaterThan(50);
    const decoded = decodeTraceRequest(bytes);
    expect(decoded.resourceSpans).toHaveLength(1);
    const span = decoded.resourceSpans[0].scopeSpans![0].spans![0] as unknown as OtlpSpan;
    expect(span.traceId).toBe("ab".repeat(16));
    expect(span.spanId).toBe("cd".repeat(8));
    expect(span.startTimeUnixNano).toBe("1760371200000000000");
    const attrs = attrsToObject(span.attributes);
    expect(attrs["gen_ai.usage.input_tokens"]).toBe(100);
  });

  it("maps decoded spans exactly like JSON ones", () => {
    const decoded = decodeTraceRequest(encodeTraceRequest(sampleJson()));
    const rs = decoded.resourceSpans[0];
    const resource = attrsToObject(
      (rs.resource?.attributes ?? []) as Parameters<typeof attrsToObject>[0]
    );
    const m = mapOtlpSpan(rs.scopeSpans![0].spans![0] as unknown as OtlpSpan, resource)!;
    expect(m.operationType).toBe("model.request");
    expect(m.provider).toBe("openai");
    expect(m.model).toBe("gpt-x");
    expect(m.inputTokens).toBe(100);
    expect(m.durationMs).toBe(842);
  });

  it("rejects non-protobuf bytes", () => {
    // Valid protobuf framing but wrong message: decodes to empty, not a crash.
    expect(decodeTraceRequest(Buffer.from([0x08, 0x01])).resourceSpans).toEqual([]);
    expect(() => decodeTraceRequest(Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff]))).toThrow();
  });
});
