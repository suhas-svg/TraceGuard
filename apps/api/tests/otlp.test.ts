import { describe, expect, it } from "vitest";
import { mapOtlpSpan, uuidV5, TRACE_NAMESPACE } from "../src/otlp.js";

const resource = { "service.name": "shop-bot", "traceguard.workspace": "shop" };
const base = {
  traceId: "a".repeat(32),
  spanId: "b".repeat(16),
  name: "gen_ai.chat",
  startTimeUnixNano: "1760371200000000000",
  endTimeUnixNano: "1760371200842000000",
  attributes: [
    { key: "gen_ai.system", value: { stringValue: "openai" } },
    { key: "gen_ai.request.model", value: { stringValue: "gpt-x" } },
    { key: "gen_ai.usage.input_tokens", value: { intValue: "100" } },
    { key: "gen_ai.usage.output_tokens", value: { intValue: "20" } }
  ]
};

// A mapper that guesses would still pass a single happy path, so identity,
// error, and tool routing each get a case that guessing fails.
describe("otlp mapping", () => {
  it("maps genai model spans with usage and duration", () => {
    const m = mapOtlpSpan(base, resource)!;
    expect(m.operationType).toBe("model.request");
    expect(m.provider).toBe("openai");
    expect(m.model).toBe("gpt-x");
    expect(m.inputTokens).toBe(100);
    expect(m.outputTokens).toBe(20);
    expect(m.durationMs).toBe(842);
    expect(m.status).toBe("success");
    expect(m.agentName).toBe("shop-bot");
    expect(m.workspaceName).toBe("shop");
  });

  it("derives stable ids so retries upsert", () => {
    const a = mapOtlpSpan(base, resource)!;
    const b = mapOtlpSpan(base, resource)!;
    expect(a.runId).toBe(b.runId);
    expect(a.spanId).toBe(b.spanId);
    expect(a.eventId).toBe(b.eventId);
    expect(uuidV5(TRACE_NAMESPACE, "x")).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
    );
  });

  it("routes tool spans and error statuses", () => {
    const tool = mapOtlpSpan(
      { ...base, name: "gen_ai.execute_tool",
        attributes: [{ key: "gen_ai.tool.name", value: { stringValue: "read_file" } }] },
      resource
    )!;
    expect(tool.operationType).toBe("tool.invocation");
    expect(tool.name).toBe("read_file");
    const failed = mapOtlpSpan(
      { ...base, status: { code: 2 },
        events: [{ name: "exception",
          attributes: [{ key: "exception.type", value: { stringValue: "ToolTimeout" } }] }] },
      resource
    )!;
    expect(failed.status).toBe("failed");
    expect(failed.errorType).toBe("ToolTimeout");
  });

  it("maps cached input tokens when the provider reports them", () => {
    const m = mapOtlpSpan(
      { ...base, attributes: [
        ...base.attributes,
        { key: "gen_ai.usage.cache_read_input_tokens", value: { intValue: "40" } }
      ] },
      resource
    )!;
    expect(m.cachedTokens).toBe(40);
    const plain = mapOtlpSpan(base, resource)!;
    expect(plain.cachedTokens).toBeNull();
  });

  it("drops spans without ids and marks missing usage unavailable", () => {
    expect(mapOtlpSpan({ ...base, traceId: "" }, resource)).toBeNull();
    const m = mapOtlpSpan({ ...base, attributes: [] }, {})!;
    expect(m.usageSource).toBe("unavailable");
    expect(m.agentName).toBe("otel-agent");
  });
});
