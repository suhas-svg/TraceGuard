import { describe, expect, it } from "vitest";
import { computeWarnings, thresholdsFromEnv, type WarningSpan } from "../src/diagnostics.js";

const T = { maxCalls: 3, maxDurationMs: 60_000, maxTokens: 1000, repeatedFailures: 3 };

const run = (
  over: Partial<{ status: string; started_at: string; ended_at: string | null }> = {}
) => ({
  status: "running",
  started_at: new Date(Date.now() - 1000).toISOString(),
  ended_at: null as string | null,
  ...over
});

const tool = (over: Partial<WarningSpan> = {}): WarningSpan => ({
  operation_type: "tool.invocation",
  name: "echo",
  status: "success",
  started_at: new Date().toISOString(),
  ended_at: new Date().toISOString(),
  attributes: {},
  ...over
});

// Diagnostics are advisory, so the cost of a false positive is mostly noise.
// Each heuristic therefore gets a positive case and a near-miss case.
describe("loop and usage diagnostics", () => {
  it("stays quiet for a healthy short run", () => {
    expect(computeWarnings(run(), [tool(), tool()], T)).toEqual([]);
  });

  it("warns when tool calls exceed the threshold, not at it", () => {
    const at = Array.from({ length: 3 }, () => tool());
    expect(computeWarnings(run(), at, T).map((w) => w.code)).not.toContain("high_call_count");
    const over = Array.from({ length: 4 }, () => tool());
    expect(computeWarnings(run(), over, T).map((w) => w.code)).toContain("high_call_count");
  });

  it("warns when the same tool fails repeatedly, not for distinct tools", () => {
    const same = Array.from({ length: 3 }, () =>
      tool({ status: "failed", attributes: { server_id: "s1", tool: "flaky" } })
    );
    const hit = computeWarnings(run(), same, T).find((w) => w.code === "repeated_tool_failures");
    expect(hit?.details.tool).toBe("flaky");
    expect(hit?.details.failures).toBe(3);
    const distinct = [
      tool({ status: "failed", attributes: { server_id: "s1", tool: "a" } }),
      tool({ status: "failed", attributes: { server_id: "s1", tool: "b" } }),
      tool({ status: "failed", attributes: { server_id: "s2", tool: "a" } })
    ];
    expect(computeWarnings(run(), distinct, T).map((w) => w.code)).not.toContain(
      "repeated_tool_failures"
    );
  });

  it("counts denials as failures: hammering a refused tool is a loop too", () => {
    const denied = Array.from({ length: 3 }, () =>
      tool({ status: "denied", attributes: { tool: "wipe_disk" } })
    );
    expect(computeWarnings(run(), denied, T).map((w) => w.code)).toContain(
      "repeated_tool_failures"
    );
  });

  it("warns on long runs using ended_at, or now while still running", () => {
    const finishedShort = run({
      status: "success",
      started_at: new Date(Date.now() - 10_000).toISOString(),
      ended_at: new Date().toISOString()
    });
    expect(computeWarnings(finishedShort, [], T).map((w) => w.code)).not.toContain(
      "long_running_run"
    );
    const finishedLong = run({
      status: "success",
      started_at: new Date(Date.now() - 120_000).toISOString(),
      ended_at: new Date().toISOString()
    });
    expect(computeWarnings(finishedLong, [], T).map((w) => w.code)).toContain("long_running_run");
    const stillRunning = run({ started_at: new Date(Date.now() - 120_000).toISOString() });
    const hit = computeWarnings(stillRunning, [], T).find((w) => w.code === "long_running_run");
    expect(hit?.details.still_running).toBe(true);
  });

  it("warns when tokens reach the threshold and notes unknown usage", () => {
    const spans = [
      tool({ input_tokens: 600, output_tokens: 0 }),
      tool({ input_tokens: 400, output_tokens: 5 }),
      tool({ input_tokens: null, output_tokens: null })
    ];
    const hit = computeWarnings(run(), spans, T).find((w) => w.code === "high_token_usage");
    expect(hit?.details.input_output_tokens).toBe(1005);
    expect(hit?.details.spans_without_usage).toBe(1);
    const below = [tool({ input_tokens: 999, output_tokens: 0 })];
    expect(computeWarnings(run(), below, T).map((w) => w.code)).not.toContain("high_token_usage");
  });

  it("reads thresholds from the environment with spec-shaped defaults", () => {
    expect(thresholdsFromEnv({})).toEqual({
      maxCalls: 50,
      maxDurationMs: 30 * 60 * 1000,
      maxTokens: 1_000_000,
      repeatedFailures: 3
    });
    expect(thresholdsFromEnv({ DIAG_MAX_CALLS: "5", DIAG_REPEATED_FAILURES: "2" })).toMatchObject({
      maxCalls: 5,
      repeatedFailures: 2
    });
    // Junk values fall back rather than disabling the check or throwing.
    expect(thresholdsFromEnv({ DIAG_MAX_CALLS: "nope", DIAG_MAX_TOKENS: "-5" })).toMatchObject({
      maxCalls: 50,
      maxTokens: 1_000_000
    });
  });
});
