import { beforeEach, describe, expect, it, vi } from "vitest";
import { BudgetExceeded, BudgetGuard, nowIso, TraceGuardClient } from "../src/index.js";

// A sender test with a live server proves nothing about failure handling, so
// fetch is stubbed and every rejection path gets asserted.
describe("typescript sdk", () => {
  const posted: { url: string; body: Record<string, unknown> }[] = [];

  beforeEach(() => {
    posted.length = 0;
    vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
      posted.push({ url, body: JSON.parse(String(init.body)) });
      return { status: 200, json: async () => ({}) };
    }));
  });

  it("stamps Zulu timestamps the API accepts", () => {
    expect(nowIso()).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  });

  it("emits a complete run and flushes before exit", async () => {
    const client = new TraceGuardClient("http://x:8090", "k", "ts-agent", "ws");
    const runId = client.startRun();
    client.modelEvent(runId, { provider: "demo", model: "demo-1", inputTokens: 10, outputTokens: 5 });
    client.endRun(runId, true);
    await client.flush();
    expect(posted).toHaveLength(3);
    const events = posted.flatMap((p) => (p.body.events ?? []) as Record<string, unknown>[]);
    expect(events.map((e) => e.event_type).sort()).toEqual(["model.request", "run.completed", "run.started"]);
    expect(events.every((e) => e.run_id === runId)).toBe(true);
  });

  it("never throws telemetry into the agent", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw new Error("down");
    }));
    const client = new TraceGuardClient("http://x:8090", "k");
    expect(() => client.emit({ a: 1 })).not.toThrow();
    await expect(client.flush(50)).resolves.toBeUndefined();
  });

  it("raises BudgetExceeded instead of calling past the limit", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({
      status: 409,
      json: async () => ({ error: "budget_exceeded" })
    })));
    const guard = new BudgetGuard("http://x:8090", "k", "b1");
    await expect(guard.reserve(100)).rejects.toBeInstanceOf(BudgetExceeded);
  });

  it("reserves and settles through the budget endpoints", async () => {
    const calls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      calls.push(url);
      if (url.endsWith("/check")) return { status: 200, json: async () => ({ reservation_id: "r1" }) };
      return { status: 200, json: async () => ({ ok: true }) };
    }));
    const guard = new BudgetGuard("http://x:8090", "k", "b1");
    expect(await guard.reserve(100)).toBe("r1");
    await guard.settle("r1", 80);
    expect(calls).toEqual([
      "http://x:8090/v1/budgets/check",
      "http://x:8090/v1/budgets/settle"
    ]);
  });
});
