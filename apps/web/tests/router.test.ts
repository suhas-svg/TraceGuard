import { describe, expect, it } from "vitest";
import { formatRoute, parseRoute, type Route } from "../src/router";

// Hash routes are the app's only deep-link surface: a wrong parse silently
// drops the user on the wrong screen, so every shape gets a case.
describe("hash routes", () => {
  it("defaults to the runs list on an empty hash", () => {
    expect(parseRoute("")).toEqual({ tab: "runs", runId: null });
    expect(parseRoute("#")).toEqual({ tab: "runs", runId: null });
  });

  it("parses every top-level tab", () => {
    for (const tab of ["runs", "evals", "policy", "approvals", "webhooks", "retention", "costs", "users"]) {
      expect(parseRoute(`#/${tab}`)).toEqual({ tab, runId: null });
    }
  });

  it("parses a run deep link", () => {
    expect(parseRoute("#/runs/run_abc123")).toEqual({ tab: "runs", runId: "run_abc123" });
  });

  it("falls back to runs for an unknown tab", () => {
    expect(parseRoute("#/nope")).toEqual({ tab: "runs", runId: null });
  });

  it("formats routes back into hashes", () => {
    expect(formatRoute({ tab: "costs", runId: null })).toBe("#/costs");
    expect(formatRoute({ tab: "runs", runId: "run_1" })).toBe("#/runs/run_1");
  });

  it("round-trips through parse and format", () => {
    const route: Route = { tab: "runs", runId: "run_xyz" };
    expect(parseRoute(formatRoute(route))).toEqual(route);
  });
});
