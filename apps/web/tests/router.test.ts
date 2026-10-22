import { describe, expect, it } from "vitest";
import { formatRoute, parseRoute, type Route } from "../src/router";

// Hash routes are the app's only deep-link surface: a wrong parse silently
// drops the user on the wrong screen, so every shape gets a case.
describe("hash routes", () => {
  it("defaults to the overview on an empty hash", () => {
    expect(parseRoute("")).toEqual({ tab: "overview", runId: null, approvalId: null });
    expect(parseRoute("#")).toEqual({ tab: "overview", runId: null, approvalId: null });
  });

  it("parses every top-level tab", () => {
    for (const tab of ["overview", "runs", "evals", "policy", "approvals", "webhooks", "retention", "costs", "users"]) {
      expect(parseRoute(`#/${tab}`)).toEqual({ tab, runId: null, approvalId: null });
    }
  });

  it("parses a run deep link", () => {
    expect(parseRoute("#/runs/run_abc123")).toEqual({ tab: "runs", runId: "run_abc123", approvalId: null });
  });

  it("parses an approval deep link", () => {
    expect(parseRoute("#/approvals/appr_abc123")).toEqual({ tab: "approvals", runId: null, approvalId: "appr_abc123" });
  });

  it("falls back to the overview for an unknown tab", () => {
    expect(parseRoute("#/nope")).toEqual({ tab: "overview", runId: null, approvalId: null });
  });

  it("formats routes back into hashes", () => {
    expect(formatRoute({ tab: "costs", runId: null, approvalId: null })).toBe("#/costs");
    expect(formatRoute({ tab: "runs", runId: "run_1", approvalId: null })).toBe("#/runs/run_1");
    expect(formatRoute({ tab: "approvals", runId: null, approvalId: "appr_1" })).toBe("#/approvals/appr_1");
  });

  it("round-trips through parse and format", () => {
    const route: Route = { tab: "runs", runId: "run_xyz", approvalId: null };
    expect(parseRoute(formatRoute(route))).toEqual(route);
  });
});
