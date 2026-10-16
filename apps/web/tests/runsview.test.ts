import { describe, expect, it } from "vitest";
import { filterRuns, sortRuns } from "../src/runsview";
import type { RunItem } from "../src/api";

const run = (over: Partial<RunItem>): RunItem => ({
  id: "aaaaaaaa-0000-0000-0000-000000000000",
  agent_name: "ts-agent",
  status: "success",
  started_at: "2026-10-15T12:00:00.000Z",
  ended_at: null,
  error_type: null,
  input_tokens: "0",
  output_tokens: "0",
  span_count: "0",
  ...over
});

describe("filterRuns", () => {
  const runs = [
    run({ id: "84ba3a3a-1111-1111-1111-111111111111", agent_name: "ts-agent" }),
    run({ id: "aaaa9999-2222-2222-2222-222222222222", agent_name: "scope-mv9" }),
    run({ id: "bbbb1111-3333-3333-3333-333333333333", agent_name: "ts-agent" })
  ];

  it("passes everything through on an empty query", () => {
    expect(filterRuns(runs, "   ")).toHaveLength(3);
  });

  it("matches a run-id prefix, case-insensitively", () => {
    expect(filterRuns(runs, "84BA3A").map((r) => r.id[0])).toEqual(["8"]);
  });

  it("matches the agent name anywhere in the string", () => {
    expect(filterRuns(runs, "MV9").map((r) => r.agent_name)).toEqual(["scope-mv9"]);
  });

  it("returns an empty list when nothing matches", () => {
    expect(filterRuns(runs, "zzz")).toEqual([]);
  });
});

describe("sortRuns", () => {
  const runs = [
    run({ id: "old-big", started_at: "2026-10-15T10:00:00.000Z", span_count: "9", input_tokens: "10", output_tokens: "5" }),
    run({ id: "new-small", started_at: "2026-10-15T12:00:00.000Z", span_count: "1", input_tokens: "700", output_tokens: "300" }),
    run({ id: "mid", started_at: "2026-10-15T11:00:00.000Z", span_count: "4", input_tokens: "40", output_tokens: "10" })
  ];

  it("sorts by start time, newest first for desc", () => {
    expect(sortRuns(runs, "started", "desc").map((r) => r.id)).toEqual(["new-small", "mid", "old-big"]);
  });

  it("sorts by span count numerically, not lexically", () => {
    expect(sortRuns(runs, "spans", "desc").map((r) => r.span_count)).toEqual(["9", "4", "1"]);
  });

  it("sorts by total tokens across both directions", () => {
    expect(sortRuns(runs, "tokens", "desc").map((r) => r.id)).toEqual(["new-small", "mid", "old-big"]);
    expect(sortRuns(runs, "tokens", "asc").map((r) => r.id)).toEqual(["old-big", "mid", "new-small"]);
  });

  it("does not mutate the input list", () => {
    const before = runs.map((r) => r.id);
    sortRuns(runs, "spans", "asc");
    expect(runs.map((r) => r.id)).toEqual(before);
  });
});
