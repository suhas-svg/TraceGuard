import { describe, expect, it } from "vitest";
import { buildTree, tokenTotal } from "../src/tree";
import type { Span } from "../src/api";

const span = (over: Partial<Span>): Span => ({
  id: "s", run_id: "r", parent_span_id: null, event_id: "e",
  operation_type: "model.request", started_at: "2026-10-13T12:00:00.000Z",
  ended_at: null, duration_ms: null, status: "success", provider: null,
  model: null, input_tokens: null, output_tokens: null, usage_source: null,
  error_type: null, attributes: {}, ...over
});

// A tree builder that drops orphans would hide crashes, so orphans must surface.
describe("span tree", () => {
  it("nests children under parents in time order", () => {
    const spans = [
      span({ id: "root", started_at: "2026-10-13T12:00:00.000Z" }),
      span({ id: "late", parent_span_id: "root", started_at: "2026-10-13T12:00:02.000Z" }),
      span({ id: "early", parent_span_id: "root", started_at: "2026-10-13T12:00:01.000Z" })
    ];
    const roots = buildTree(spans);
    expect(roots).toHaveLength(1);
    expect(roots[0].children.map((c) => c.span.id)).toEqual(["early", "late"]);
  });

  it("keeps orphaned spans at the root instead of dropping them", () => {
    const spans = [span({ id: "orphan", parent_span_id: "missing" })];
    const roots = buildTree(spans);
    expect(roots.map((r) => r.span.id)).toEqual(["orphan"]);
  });

  it("treats missing usage as zero in totals, never NaN", () => {
    expect(tokenTotal([span({}), span({ input_tokens: 5, output_tokens: 7 })])).toEqual({
      input: 5, output: 7
    });
  });
});
