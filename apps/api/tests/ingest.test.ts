import { describe, expect, it } from "vitest";
import { ingestBodySchema } from "@traceguard/schemas";

// Behavior checks for the parse boundary. A schema that accepts anything has no teeth,
// so each case below would pass a broken validator and must fail here instead.
describe("ingest validation", () => {
  const base = {
    schema_version: "1",
    event_id: "evt-1",
    run_id: "11111111-1111-4111-8111-111111111111",
    span_id: "22222222-2222-4222-8222-222222222222",
    event_type: "model.request",
    timestamp: "2026-10-13T12:00:00.000Z",
    status: "success"
  };

  it("accepts a minimal valid event", () => {
    expect(ingestBodySchema.safeParse({ events: [base] }).success).toBe(true);
  });

  it("rejects negative tokens", () => {
    const r = ingestBodySchema.safeParse({ events: [{ ...base, input_tokens: -5 }] });
    expect(r.success).toBe(false);
  });

  it("rejects unknown event types", () => {
    const r = ingestBodySchema.safeParse({ events: [{ ...base, event_type: "hack" }] });
    expect(r.success).toBe(false);
  });

  it("rejects empty batches and oversized batches", () => {
    expect(ingestBodySchema.safeParse({ events: [] }).success).toBe(false);
    const big = Array.from({ length: 501 }, (_, i) => ({ ...base, event_id: `evt-${i}` }));
    expect(ingestBodySchema.safeParse({ events: big }).success).toBe(false);
  });

  it("marks missing usage as unavailable, never zero", () => {
    const r = ingestBodySchema.safeParse({ events: [{ ...base }] });
    expect(r.success).toBe(true);
    if (r.success) {
      expect(r.data.events[0].input_tokens).toBeUndefined();
    }
  });
});
