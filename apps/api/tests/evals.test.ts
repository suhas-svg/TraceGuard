import { describe, expect, it } from "vitest";
import { runAssertion } from "../src/assertions.js";

// A judge that passes everything would pass a single happy-path test, so
// every assertion type gets a failing case it must survive.
describe("deterministic assertions", () => {
  const ctx = { output: '{"answer": 42, "ok": true}', tools: ["read_file", "write_file"], status: "success" };

  it("exact distinguishes equal from near-equal", () => {
    expect(runAssertion({ type: "exact", value: ctx.output }, ctx).passed).toBe(true);
    expect(runAssertion({ type: "exact", value: ctx.output + " " }, ctx).passed).toBe(false);
  });

  it("contains and regex find and miss", () => {
    expect(runAssertion({ type: "contains", value: "42" }, ctx).passed).toBe(true);
    expect(runAssertion({ type: "contains", value: "43" }, ctx).passed).toBe(false);
    expect(runAssertion({ type: "regex", pattern: '"answer": \\d+' }, ctx).passed).toBe(true);
    expect(runAssertion({ type: "regex", pattern: "zzz" }, ctx).passed).toBe(false);
    expect(runAssertion({ type: "regex", pattern: "(unclosed" }, ctx).passed).toBe(false);
  });

  it("json_schema checks shape, not text", () => {
    const schema = { required: ["answer"], properties: { answer: "number" } };
    expect(runAssertion({ type: "json_schema", schema }, ctx).passed).toBe(true);
    expect(runAssertion({ type: "json_schema", schema: { required: ["missing"] } }, ctx).passed).toBe(false);
    expect(runAssertion({ type: "json_schema", schema }, { ...ctx, output: "not json" }).passed).toBe(false);
  });

  it("tools requires the exact sequence", () => {
    expect(runAssertion({ type: "tools", sequence: ["read_file", "write_file"] }, ctx).passed).toBe(true);
    expect(runAssertion({ type: "tools", sequence: ["read_file"] }, ctx).passed).toBe(false);
    expect(runAssertion({ type: "tools", sequence: ["write_file", "read_file"] }, ctx).passed).toBe(false);
  });

  it("status and unknown types fail loudly", () => {
    expect(runAssertion({ type: "status", value: "success" }, ctx).passed).toBe(true);
    expect(runAssertion({ type: "status", value: "failed" }, ctx).passed).toBe(false);
    expect(runAssertion({ type: "judge" }, ctx).passed).toBe(false);
  });

  it("tools names compare as an unordered multiset", () => {
    expect(runAssertion({ type: "tools", names: ["write_file", "read_file"] }, ctx).passed).toBe(true);
    expect(runAssertion({ type: "tools", names: ["read_file"] }, ctx).passed).toBe(false);
    expect(runAssertion({ type: "tools", names: ["read_file", "read_file"] }, ctx).passed).toBe(false);
    // The ordered form still exists and still cares about order.
    expect(runAssertion({ type: "tools", sequence: ["write_file", "read_file"] }, ctx).passed).toBe(false);
  });

  it("json_schema validates nested objects, arrays, enums and integers", () => {
    const nested = {
      required: ["answer", "items", "state"],
      properties: {
        answer: { type: "integer" },
        items: { type: "array", items: { type: "string" } },
        state: { enum: ["on", "off"] }
      }
    };
    const ok = { ...ctx, output: '{"answer": 42, "items": ["a", "b"], "state": "on"}' };
    expect(runAssertion({ type: "json_schema", schema: nested }, ok).passed).toBe(true);
    const badItem = { ...ctx, output: '{"answer": 42, "items": ["a", 2], "state": "on"}' };
    expect(runAssertion({ type: "json_schema", schema: nested }, badItem).passed).toBe(false);
    const badEnum = { ...ctx, output: '{"answer": 42, "items": ["a"], "state": "maybe"}' };
    expect(runAssertion({ type: "json_schema", schema: nested }, badEnum).passed).toBe(false);
    const float = { ...ctx, output: '{"answer": 4.5, "items": [], "state": "off"}' };
    expect(runAssertion({ type: "json_schema", schema: nested }, float).passed).toBe(false);
    // The flat string shorthand inside properties still works.
    expect(runAssertion({ type: "json_schema",
      schema: { required: ["answer"], properties: { answer: "number" } } }, ok).passed).toBe(true);
  });
});
