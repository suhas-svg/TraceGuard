import { describe, expect, it } from "vitest";
import {
  checkConditions,
  evaluate,
  pathWithin,
  requestHash,
  type PolicyRule
} from "../src/policy.js";

const base: PolicyRule = {
  id: "r1", version: 1, name: "base", enabled: true, priority: 0,
  agent_id: null, server_id: null, tool_name: null, effect: "allow", conditions: {}
};
const rule = (over: Partial<PolicyRule>): PolicyRule => ({ ...base, ...over });

// Each case below would pass a validator that allows everything, so the test
// only has teeth if it asserts the specific denial or binding failure.
describe("policy evaluation", () => {
  it("explicit deny beats a general allow", () => {
    const rules = [
      rule({ id: "a", name: "allow-all", effect: "allow", priority: 0 }),
      rule({ id: "d", name: "deny-wipe", effect: "deny", priority: 0, tool_name: "wipe_disk" })
    ];
    const r = evaluate(rules, { caller: "c", server_id: "s", tool_name: "wipe_disk", args: {} });
    expect(r.decision).toBe("deny");
    expect(r.rule?.name).toBe("deny-wipe");
  });

  it("priority breaks ties only within the same effect", () => {
    const rules = [
      rule({ id: "a", name: "low-allow", effect: "allow", priority: 1 }),
      rule({ id: "d", name: "high-deny", effect: "deny", priority: 100 })
    ];
    expect(evaluate(rules, { caller: "c", server_id: "s", tool_name: "t", args: {} }).decision).toBe("deny");
  });

  it("unknown tools are denied when nothing allows them", () => {
    const r = evaluate([], { caller: "c", server_id: "s", tool_name: "mystery", args: {} });
    expect(r.decision).toBe("deny");
  });

  it("approval never overrides a deny", () => {
    const rules = [
      rule({ id: "p", name: "needs-ok", effect: "require_approval", priority: 50 }),
      rule({ id: "d", name: "no-shell", effect: "deny", priority: 0, tool_name: "shell" })
    ];
    const r = evaluate(rules, { caller: "c", server_id: "s", tool_name: "shell", args: {} });
    expect(r.decision).toBe("deny");
  });

  it("disabled rules do not match", () => {
    const rules = [rule({ enabled: false, effect: "deny" })];
    const r = evaluate(rules, { caller: "c", server_id: "s", tool_name: "t", args: {} });
    expect(r.decision).toBe("deny");
    expect(r.matched).toHaveLength(0);
  });
});

describe("argument constraints", () => {
  it("path_within rejects .. escapes", () => {
    expect(pathWithin("/data/report.txt", "/data")).toBe(true);
    expect(pathWithin("/data/../etc/passwd", "/data")).toBe(false);
    expect(pathWithin("/database/x", "/data")).toBe(false);
  });

  it("required and operator checks narrow a rule", () => {
    const cond = {
      required: ["path"],
      arguments: { path: { path_within: "/data" }, mode: { enum: ["read"] } }
    };
    expect(checkConditions({ path: "/data/a", mode: "read" }, cond)).toBe(true);
    expect(checkConditions({ mode: "read" }, cond)).toBe(false);
    expect(checkConditions({ path: "/etc/x", mode: "read" }, cond)).toBe(false);
    expect(checkConditions({ path: "/data/a", mode: "write" }, cond)).toBe(false);
  });
});

describe("approval binding", () => {
  it("any change of caller, args, request id, or pin breaks the hash", () => {
    const pin = "a".repeat(64);
    const h = requestHash("c", "s", "t", { a: 1 }, "req-1", pin);
    expect(requestHash("c", "s", "t", { a: 1 }, "req-1", pin)).toBe(h);
    expect(requestHash("other", "s", "t", { a: 1 }, "req-1", pin)).not.toBe(h);
    expect(requestHash("c", "s", "t", { a: 2 }, "req-1", pin)).not.toBe(h);
    expect(requestHash("c", "s", "t", { a: 1 }, "req-2", pin)).not.toBe(h);
    // §9.1 binds the tool-definition pin: a re-approved or changed definition
    // must not reuse an approval issued for the old one.
    expect(requestHash("c", "s", "t", { a: 1 }, "req-1", "b".repeat(64))).not.toBe(h);
    // Key order must not matter (RFC 8785 canonical JSON).
    expect(requestHash("c", "s", "t", { b: 2, a: 1 }, "req-1", pin)).toBe(
      requestHash("c", "s", "t", { a: 1, b: 2 }, "req-1", pin)
    );
  });
});
