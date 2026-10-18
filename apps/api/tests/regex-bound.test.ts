import { describe, expect, it } from "vitest";
import { fieldConstraintSchema, type PolicyRule } from "@traceguard/schemas";
import { checkField, MAX_REGEX_SUBJECT, regexMatches } from "../src/policy.js";

// T8: a policy regex is matched against caller-supplied arguments, so the
// pattern is refused where it is stored or loaded, and the subject is capped
// where it is matched. These cases are the difference between "bounded" and
// "bounded in the docs".

describe("policy regex bounds (T8)", () => {
  it("accepts the patterns the docs show, and bounded repetition", () => {
    for (const pattern of ["^/tmp/", "^nope", "read_[a-z]+\\.txt$", "(a|b){1,3}", "(ab+){2}", "a{2,}", "^(?!/etc)", "\\d{4}-\\d{2}"]) {
      const parsed = fieldConstraintSchema.safeParse({ regex: pattern });
      expect(parsed.success, pattern).toBe(true);
    }
  });

  it("refuses a pattern that is not a valid regular expression", () => {
    const parsed = fieldConstraintSchema.safeParse({ regex: "(" });
    expect(parsed.success).toBe(false);
  });

  it("refuses the shapes that backtrack catastrophically", () => {
    for (const pattern of ["(a+)+$", "(a*)*", "(\\w+)*@", "([a-z]+){2,}", "^(\\d+)+$", "(a|a)*$", "(a|aa)+", "^(x+)+$", "(a|b)+", "(a|b)*"]) {
      const parsed = fieldConstraintSchema.safeParse({ regex: pattern });
      expect(parsed.success, pattern).toBe(false);
    }
  });

  it("refuses backreferences", () => {
    for (const pattern of ["(a)\\1", "^(\\w+) \\1$"]) {
      const parsed = fieldConstraintSchema.safeParse({ regex: pattern });
      expect(parsed.success, pattern).toBe(false);
    }
  });

  it("refuses an oversized pattern", () => {
    const parsed = fieldConstraintSchema.safeParse({ regex: "a".repeat(513) });
    expect(parsed.success).toBe(false);
  });

  it("denies instead of throwing on a pattern the schema would have refused", () => {
    // Defence in depth: a bundle stored before these checks existed must not
    // crash a decision path, it must simply not match.
    expect(() => checkField("anything", { regex: "(" })).not.toThrow();
    expect(checkField("anything", { regex: "(" })).toBe(false);
    expect(regexMatches("(", "anything")).toBe(false);
  });

  it("caps the subject it matches", () => {
    expect(MAX_REGEX_SUBJECT).toBe(4096);
    // A match inside the cap is found; anything past it is not scanned, so a
    // megabyte argument cannot turn a decision into a stall.
    expect(checkField(`${"x".repeat(MAX_REGEX_SUBJECT)}needle`, { regex: "needle" })).toBe(false);
    expect(checkField(`needle${"x".repeat(1_000_000)}`, { regex: "^needle" })).toBe(true);
    // A pattern of the shape the schema refuses still answers (deny) when it
    // reaches the matcher from an older bundle, instead of hanging on it.
    expect(checkField("x".repeat(64), { regex: "(a+)+$" })).toBe(false);
  });

  it("keeps the rest of the rule semantics intact", () => {
    expect(checkField("abc", { max_length: 2 })).toBe(false);
    expect(checkField("abc", { max_length: 3, regex: "^a" })).toBe(true);
    expect(checkField("/data/file.txt", { path_within: "/data" })).toBe(true);
    expect(checkField("/etc/passwd", { path_within: "/data" })).toBe(false);
  });
});

// The bundle schema is what the loader runs before enforcing anything, so a
// rule that reaches it has to be refused there too.
describe("bundle rules (T8)", () => {
  const rule = (constraint: object): unknown => ({
    id: "11111111-1111-1111-1111-111111111111",
    name: "r",
    enabled: true,
    priority: 1,
    agent_id: null,
    server_id: null,
    tool_name: null,
    effect: "deny",
    conditions: { arguments: { path: constraint } }
  });

  it("refuses a bundle rule whose pattern blows up, and keeps a plain one", async () => {
    const { bundleRuleSchema } = await import("@traceguard/schemas");
    expect(bundleRuleSchema.safeParse(rule({ regex: "(a+)+$" })).success).toBe(false);
    expect(bundleRuleSchema.safeParse(rule({ regex: "^/tmp/" })).success).toBe(true);
  });

  it("still exposes the rule type the api enforces", () => {
    const typed: Pick<PolicyRule, "effect"> = { effect: "deny" };
    expect(typed.effect).toBe("deny");
  });
});
