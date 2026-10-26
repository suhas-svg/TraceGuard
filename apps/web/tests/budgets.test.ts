import { describe, expect, it } from "vitest";
import { budgetRemainingHint } from "../src/api";

// FR-017 follow-up: a remainder is unknowable when unpriced usage exists.
// The dashboard must say so instead of rendering $0.00.
describe("budgetRemainingHint", () => {
  it("reports unknown when spend is incomplete, even with a remainder present", () => {
    expect(
      budgetRemainingHint(
        { spend_complete: false, remaining_micro: 4_000_000 },
        "remaining unknown: unpriced usage"
      )
    ).toBe("remaining unknown: unpriced usage");
  });

  it("renders the remainder when spend is complete", () => {
    expect(
      budgetRemainingHint({ spend_complete: true, remaining_micro: 2_500_000 }, "unknown")
    ).toBe("remaining $2.5000");
  });

  it("treats a missing remainder as zero, not unknown", () => {
    expect(budgetRemainingHint({ remaining_micro: null }, "unknown")).toBe("remaining $0.0000");
  });

  it("clamps a negative remainder at zero", () => {
    expect(
      budgetRemainingHint({ spend_complete: true, remaining_micro: -100 }, "unknown")
    ).toBe("remaining $0.0000");
  });
});
