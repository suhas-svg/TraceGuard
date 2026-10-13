import { describe, expect, it } from "vitest";
import { estimateCostMicro, maxCallCostMicro } from "../src/cost.js";

const price = {
  input_price_per_million: 2_000_000,
  output_price_per_million: 8_000_000,
  cached_input_price_per_million: 500_000
};

// A calculator that rounds, floats, or double-counts would still pass a
// single happy-path case, so each property below gets its own assertion.
describe("cost math", () => {
  it("follows the spec formula exactly", () => {
    expect(estimateCostMicro(1500, 300, 0, price)).toBe(
      Math.floor((1500 * 2_000_000 + 300 * 8_000_000) / 1_000_000)
    );
  });

  it("bills cached tokens once at the cached rate, never double", () => {
    const withCache = estimateCostMicro(1000, 0, 1000, price);
    expect(withCache).toBe(Math.floor((1000 * 500_000) / 1_000_000));
    expect(withCache).toBeLessThan(estimateCostMicro(1000, 0, 0, price));
  });

  it("treats missing usage as zero without NaN", () => {
    expect(estimateCostMicro(null, null, null, price)).toBe(0);
  });

  it("reserves the worst case: full input plus max output", () => {
    expect(maxCallCostMicro(1500, 300, price)).toBe(estimateCostMicro(1500, 300, 0, price));
  });
});
