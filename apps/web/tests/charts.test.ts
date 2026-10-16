import { describe, expect, it } from "vitest";
import { binValues, scalePoints } from "../src/charts";

describe("chart helpers", () => {
  it("spreads points across the full width inside the vertical padding", () => {
    const pts = scalePoints([0, 5, 10], 100, 40, 3);
    expect(pts).toHaveLength(3);
    expect(pts[0].x).toBe(0);
    expect(pts[1].x).toBe(50);
    expect(pts[2].x).toBe(100);
    expect(pts[0].y).toBe(37); // the minimum sits pad above the bottom
    expect(pts[2].y).toBe(3); // the maximum sits pad below the top
    expect(pts[1].y).toBe(20);
  });

  it("draws a flat series through the middle and handles short inputs", () => {
    for (const p of scalePoints([4, 4, 4], 100, 40, 3)) expect(p.y).toBe(20);
    expect(scalePoints([], 100, 40)).toEqual([]);
    const single = scalePoints([7], 100, 40);
    expect(single).toHaveLength(1);
    expect(single[0].x).toBe(50); // a lone point centers horizontally
  });

  it("bins values into evenly sized buckets with the max in the last bin", () => {
    const counts = binValues([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], 4);
    expect(counts).toHaveLength(4);
    expect(counts.reduce((a, b) => a + b, 0)).toBe(11);
    expect(counts[0]).toBe(3);
    expect(counts[3]).toBeGreaterThan(0);
    expect(binValues([], 4)).toHaveLength(4);
  });
});
