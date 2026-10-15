import { describe, expect, it } from "vitest";
import { relTime } from "../src/format";

const now = new Date("2026-10-15T12:00:00.000Z").getTime();
const at = (s: number) => new Date(now - s * 1000).toISOString();

describe("relTime", () => {
  it("says just now under a minute", () => {
    expect(relTime(at(0), now)).toBe("just now");
    expect(relTime(at(59), now)).toBe("just now");
  });

  it("steps through minutes, hours and days", () => {
    expect(relTime(at(60), now)).toBe("1m ago");
    expect(relTime(at(59 * 60), now)).toBe("59m ago");
    expect(relTime(at(3600), now)).toBe("1h ago");
    expect(relTime(at(23 * 3600 + 59 * 60), now)).toBe("23h ago");
    expect(relTime(at(86400), now)).toBe("1d ago");
    expect(relTime(at(6 * 86400), now)).toBe("6d ago");
  });

  it("falls back to a date past a week", () => {
    expect(relTime(at(8 * 86400), now)).toBe(new Date(now - 8 * 86400_000).toLocaleDateString());
  });

  it("never renders NaN, and clamps clock skew to just now", () => {
    expect(relTime("not-a-date", now)).toBe("unknown");
    expect(relTime(at(-120), now)).toBe("just now");
  });
});
