import { describe, expect, it } from "vitest";
import { matchItems, type PaletteItem } from "../src/palette";

const item = (id: string, label: string, hint?: string): PaletteItem => ({ id, label, hint, action: () => {} });
const items = [
  item("tab-runs", "Go to Runs"),
  item("tab-approvals", "Go to Approvals"),
  item("run-abc", "Open run 84ba3a3a", "ts-agent")
];

describe("matchItems", () => {
  it("shows the first entries when the query is empty", () => {
    expect(matchItems(items, "  ").map((i) => i.id)).toEqual(["tab-runs", "tab-approvals", "run-abc"]);
  });

  it("matches the label case-insensitively", () => {
    expect(matchItems(items, "APPROV").map((i) => i.id)).toEqual(["tab-approvals"]);
  });

  it("matches the hint too, so an agent name finds its runs", () => {
    expect(matchItems(items, "ts-agent").map((i) => i.id)).toEqual(["run-abc"]);
  });

  it("returns nothing for an unmatched query, rather than everything", () => {
    expect(matchItems(items, "zzz")).toEqual([]);
  });

  it("caps the list at the limit", () => {
    const many = Array.from({ length: 20 }, (_, i) => item(`i${i}`, `Item ${i}`));
    expect(matchItems(many, "", 9)).toHaveLength(9);
  });
});
