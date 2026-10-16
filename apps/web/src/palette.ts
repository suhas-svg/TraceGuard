// Command palette entries and their matching rule, kept pure so the palette
// component stays a thin shell.

export type PaletteItem = { id: string; label: string; hint?: string; action: () => void };

export function matchItems(items: PaletteItem[], query: string, limit = 9): PaletteItem[] {
  const q = query.trim().toLowerCase();
  if (!q) return items.slice(0, limit);
  return items
    .filter((i) => `${i.label} ${i.hint ?? ""}`.toLowerCase().includes(q))
    .slice(0, limit);
}
