import type { RunItem } from "./api";

// Client-side view logic for the runs list: the loaded pages are searched and
// sorted in the browser; the API keeps owning pagination and live status.
// shortcut: search spans only the loaded pages, move it server-side if lists
// grow past a few hundred runs.

export type RunSortKey = "started" | "spans" | "tokens";
export type RunSortDir = "asc" | "desc";

export function filterRuns(runs: RunItem[], query: string): RunItem[] {
  const q = query.trim().toLowerCase();
  if (!q) return runs;
  return runs.filter(
    (r) => r.id.toLowerCase().startsWith(q) || r.agent_name.toLowerCase().includes(q)
  );
}

export function sortRuns(runs: RunItem[], key: RunSortKey, dir: RunSortDir): RunItem[] {
  const value = (r: RunItem): number =>
    key === "started"
      ? new Date(r.started_at).getTime()
      : key === "spans"
        ? Number(r.span_count)
        : Number(r.input_tokens) + Number(r.output_tokens);
  const sign = dir === "asc" ? 1 : -1;
  return [...runs].sort((a, b) => sign * (value(a) - value(b)));
}
