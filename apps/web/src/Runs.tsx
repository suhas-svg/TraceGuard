import { useState } from "react";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import {
  getRunCounts, listAgents, listRuns, type RunItem
} from "./api";
import { relTime } from "./format";
import { filterRuns, sortRuns, type RunSortDir, type RunSortKey } from "./runsview";
import {
  Alert, Button, Card, Field, Input, LinkButton, NavIcon, Page, Segmented,
  Select, StatusBadge, TableSkeleton, Td, Th
} from "./components";

function runDuration(started: string, ended: string | null) {
  if (!ended) return "—";
  const ms = new Date(ended).getTime() - new Date(started).getTime();
  if (!Number.isFinite(ms) || ms < 0) return "—";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(ms < 10_000 ? 2 : 1)} s`;
}

function formatTokens(value: string) {
  const n = Number(value);
  return Number.isFinite(n) ? n.toLocaleString() : value;
}

function initials(name: string) {
  const parts = name.split(/[-_\s]+/).filter(Boolean);
  return (parts.slice(0, 2).map((p) => p[0]).join("") || "?").toUpperCase();
}

// The API exposes run ids, agents, and timestamps, so the export mirrors the
// table rather than inventing pricing or cost columns the list endpoint lacks.
function downloadCsv(rows: RunItem[]) {
  const cell = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const header = [
    "run_id", "agent", "status", "started_at", "ended_at", "duration",
    "spans", "input_tokens", "output_tokens"
  ];
  const body = rows.map((r) => [
    r.id, r.agent_name, r.status, r.started_at, r.ended_at ?? "",
    runDuration(r.started_at, r.ended_at), r.span_count, r.input_tokens, r.output_tokens
  ]);
  const csv = [header, ...body].map((row) => row.map(cell).join(",")).join("\r\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = `traceguard-runs-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function FilterChip({ label, onClear }: { label: string; onClear: () => void }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-ink-200 bg-surface-2 py-0.5 pl-2 pr-1 text-[11px] text-ink-600">
      {label}
      <button
        type="button"
        onClick={onClear}
        aria-label={`Remove ${label}`}
        className="grid h-4 w-4 place-items-center rounded-full text-ink-400 transition-colors hover:bg-surface-3 hover:text-ink-800"
      >
        <NavIcon name="close" className="h-2.5 w-2.5" />
      </button>
    </span>
  );
}

export default function RunsView({ onOpen }: { onOpen: (id: string) => void }) {
  const [status, setStatus] = useState("");
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<{ key: RunSortKey; dir: RunSortDir } | null>(null);
  const [showFilters, setShowFilters] = useState(false);
  // Server-side filters narrow what the API returns, including runs that have
  // not been paged in yet. Search and sort stay client-side over loaded pages.
  const [agentId, setAgentId] = useState("");
  const [provider, setProvider] = useState("");
  const [model, setModel] = useState("");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [evalRunId, setEvalRunId] = useState("");

  const agentsQuery = useQuery({ queryKey: ["agents"], queryFn: listAgents, staleTime: 60_000 });
  const filters = {
    status: status || undefined,
    agent_id: agentId || undefined,
    provider: provider.trim() || undefined,
    model: model.trim() || undefined,
    since: since ? new Date(`${since}T00:00:00`).toISOString() : undefined,
    until: until ? new Date(`${until}T23:59:59.999`).toISOString() : undefined,
    eval_run_id: evalRunId.trim() || undefined
  };
  const runsQuery = useInfiniteQuery({
    queryKey: ["runs", filters],
    queryFn: ({ pageParam }) => listRuns({ ...filters, limit: 50, cursor: pageParam ?? undefined }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    refetchInterval: 10_000
  });
  const runs = runsQuery.data?.pages.flatMap((p) => p.items) ?? [];
  const error = runsQuery.error instanceof Error ? runsQuery.error.message : runsQuery.error ? "load failed" : "";

  // Global totals from the counts endpoint keep the headline meaningful while
  // the list below is filtered.
  const totalsQuery = useQuery({
    queryKey: ["runs", "counts"],
    queryFn: getRunCounts,
    refetchInterval: 15_000
  });
  const totals = totalsQuery.data;
  const filtered = filterRuns(runs, query);
  const visible = sort ? sortRuns(filtered, sort.key, sort.dir) : filtered;
  const flipSort = (key: RunSortKey) =>
    setSort((cur) => (cur?.key === key ? { key, dir: cur.dir === "desc" ? "asc" : "desc" } : { key, dir: "desc" }));

  const advancedCount = [agentId, provider, model, since, until, evalRunId].filter(Boolean).length;
  const agentName = agentsQuery.data?.items.find((a) => a.id === agentId)?.name ?? (agentId ? agentId.slice(0, 8) : "");
  const clearAll = () => {
    setStatus("");
    setAgentId("");
    setProvider("");
    setModel("");
    setSince("");
    setUntil("");
    setEvalRunId("");
  };

  return (
    <Page
      eyebrow="Monitor"
      title={
        <span className="inline-flex items-baseline gap-2.5">
          Runs
          <span className="tg-nums text-[15px] font-semibold tracking-normal text-ink-400">
            {totals ? totals.total.toLocaleString() : "–"}
          </span>
        </span>
      }
      sub="Every agent execution, newest first. Open a run for its full trace."
      actions={
        <>
          <Button onClick={() => downloadCsv(visible)} disabled={visible.length === 0}>
            <NavIcon name="download" className="h-3.5 w-3.5" />
            Export
          </Button>
          <Button variant="primary" onClick={() => runsQuery.refetch()}>
            <NavIcon name="refresh" className="h-3.5 w-3.5" />
            Refresh
          </Button>
        </>
      }
    >
      {error && <Alert>{error}</Alert>}

      <Card className="mb-3">
        <div className="flex flex-wrap items-center gap-2 px-3.5 py-3">
          <label className="flex min-w-[240px] flex-1 items-center gap-2 rounded-lg border border-ink-200 bg-surface-2 px-2.5 py-1.5 text-ink-400 transition-colors focus-within:border-brand-400 focus-within:bg-surface focus-within:ring-2 focus-within:ring-brand-500/15 sm:max-w-[320px] sm:flex-none">
            <NavIcon name="search" className="h-4 w-4 shrink-0" />
            <input
              aria-label="Search runs"
              placeholder="Search run id or agent..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full bg-transparent text-[12.5px] text-ink-800 outline-none placeholder:text-ink-400"
            />
          </label>

          <Segmented
            label="Filter by status"
            value={status}
            onChange={setStatus}
            options={[
              { value: "", label: "All" },
              { value: "running", label: "Running" },
              { value: "success", label: "Success" },
              { value: "failed", label: "Failed" },
              { value: "cancelled", label: "Cancelled" }
            ]}
          />

          <Select
            aria-label="Filter by agent"
            value={agentId}
            onChange={(e) => setAgentId(e.target.value)}
            className="max-w-[190px]"
          >
            <option value="">All agents</option>
            {(agentsQuery.data?.items ?? []).map((a) => (
              <option key={a.id} value={a.id}>{a.name}</option>
            ))}
          </Select>

          <Button
            onClick={() => setShowFilters((v) => !v)}
            aria-expanded={showFilters}
            aria-controls="run-filters"
          >
            <NavIcon name="filter" className="h-3.5 w-3.5" />
            Filters
            {advancedCount > 0 && (
              <span className="tg-nums rounded-full bg-brand-600 px-1.5 py-0.5 text-[10px] font-semibold leading-none text-white">
                {advancedCount}
              </span>
            )}
          </Button>

          <span
            className="ml-auto inline-flex items-center gap-1.5 rounded-full border border-ink-200 bg-surface-2 px-2 py-1 text-[10px] font-semibold text-ink-500"
            title="Auto-refreshes every 10 seconds"
          >
            <span className="tg-live-dot" aria-hidden="true" />
            Live
          </span>
        </div>

        {(status || advancedCount > 0) && (
          <div className="flex flex-wrap items-center gap-1.5 border-t border-ink-200 px-3.5 py-2 text-[11px]">
            <span className="mr-1 text-ink-400">Active</span>
            {status && <FilterChip label={`Status: ${status}`} onClear={() => setStatus("")} />}
            {agentId && <FilterChip label={`Agent: ${agentName}`} onClear={() => setAgentId("")} />}
            {provider && <FilterChip label={`Provider: ${provider}`} onClear={() => setProvider("")} />}
            {model && <FilterChip label={`Model: ${model}`} onClear={() => setModel("")} />}
            {since && <FilterChip label={`From: ${since}`} onClear={() => setSince("")} />}
            {until && <FilterChip label={`To: ${until}`} onClear={() => setUntil("")} />}
            {evalRunId && <FilterChip label={`Eval: ${evalRunId.slice(0, 8)}`} onClear={() => setEvalRunId("")} />}
            <button
              type="button"
              onClick={clearAll}
              className="ml-1 text-[11px] font-medium text-ink-500 underline decoration-ink-300 underline-offset-2 hover:text-ink-800"
            >
              Clear all
            </button>
          </div>
        )}

        {showFilters && (
          <div
            id="run-filters"
            className="grid gap-3 border-t border-ink-200 bg-surface-2/60 px-3.5 py-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5"
          >
            <Field label="Provider">
              <Input
                aria-label="Filter by provider"
                placeholder="any"
                value={provider}
                onChange={(e) => setProvider(e.target.value)}
              />
            </Field>
            <Field label="Model">
              <Input
                aria-label="Filter by model"
                placeholder="any"
                value={model}
                onChange={(e) => setModel(e.target.value)}
              />
            </Field>
            <Field label="From">
              <Input aria-label="Started after" type="date" value={since} onChange={(e) => setSince(e.target.value)} />
            </Field>
            <Field label="To">
              <Input aria-label="Started before" type="date" value={until} onChange={(e) => setUntil(e.target.value)} />
            </Field>
            <Field label="Eval run">
              <Input
                aria-label="Filter by evaluation run"
                placeholder="eval run id"
                value={evalRunId}
                onChange={(e) => setEvalRunId(e.target.value)}
              />
            </Field>
          </div>
        )}
      </Card>

      {runsQuery.isPending ? (
        <TableSkeleton label="Loading runs..." />
      ) : (
        <Card className="overflow-hidden">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-ink-200 px-4 py-3">
            <div>
              <div className="text-[13px] font-semibold text-ink-900">All runs</div>
              <div className="mt-0.5 text-[11px] text-ink-500">
                {runs.length === 0
                  ? "No runs yet"
                  : query.trim()
                    ? `${visible.length} of ${runs.length} loaded runs match`
                    : `${runs.length} run${runs.length === 1 ? "" : "s"} loaded`}
              </div>
            </div>
            <span className="text-[11px] text-ink-400">Newest first · refreshes every 10 s</span>
          </div>

          {runs.length === 0 ? (
            <div className="px-4 py-14 text-center">
              <p className="text-sm text-ink-500">No runs yet. Run the demo agent to create one.</p>
            </div>
          ) : visible.length === 0 ? (
            <div className="px-4 py-14 text-center">
              <p className="text-sm text-ink-500">No loaded runs match “{query.trim()}”.</p>
            </div>
          ) : (
            <div className="max-h-[68vh] overflow-auto overscroll-contain">
              <table aria-label="Runs" className="tg-nums w-full border-collapse text-[12.5px]">
                <thead>
                  <tr>
                    <Th>Run</Th>
                    <Th>Agent</Th>
                    <Th>Status</Th>
                    <Th
                      onSort={() => flipSort("started")}
                      sorted={sort?.key === "started" ? sort.dir : undefined}
                    >
                      Started
                    </Th>
                    <Th>Duration</Th>
                    <Th
                      className="text-right"
                      onSort={() => flipSort("spans")}
                      sorted={sort?.key === "spans" ? sort.dir : undefined}
                    >
                      Spans
                    </Th>
                    <Th
                      className="text-right"
                      onSort={() => flipSort("tokens")}
                      sorted={sort?.key === "tokens" ? sort.dir : undefined}
                    >
                      Tokens in / out
                    </Th>
                    <Th className="w-8"><span className="sr-only">Open</span></Th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((r) => (
                    <tr key={r.id} className="transition-colors hover:bg-surface-2">
                      <Td>
                        <LinkButton onClick={() => onOpen(r.id)}>{r.id.slice(0, 8)}</LinkButton>
                      </Td>
                      <Td>
                        <span className="inline-flex items-center gap-2 whitespace-nowrap">
                          <span className="flex h-[22px] w-[22px] items-center justify-center rounded-md bg-surface-3 text-[8.5px] font-bold tracking-wide text-ink-600">
                            {initials(r.agent_name)}
                          </span>
                          <span className="text-ink-700">{r.agent_name}</span>
                        </span>
                      </Td>
                      <Td><StatusBadge status={r.status} /></Td>
                      <Td className="whitespace-nowrap text-ink-500" title={new Date(r.started_at).toLocaleString()}>
                        {relTime(r.started_at)}
                      </Td>
                      <Td className="whitespace-nowrap text-ink-500">
                        {r.status === "running" ? "running" : runDuration(r.started_at, r.ended_at)}
                      </Td>
                      <Td className="text-right text-ink-700">{r.span_count}</Td>
                      <Td className="whitespace-nowrap text-right text-ink-700">
                        {formatTokens(r.input_tokens)}
                        <span className="px-1 text-ink-300">/</span>
                        {formatTokens(r.output_tokens)}
                      </Td>
                      <Td className="w-8 text-right">
                        <button
                          type="button"
                          onClick={() => onOpen(r.id)}
                          aria-label={`Open trace for run ${r.id.slice(0, 8)}`}
                          className="grid h-6 w-6 place-items-center rounded-md text-ink-400 transition-colors hover:bg-surface-3 hover:text-brand-600"
                        >
                          <NavIcon name="chevronRight" className="h-3.5 w-3.5" />
                        </button>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {runs.length > 0 && (
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-ink-200 px-4 py-2.5 text-[11px] text-ink-500">
              <span>
                {query.trim() ? `Showing ${visible.length} of ${runs.length} loaded` : `${runs.length} loaded`}
                {runsQuery.hasNextPage ? " · older runs load on demand" : ""} · auto-refreshes every 10 s
              </span>
              {runsQuery.hasNextPage && (
                <Button size="sm" disabled={runsQuery.isFetching} onClick={() => runsQuery.fetchNextPage()}>
                  Load older runs
                </Button>
              )}
            </div>
          )}
        </Card>
      )}
    </Page>
  );
}
