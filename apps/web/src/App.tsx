import { useEffect, useState } from "react";
import { useInfiniteQuery, useQuery, useQueryClient } from "@tanstack/react-query";
import { formatMicro, getTrace, getUsage, gwApi, listRuns, settings, type Span } from "./api";
import { buildTree, tokenTotal, type SpanNode } from "./tree";
import { relTime } from "./format";
import { useHashRoute, type Tab } from "./router";
import EvalsView from "./Evals";
import PoliciesView from "./Policies";
import ApprovalsView from "./Approvals";
import WebhooksView from "./Webhooks";
import RetentionView from "./Retention";
import CostsView from "./Costs";
import UsersView from "./Users";
import {
  Alert, Badge, Button, Card, Empty, Field, Input, LinkButton,
  NavIcon, Page, Segmented, Stat, StatusBadge, Table, TableSkeleton, Td, Th
} from "./components";

const TABS: { id: Tab; label: string }[] = [
  { id: "runs", label: "Runs" },
  { id: "evals", label: "Evaluations" },
  { id: "policy", label: "Policy" },
  { id: "approvals", label: "Approvals" },
  { id: "webhooks", label: "Webhooks" },
  { id: "retention", label: "Retention" },
  { id: "costs", label: "Costs" },
  { id: "users", label: "Users" }
];

function short(id: string) {
  return id.slice(0, 8);
}

function theme(): "light" | "dark" {
  if (typeof document === "undefined") return "light";
  const saved = localStorage.getItem("tg-theme");
  if (saved === "dark" || saved === "light") return saved;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function ThemeToggle() {
  const [mode, setMode] = useState<"light" | "dark">("light");
  useEffect(() => {
    const t = theme();
    setMode(t);
    document.documentElement.classList.toggle("dark", t === "dark");
  }, []);
  return (
    <button
      onClick={() => {
        const next = mode === "dark" ? "light" : "dark";
        setMode(next);
        localStorage.setItem("tg-theme", next);
        document.documentElement.classList.toggle("dark", next === "dark");
      }}
      aria-label={mode === "dark" ? "Switch to light mode" : "Switch to dark mode"}
      title={mode === "dark" ? "Switch to light mode" : "Switch to dark mode"}
      className="flex h-8 w-8 items-center justify-center rounded-md text-slate-400 transition-colors hover:bg-white/10 hover:text-white"
    >
      {mode === "dark" ? (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
          strokeLinecap="round" className="h-4 w-4" aria-hidden="true">
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4l1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
        </svg>
      ) : (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
          strokeLinecap="round" strokeLinejoin="round" className="h-4 w-4" aria-hidden="true">
          <path d="M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z" />
        </svg>
      )}
    </button>
  );
}

function ConnectionDrawer({ open, onClose, onSaved }: {
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [url, setUrl] = useState(settings.url);
  const [key, setKey] = useState(settings.key);
  const [gwUrl, setGwUrl] = useState(settings.gwUrl);
  const [approverKey, setApproverKey] = useState(settings.approverKey);
  return (
    <div
      className={`fixed inset-0 z-50 flex justify-end transition-[visibility] duration-200 ${open ? "visible" : "invisible"}`}
      role="dialog" aria-label="Connection settings" aria-hidden={!open}
    >
      <div
        className={`absolute inset-0 bg-black/50 transition-opacity duration-200 ${open ? "opacity-100" : "opacity-0"}`}
        onClick={onClose}
      />
      <form
        className={`relative flex w-80 flex-col gap-3 bg-surface p-5 shadow-xl transition-transform duration-200 ${open ? "translate-x-0" : "translate-x-full"}`}
        onSubmit={(e) => {
          e.preventDefault();
          settings.save(url, key, gwUrl, approverKey);
          onSaved();
          onClose();
        }}
      >
        <h2 className="text-base font-semibold text-ink-900">Connection</h2>
        <p className="text-xs text-ink-500">Keys stay in this browser only, never on the server.</p>
        <Field label="API URL"><Input value={url} onChange={(e) => setUrl(e.target.value)} /></Field>
        <Field label="API key"><Input type="password" value={key} onChange={(e) => setKey(e.target.value)} /></Field>
        <Field label="Gateway URL"><Input value={gwUrl} onChange={(e) => setGwUrl(e.target.value)} /></Field>
        <Field label="Approver key">
          <Input type="password" value={approverKey} onChange={(e) => setApproverKey(e.target.value)} />
        </Field>
        <div className="mt-1 flex gap-2">
          <Button variant="primary" type="submit">Connect</Button>
          <Button type="button" onClick={onClose}>Cancel</Button>
        </div>
      </form>
    </div>
  );
}

function RunsList({ onOpen }: { onOpen: (id: string) => void }) {
  const [status, setStatus] = useState("");
  const runsQuery = useInfiniteQuery({
    queryKey: ["runs", status],
    queryFn: ({ pageParam }) => listRuns({ status: status || undefined, limit: 50, cursor: pageParam ?? undefined }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    refetchInterval: 10_000
  });
  const runs = runsQuery.data?.pages.flatMap((p) => p.items) ?? [];
  const error = runsQuery.error instanceof Error ? runsQuery.error.message : runsQuery.error ? "load failed" : "";

  const counts = runs.reduce<Record<string, number>>((m, r) => {
    m[r.status] = (m[r.status] ?? 0) + 1;
    return m;
  }, {});
  // Clicking a KPI filters the list below it; clicking it again clears the filter.
  const toggleStatus = (s: string) => setStatus((cur) => (cur === s ? "" : s));

  return (
    <Page
      title="Runs"
      sub="Every agent execution, newest first. Open one for its full trace."
      actions={
        <>
          <Segmented
            label="Filter by status"
            value={status}
            onChange={(v) => setStatus(v)}
            options={[
              { value: "", label: "All" },
              { value: "running", label: "Running" },
              { value: "success", label: "Success" },
              { value: "failed", label: "Failed" },
              { value: "cancelled", label: "Cancelled" }
            ]}
          />
          <Button onClick={() => runsQuery.refetch()}>Refresh</Button>
        </>
      }
    >
      {runs.length > 0 && (
        <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Stat label="Loaded" value={runs.length} />
          <Stat
            label="Failed" value={counts.failed ?? 0} tone={(counts.failed ?? 0) > 0 ? "bad" : "default"}
            active={status === "failed"} onClick={() => toggleStatus("failed")}
          />
          <Stat
            label="Running" value={counts.running ?? 0} tone={(counts.running ?? 0) > 0 ? "warn" : "default"}
            active={status === "running"} onClick={() => toggleStatus("running")}
          />
          <Stat label="Denied spans" value={counts.denied ?? 0} />
        </div>
      )}
      {error && <Alert>{error}</Alert>}
      {runsQuery.isPending ? (
        <TableSkeleton label="Loading runs..." />
      ) : runs.length === 0 ? (
        <Empty hint="No runs yet. Run the demo agent to create one." />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Run</Th>
              <Th>Agent</Th>
              <Th>Status</Th>
              <Th>Started</Th>
              <Th className="text-right">Spans</Th>
              <Th className="text-right">Tokens in/out</Th>
            </tr>
          </thead>
          <tbody>
            {runs.map((r) => (
              <tr key={r.id} className="transition-colors hover:bg-ink-50/70">
                <Td><LinkButton onClick={() => onOpen(r.id)}>{short(r.id)}</LinkButton></Td>
                <Td>{r.agent_name}</Td>
                <Td><StatusBadge status={r.status} /></Td>
                <Td className="whitespace-nowrap text-ink-500" title={new Date(r.started_at).toLocaleString()}>
                  {relTime(r.started_at)}
                </Td>
                <Td className="text-right">{r.span_count}</Td>
                <Td className="whitespace-nowrap text-right">{r.input_tokens}/{r.output_tokens}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      {runs.length > 0 && (
        <p className="mt-2 text-xs text-ink-500">
          {runs.length} run{runs.length === 1 ? "" : "s"} loaded
          {runsQuery.hasNextPage ? " · older runs load on demand" : ""} · refreshes every 10 s
        </p>
      )}
      <div className="mt-3">
        {runsQuery.hasNextPage && (
          <Button disabled={runsQuery.isFetching} onClick={() => runsQuery.fetchNextPage()}>
            Load more
          </Button>
        )}
      </div>
    </Page>
  );
}

function SpanRow({ node, depth, selected, onSelect, base, maxEnd }: {
  node: SpanNode;
  depth: number;
  selected: string | null;
  onSelect: (id: string) => void;
  base: number;
  maxEnd: number;
}) {
  const s = node.span;
  const start = new Date(s.started_at).getTime() - base;
  const dur = s.duration_ms ?? 0;
  const left = maxEnd > 0 ? Math.min(96, (start / maxEnd) * 100) : 0;
  const width = maxEnd > 0 && dur > 0 ? Math.max(1.5, Math.min(100 - left, (dur / maxEnd) * 100)) : 1.5;
  const barTone =
    s.status === "failed" || s.status === "denied" ? "bg-bad-700/70"
    : s.operation_type.includes("tool") ? "bg-brand-500/70"
    : "bg-ink-300";
  return (
    <>
      <button
        className={`block w-full rounded-md px-2 py-1.5 text-left transition-colors hover:bg-ink-50 ${
          selected === s.id ? "bg-brand-50 ring-1 ring-brand-200" : ""
        }`}
        style={{ paddingLeft: `${depth * 1.25 + 0.5}rem` }}
        onClick={() => onSelect(s.id)}
      >
        <span className="flex items-center gap-2 text-sm">
          <StatusBadge status={s.status} />
          <span className="font-mono font-medium text-ink-800">{s.operation_type}</span>
          {s.model && <span className="truncate text-ink-500">{s.model}</span>}
          {s.error_type && <span className="text-bad-700">{s.error_type}</span>}
          <span className="tg-nums ml-auto shrink-0 text-xs text-ink-500">
            {s.duration_ms != null ? `${s.duration_ms} ms` : ""}
          </span>
        </span>
        <span className="tg-track mt-1 block h-1.5 w-full" aria-hidden="true">
          <span className={`tg-bar block h-1.5 ${barTone}`} style={{ marginLeft: `${left}%`, width: `${width}%` }} />
        </span>
      </button>
      {node.children.map((c) => (
        <SpanRow key={c.span.id} node={c} depth={depth + 1} selected={selected} onSelect={onSelect} base={base} maxEnd={maxEnd} />
      ))}
    </>
  );
}

function SpanDetail({ span }: { span: Span }) {
  // Denials come from policy rules or exhausted budgets. The stored reason
  // names the cause; the label only says denied.
  const denialCause =
    (span.attributes?.reason as string | undefined) ?? span.error_type ?? "policy";
  const rows: [string, React.ReactNode][] = [
    ["Operation", <span className="font-mono">{span.operation_type}</span>],
    ["Status", span.status === "denied" ? `denied by ${denialCause}` : span.status],
    ["Started", new Date(span.started_at).toLocaleString()],
    ["Duration", span.duration_ms != null ? `${span.duration_ms} ms` : "n/a"],
    ["Provider", span.provider ?? "n/a"],
    ["Model", span.model ?? "n/a"],
    ["Tokens", `${span.input_tokens ?? "unknown"} in / ${span.output_tokens ?? "unknown"} out`],
    ["Usage source", span.usage_source ?? "n/a"],
    ["Error", span.error_type ?? "none"]
  ];
  return (
    <Card className="p-4 text-sm">
      <h3 className="mb-2 font-mono font-semibold text-ink-900">span {short(span.id)}</h3>
      <dl>
        {rows.map(([k, v]) => (
          <div key={k} className="flex gap-3 border-b border-ink-100 py-1.5 last:border-0">
            <dt className="w-28 shrink-0 text-ink-500">{k}</dt>
            <dd className="text-ink-800">{v}</dd>
          </div>
        ))}
      </dl>
      <details className="mt-2">
        <summary className="cursor-pointer text-sm text-ink-500">attributes</summary>
        <pre className="mt-1 max-h-64 overflow-auto rounded-md bg-[#0b0e16] p-3 font-mono text-xs text-slate-100">
          {JSON.stringify(span.attributes, null, 2)}
        </pre>
      </details>
    </Card>
  );
}

function TraceView({ runId, onBack }: { runId: string; onBack: () => void }) {
  const [selected, setSelected] = useState<string | null>(null);
  const traceQuery = useQuery({ queryKey: ["trace", runId], queryFn: () => getTrace(runId) });
  const usageQuery = useQuery({ queryKey: ["usage", runId], queryFn: () => getUsage(runId) });

  const error = traceQuery.error instanceof Error ? traceQuery.error.message : traceQuery.error ? "load failed" : "";
  const run = traceQuery.data?.run ?? null;
  const spans: Span[] = traceQuery.data?.spans ?? [];
  const cost = usageQuery.data
    ? `${formatMicro(usageQuery.data.estimated_cost_micro)}${usageQuery.data.cost_partial ? " (partial)" : ""}`
    : usageQuery.isError ? "n/a" : null;

  if (error) {
    return (
      <Page title="Trace">
        <Alert>{error}</Alert>
        <Button onClick={onBack}>Back to runs</Button>
      </Page>
    );
  }
  if (!run) {
    return (
      <Page title="Trace"><TableSkeleton label="Loading trace..." /></Page>
    );
  }

  const roots = buildTree(spans);
  const totals = tokenTotal(spans);
  const selectedSpan = spans.find((s) => s.id === selected) ?? null;
  const base = spans.length
    ? Math.min(...spans.map((s) => new Date(s.started_at).getTime()))
    : 0;
  const maxEnd = spans.length
    ? Math.max(...spans.map((s) => new Date(s.started_at).getTime() + (s.duration_ms ?? 0))) - base
    : 0;

  return (
    <Page
      title={short(run.id)}
      sub={`${run.agent_name ?? "unknown agent"} · started ${new Date(run.started_at).toLocaleString()}`}
      actions={<Button onClick={onBack}>Back to runs</Button>}
    >
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <StatusBadge status={run.status} />
        {run.error_type && <Badge tone="bad">{run.error_type}</Badge>}
        <span className="tg-nums text-sm text-ink-500">{totals.input} in / {totals.output} out</span>
        {cost && <span className="tg-nums text-sm text-ink-500">est. {cost}</span>}
      </div>
      <div className="grid items-start gap-4 lg:grid-cols-2">
        <Card className="space-y-0.5 p-2">
          {roots.map((n) => (
            <SpanRow key={n.span.id} node={n} depth={0} selected={selected} onSelect={setSelected} base={base} maxEnd={maxEnd} />
          ))}
          {roots.length === 0 && <p className="p-2 text-sm text-ink-500">No spans recorded.</p>}
        </Card>
        <div className="lg:sticky lg:top-4">
          {selectedSpan ? (
            <SpanDetail span={selectedSpan} />
          ) : (
            <Empty hint="Select a span to inspect its timing, tokens, and error." />
          )}
        </div>
      </div>
    </Page>
  );
}

export default function App() {
  const [{ tab, runId: openRun }, navigate] = useHashRoute();
  const [drawer, setDrawer] = useState(false);
  const queryClient = useQueryClient();
  const health = useQuery({
    queryKey: ["healthz"],
    queryFn: async () => (await fetch(`${settings.url}/healthz`)).ok,
    refetchInterval: 30_000
  });
  const connected = health.isError ? false : health.data ?? null;
  // Same key as the Approvals view's default filter, so the badge rides the
  // cache the view already warms.
  const pendingApprovals = useQuery({
    queryKey: ["approvals", "pending"],
    queryFn: () => gwApi.approvals("pending"),
    refetchInterval: 30_000,
    retry: false
  }).data?.items.length ?? 0;

  const go = (t: Tab) => navigate({ tab: t, runId: null });

  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 flex h-screen w-60 shrink-0 flex-col bg-[#0b0e16] text-slate-300">
        <div className="flex items-center gap-2 px-5 pb-5 pt-6">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-brand-400 to-brand-700 font-mono text-sm font-bold text-white shadow-lg shadow-brand-600/30">
            TG
          </span>
          <div>
            <div className="text-[15px] font-semibold tracking-tight text-white">TraceGuard</div>
            <div className="text-[11px] text-slate-500">agent control plane</div>
          </div>
          <span className="ml-auto">
            <ThemeToggle />
          </span>
        </div>
        <nav className="flex flex-col gap-0.5 px-3" aria-label="Primary">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => go(t.id)}
              aria-current={tab === t.id && !openRun ? "page" : undefined}
              className={`flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors ${
                tab === t.id && !openRun
                  ? "bg-white/10 font-medium text-white"
                  : "text-slate-400 hover:bg-white/5 hover:text-white"
              }`}
            >
              <NavIcon name={t.id} />
              {t.label}
              {t.id === "approvals" && pendingApprovals > 0 && (
                <span
                  className="tg-nums ml-auto rounded-full bg-brand-600 px-1.5 py-0.5 text-[11px] font-medium leading-none text-white"
                  aria-label={`${pendingApprovals} pending`}
                >
                  {pendingApprovals}
                </span>
              )}
            </button>
          ))}
        </nav>
        <div className="mt-auto p-4">
          <button
            onClick={() => setDrawer(true)}
            className="flex w-full items-center gap-2 rounded-md border border-white/10 px-3 py-2 text-left text-xs text-slate-400 hover:bg-white/5"
          >
            <span
              className={`inline-block h-2 w-2 rounded-full ${
                connected === null ? "bg-slate-500" : connected ? "bg-green-400" : "bg-red-400"
              }`}
              aria-hidden="true"
            />
            <span className="truncate">
              {connected === null ? "checking API..." : connected ? settings.url : "API unreachable"}
            </span>
          </button>
        </div>
      </aside>
      <div className="min-w-0 flex-1">
        <main>
          {tab === "evals" ? (
            <EvalsView onOpenRun={(id) => navigate({ tab: "runs", runId: id })} />
          ) : tab === "policy" ? (
            <PoliciesView />
          ) : tab === "approvals" ? (
            <ApprovalsView />
          ) : tab === "webhooks" ? (
            <WebhooksView />
          ) : tab === "retention" ? (
            <RetentionView />
          ) : tab === "costs" ? (
            <CostsView />
          ) : tab === "users" ? (
            <UsersView />
          ) : openRun ? (
            <TraceView runId={openRun} onBack={() => navigate({ tab: "runs", runId: null })} />
          ) : (
            <RunsList onOpen={(id) => navigate({ tab: "runs", runId: id })} />
          )}
        </main>
      </div>
      <ConnectionDrawer open={drawer} onClose={() => setDrawer(false)}
        onSaved={() => queryClient.invalidateQueries()} />
    </div>
  );
}
