import { useCallback, useEffect, useState } from "react";
import { formatMicro, getTrace, getUsage, listRuns, settings, type RunItem, type Span } from "./api";
import { buildTree, tokenTotal, type SpanNode } from "./tree";
import EvalsView from "./Evals";
import PoliciesView from "./Policies";
import ApprovalsView from "./Approvals";
import WebhooksView from "./Webhooks";
import RetentionView from "./Retention";
import CostsView from "./Costs";
import {
  Alert, Badge, Button, Card, Empty, Field, Input, LinkButton,
  NavIcon, Page, Segmented, Spinner, Stat, StatusBadge, Table, Td, Th
} from "./components";

type Tab = "runs" | "evals" | "policy" | "approvals" | "webhooks" | "retention" | "costs";

const TABS: { id: Tab; label: string }[] = [
  { id: "runs", label: "Runs" },
  { id: "evals", label: "Evaluations" },
  { id: "policy", label: "Policy" },
  { id: "approvals", label: "Approvals" },
  { id: "webhooks", label: "Webhooks" },
  { id: "retention", label: "Retention" },
  { id: "costs", label: "Costs" }
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
      className="flex h-8 w-8 items-center justify-center rounded-lg text-slate-400 transition-colors hover:bg-white/10 hover:text-white"
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
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-label="Connection settings">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <form
        className="relative flex w-80 flex-col gap-3 bg-surface p-5 shadow-xl"
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
  const [runs, setRuns] = useState<RunItem[]>([]);
  const [status, setStatus] = useState("");
  const [cursor, setCursor] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const load = useCallback(
    async (next?: string | null, reset = false) => {
      setLoading(true);
      setError("");
      try {
        const res = await listRuns({ status: status || undefined, limit: 50, cursor: next ?? undefined });
        setRuns((prev) => (reset ? res.items : [...prev, ...res.items]));
        setCursor(res.next_cursor);
      } catch (e) {
        setError(e instanceof Error ? e.message : "load failed");
      } finally {
        setLoading(false);
      }
    },
    [status]
  );

  useEffect(() => {
    setRuns([]);
    load(null, true);
  }, [load]);

  const counts = runs.reduce<Record<string, number>>((m, r) => {
    m[r.status] = (m[r.status] ?? 0) + 1;
    return m;
  }, {});

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
          <Button onClick={() => load(null, true)}>Refresh</Button>
        </>
      }
    >
      {runs.length > 0 && (
        <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Stat label="Loaded" value={runs.length} />
          <Stat label="Failed" value={counts.failed ?? 0} />
          <Stat label="Running" value={counts.running ?? 0} />
          <Stat label="Denied spans" value={counts.denied ?? 0} />
        </div>
      )}
      {error && <Alert>{error}</Alert>}
      {runs.length === 0 && !loading ? (
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
                <Td className="whitespace-nowrap text-ink-500">{new Date(r.started_at).toLocaleString()}</Td>
                <Td className="text-right">{r.span_count}</Td>
                <Td className="whitespace-nowrap text-right">{r.input_tokens}/{r.output_tokens}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      {loading && <Spinner />}
      <div className="mt-3">
        {cursor && (
          <Button disabled={loading} onClick={() => load(cursor)}>
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
        className={`block w-full rounded-lg px-2 py-1.5 text-left transition-colors hover:bg-ink-50 ${
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
          <span className="tg-nums ml-auto shrink-0 text-xs text-ink-400">
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
            <dt className="w-28 shrink-0 text-ink-400">{k}</dt>
            <dd className="text-ink-800">{v}</dd>
          </div>
        ))}
      </dl>
      <details className="mt-2">
        <summary className="cursor-pointer text-sm text-ink-500">attributes</summary>
        <pre className="mt-1 max-h-64 overflow-auto rounded-lg bg-[#0b0e16] p-3 font-mono text-xs text-slate-100">
          {JSON.stringify(span.attributes, null, 2)}
        </pre>
      </details>
    </Card>
  );
}

function TraceView({ runId, onBack }: { runId: string; onBack: () => void }) {
  const [run, setRun] = useState<RunItem | null>(null);
  const [spans, setSpans] = useState<Span[]>([]);
  const [cost, setCost] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    getTrace(runId)
      .then((t) => {
        setRun(t.run);
        setSpans(t.spans);
      })
      .catch((e) => setError(e instanceof Error ? e.message : "load failed"));
    getUsage(runId)
      .then((u) => setCost(`${formatMicro(u.estimated_cost_micro)}${u.cost_partial ? " (partial)" : ""}`))
      .catch(() => setCost("n/a"));
  }, [runId]);

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
      <Page title="Trace"><Spinner label="Loading trace..." /></Page>
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
  const [openRun, setOpenRun] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("runs");
  const [settingsTick, setSettingsTick] = useState(0);
  const [drawer, setDrawer] = useState(false);
  const [connected, setConnected] = useState<boolean | null>(null);

  useEffect(() => {
    fetch(`${settings.url}/healthz`)
      .then((r) => setConnected(r.ok))
      .catch(() => setConnected(false));
  }, [settingsTick]);

  const go = (t: Tab) => {
    setOpenRun(null);
    setTab(t);
  };

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
              className={`flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors ${
                tab === t.id && !openRun
                  ? "bg-white/10 font-medium text-white"
                  : "text-slate-400 hover:bg-white/5 hover:text-white"
              }`}
            >
              <NavIcon name={t.id} />
              {t.label}
            </button>
          ))}
        </nav>
        <div className="mt-auto p-4">
          <button
            onClick={() => setDrawer(true)}
            className="flex w-full items-center gap-2 rounded-lg border border-white/10 px-3 py-2 text-left text-xs text-slate-400 hover:bg-white/5"
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
        <main key={settingsTick}>
          {tab === "evals" ? (
            <EvalsView onOpenRun={(id) => { setOpenRun(id); setTab("runs"); }} />
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
          ) : openRun ? (
            <TraceView runId={openRun} onBack={() => setOpenRun(null)} />
          ) : (
            <RunsList onOpen={setOpenRun} />
          )}
        </main>
      </div>
      <ConnectionDrawer open={drawer} onClose={() => setDrawer(false)} onSaved={() => setSettingsTick((t) => t + 1)} />
    </div>
  );
}
