import { useCallback, useEffect, useState } from "react";
import { formatMicro, getTrace, getUsage, listRuns, settings, type RunItem, type Span } from "./api";
import { buildTree, tokenTotal, type SpanNode } from "./tree";
import EvalsView from "./Evals";

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    success: "bg-green-100 text-green-800",
    failed: "bg-red-100 text-red-800",
    running: "bg-amber-100 text-amber-800",
    cancelled: "bg-gray-100 text-gray-800",
    denied: "bg-purple-100 text-purple-800"
  };
  return (
    <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${colors[status] ?? "bg-gray-100 text-gray-800"}`}>
      {status}
    </span>
  );
}

function short(id: string) {
  return id.slice(0, 8);
}

function SettingsBar({ onSaved }: { onSaved: () => void }) {
  const [url, setUrl] = useState(settings.url);
  const [key, setKey] = useState(settings.key);
  return (
    <form
      className="flex flex-wrap items-end gap-2 border-b bg-gray-50 px-4 py-2 text-sm"
      onSubmit={(e) => {
        e.preventDefault();
        settings.save(url, key);
        onSaved();
      }}
    >
      <label className="flex flex-col">
        <span className="text-xs text-gray-500">API URL</span>
        <input className="w-56 rounded border px-2 py-1" value={url} onChange={(e) => setUrl(e.target.value)} />
      </label>
      <label className="flex flex-col">
        <span className="text-xs text-gray-500">API key</span>
        <input
          className="w-56 rounded border px-2 py-1"
          type="password"
          value={key}
          onChange={(e) => setKey(e.target.value)}
        />
      </label>
      <button className="rounded bg-gray-800 px-3 py-1 text-white" type="submit">
        Connect
      </button>
    </form>
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

  return (
    <div className="p-4">
      <div className="mb-3 flex items-center gap-2">
        <h2 className="text-lg font-semibold">Runs</h2>
        <select
          aria-label="Filter by status"
          className="rounded border px-2 py-1 text-sm"
          value={status}
          onChange={(e) => setStatus(e.target.value)}
        >
          <option value="">all statuses</option>
          <option value="running">running</option>
          <option value="success">success</option>
          <option value="failed">failed</option>
          <option value="cancelled">cancelled</option>
        </select>
        <button className="rounded border px-2 py-1 text-sm" onClick={() => load(null, true)}>
          Refresh
        </button>
      </div>
      {error && <p className="mb-2 rounded bg-red-50 px-2 py-1 text-sm text-red-700">{error}</p>}
      {runs.length === 0 && !loading && <p className="text-sm text-gray-500">No runs yet. Run the demo agent to create one.</p>}
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b text-left text-gray-500">
            <th className="py-1 pr-2">Run</th>
            <th className="py-1 pr-2">Agent</th>
            <th className="py-1 pr-2">Status</th>
            <th className="py-1 pr-2">Started</th>
            <th className="py-1 pr-2">Spans</th>
            <th className="py-1 pr-2">Tokens in/out</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((r) => (
            <tr key={r.id} className="border-b hover:bg-gray-50">
              <td className="py-1 pr-2">
                <button className="text-blue-700 underline" onClick={() => onOpen(r.id)}>
                  {short(r.id)}
                </button>
              </td>
              <td className="py-1 pr-2">{r.agent_name}</td>
              <td className="py-1 pr-2">
                <StatusBadge status={r.status} />
              </td>
              <td className="py-1 pr-2 text-gray-600">{new Date(r.started_at).toLocaleString()}</td>
              <td className="py-1 pr-2">{r.span_count}</td>
              <td className="py-1 pr-2">
                {r.input_tokens}/{r.output_tokens}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="mt-3">
        {cursor && (
          <button className="rounded border px-3 py-1 text-sm" disabled={loading} onClick={() => load(cursor)}>
            Load more
          </button>
        )}
      </div>
    </div>
  );
}

function SpanRow({
  node,
  depth,
  selected,
  onSelect
}: {
  node: SpanNode;
  depth: number;
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  const s = node.span;
  return (
    <>
      <button
        className={`flex w-full items-center gap-2 rounded px-2 py-1 text-left text-sm hover:bg-gray-100 ${
          selected === s.id ? "bg-blue-50" : ""
        }`}
        style={{ paddingLeft: `${depth * 1.25 + 0.5}rem` }}
        onClick={() => onSelect(s.id)}
      >
        <StatusBadge status={s.status} />
        <span className="font-mono">{s.operation_type}</span>
        {s.model && <span className="text-gray-600">{s.model}</span>}
        {s.duration_ms != null && <span className="text-gray-400">{s.duration_ms}ms</span>}
        {s.error_type && <span className="text-red-600">{s.error_type}</span>}
      </button>
      {node.children.map((c) => (
        <SpanRow key={c.span.id} node={c} depth={depth + 1} selected={selected} onSelect={onSelect} />
      ))}
    </>
  );
}

function SpanDetail({ span }: { span: Span }) {
  // Denials come from policy rules or exhausted budgets. The stored reason
  // names the cause; the label only says denied.
  const denialCause =
    (span.attributes?.reason as string | undefined) ?? span.error_type ?? "policy";
  const rows: [string, string][] = [
    ["Operation", span.operation_type],
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
    <div className="rounded border p-3 text-sm">
      <h3 className="mb-2 font-semibold">Span {short(span.id)}</h3>
      <dl>
        {rows.map(([k, v]) => (
          <div key={k} className="flex gap-2 border-b py-1 last:border-0">
            <dt className="w-28 shrink-0 text-gray-500">{k}</dt>
            <dd className="font-mono">{v}</dd>
          </div>
        ))}
      </dl>
      <details className="mt-2">
        <summary className="cursor-pointer text-gray-600">attributes</summary>
        <pre className="mt-1 overflow-auto rounded bg-gray-50 p-2 text-xs">
          {JSON.stringify(span.attributes, null, 2)}
        </pre>
      </details>
    </div>
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
      <div className="p-4">
        <p className="text-sm text-red-700">{error}</p>
        <button className="mt-2 text-blue-700 underline" onClick={onBack}>
          Back to runs
        </button>
      </div>
    );
  }
  if (!run) return <p className="p-4 text-sm text-gray-500">Loading trace...</p>;

  const roots = buildTree(spans);
  const totals = tokenTotal(spans);
  const selectedSpan = spans.find((s) => s.id === selected) ?? null;

  return (
    <div className="p-4">
      <button className="mb-2 text-sm text-blue-700 underline" onClick={onBack}>
        Back to runs
      </button>
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <h2 className="font-mono text-lg font-semibold">{short(run.id)}</h2>
        <StatusBadge status={run.status} />
        <span className="text-sm text-gray-600">{run.agent_name}</span>
        <span className="text-sm text-gray-600">
          {totals.input} in / {totals.output} out
        </span>
        {cost && <span className="text-sm text-gray-600">est. {cost}</span>}
        {run.error_type && <span className="text-sm text-red-600">{run.error_type}</span>}
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <div>
          {roots.map((n) => (
            <SpanRow key={n.span.id} node={n} depth={0} selected={selected} onSelect={setSelected} />
          ))}
          {roots.length === 0 && <p className="text-sm text-gray-500">No spans recorded.</p>}
        </div>
        <div>{selectedSpan ? <SpanDetail span={selectedSpan} /> : <p className="text-sm text-gray-500">Select a span.</p>}</div>
      </div>
    </div>
  );
}

export default function App() {
  const [openRun, setOpenRun] = useState<string | null>(null);
  const [tab, setTab] = useState<"runs" | "evals">("runs");
  const [settingsTick, setSettingsTick] = useState(0);
  return (
    <div className="min-h-screen bg-white text-gray-900">
      <header className="flex items-center gap-4 border-b px-4 py-2">
        <h1 className="text-xl font-bold">TraceGuard</h1>
        <nav className="flex gap-2 text-sm">
          <button
            className={`rounded px-2 py-1 ${tab === "runs" ? "bg-gray-800 text-white" : "border"}`}
            onClick={() => setTab("runs")}
          >
            Runs
          </button>
          <button
            className={`rounded px-2 py-1 ${tab === "evals" ? "bg-gray-800 text-white" : "border"}`}
            onClick={() => setTab("evals")}
          >
            Evaluations
          </button>
        </nav>
      </header>
      <SettingsBar onSaved={() => setSettingsTick((t) => t + 1)} />
      <main key={settingsTick}>
        {tab === "evals" ? (
          <EvalsView onOpenRun={(id) => { setOpenRun(id); setTab("runs"); }} />
        ) : openRun ? (
          <TraceView runId={openRun} onBack={() => setOpenRun(null)} />
        ) : (
          <RunsList onOpen={setOpenRun} />
        )}
      </main>
    </div>
  );
}
