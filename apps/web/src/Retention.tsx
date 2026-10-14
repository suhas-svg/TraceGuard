import { useEffect, useState } from "react";
import { opsApi, type RetentionRule, type RetentionRun } from "./api";

const TARGETS = ["runs", "approvals", "webhook_deliveries"];

export default function RetentionView() {
  const [rules, setRules] = useState<RetentionRule[]>([]);
  const [runs, setRuns] = useState<RetentionRun[]>([]);
  const [form, setForm] = useState({ name: "", target: "runs", older_than_days: "30" });
  const [error, setError] = useState("");
  const [lastRun, setLastRun] = useState<Record<string, number> | null>(null);

  const reload = () =>
    Promise.all([opsApi.retentionRules(), opsApi.retentionRuns()])
      .then(([r, h]) => {
        setRules(r.items);
        setRuns(h.items);
      })
      .catch((e) => setError(e instanceof Error ? e.message : "load failed"));

  useEffect(() => {
    reload();
  }, []);

  return (
    <div className="p-4">
      <h2 className="mb-3 text-lg font-semibold">Retention</h2>
      {error && <p className="mb-2 text-sm text-red-700">{error}</p>}
      <form
        className="mb-4 flex max-w-2xl flex-wrap items-end gap-2 rounded border p-3 text-sm"
        onSubmit={async (e) => {
          e.preventDefault();
          setError("");
          try {
            await opsApi.createRetentionRule({
              name: form.name, target: form.target, older_than_days: Number(form.older_than_days) || 30
            });
            setForm({ name: "", target: "runs", older_than_days: "30" });
            reload();
          } catch (err) {
            setError(err instanceof Error ? err.message : "save failed");
          }
        }}
      >
        <label className="flex flex-col">
          <span className="text-xs text-gray-500">Rule name</span>
          <input className="w-44 rounded border px-2 py-1" value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })} required />
        </label>
        <label className="flex flex-col">
          <span className="text-xs text-gray-500">Target</span>
          <select className="rounded border px-2 py-1" value={form.target}
            onChange={(e) => setForm({ ...form, target: e.target.value })}>
            {TARGETS.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </label>
        <label className="flex flex-col">
          <span className="text-xs text-gray-500">Older than (days)</span>
          <input className="w-24 rounded border px-2 py-1" value={form.older_than_days}
            onChange={(e) => setForm({ ...form, older_than_days: e.target.value })} />
        </label>
        <button className="rounded bg-gray-800 px-3 py-1 text-white" type="submit">
          Add rule
        </button>
      </form>
      {rules.map((r) => (
        <div key={r.id} className="mb-1 flex items-center gap-2 text-sm">
          <span className="font-medium">{r.name}</span>
          <span className="font-mono text-gray-500">{r.target} older than {r.older_than_days}d</span>
          <button
            className="rounded border px-2 py-0.5 text-xs"
            onClick={() => opsApi.updateRetentionRule(r.id, { enabled: !r.enabled }).then(reload).catch((e) => setError(String(e)))}
          >
            {r.enabled ? "Disable" : "Enable"}
          </button>
          <button
            className="text-red-700 underline"
            onClick={() => opsApi.deleteRetentionRule(r.id).then(reload).catch((e) => setError(String(e)))}
          >
            Delete
          </button>
        </div>
      ))}
      <div className="mt-4">
        <button
          className="rounded bg-gray-800 px-3 py-1 text-sm text-white"
          onClick={() => opsApi.runRetention().then((r) => { setLastRun(r.deleted); reload(); }).catch((e) => setError(String(e)))}
        >
          Run now
        </button>
        {lastRun && (
          <p className="mt-1 text-sm text-gray-600">
            Deleted: {Object.entries(lastRun).map(([k, v]) => `${k}: ${v}`).join(", ") || "nothing"}
          </p>
        )}
      </div>
      <h3 className="mb-1 mt-4 text-sm font-semibold text-gray-600">Run history</h3>
      {runs.map((r) => (
        <div key={r.id} className="mb-1 text-sm">
          <span className="font-mono text-gray-500">{new Date(r.started_at).toLocaleString()}</span>
          <span className="ml-2">{r.status}</span>
          <span className="ml-2 text-gray-600">
            {Object.entries(r.deleted_counts).map(([k, v]) => `${k}: ${v}`).join(", ")}
          </span>
        </div>
      ))}
    </div>
  );
}
