import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { opsApi } from "./api";
import {
  Alert, Button, Card, Empty, Field, Input, Page,
  Select, StatusBadge
} from "./components";

const TARGETS = ["runs", "approvals", "webhook_deliveries", "spans"];

export default function RetentionView() {
  const [form, setForm] = useState({ name: "", target: "runs", older_than_days: "30", max_rows: "" });
  const [error, setError] = useState("");
  const [lastRun, setLastRun] = useState<Record<string, number> | null>(null);
  const queryClient = useQueryClient();
  const rulesQuery = useQuery({ queryKey: ["retention-rules"], queryFn: () => opsApi.retentionRules() });
  const runsQuery = useQuery({ queryKey: ["retention-runs"], queryFn: () => opsApi.retentionRuns() });
  const rules = rulesQuery.data?.items ?? [];
  const runs = runsQuery.data?.items ?? [];
  const loadError = rulesQuery.error ?? runsQuery.error;
  const loadFailed = loadError ? (loadError instanceof Error ? loadError.message : "load failed") : "";

  const reload = () => queryClient.invalidateQueries();

  return (
    <Page
      title="Retention"
      sub="Age out runs, terminal approvals, delivery logs, and whole traces. Policies, decisions, audit, and money are never targets."
      actions={
        <Button variant="primary"
          onClick={() => opsApi.runRetention().then((r) => { setLastRun(r.deleted); reload(); }).catch((e) => setError(String(e)))}>
          Run now
        </Button>
      }
    >
      {(error || loadFailed) && <Alert>{error || loadFailed}</Alert>}
      {lastRun && (
        <Card className="mb-4 border-ok-700/20 bg-ok-100/50 px-4 py-2.5 text-sm text-ok-800">
          Deleted: {Object.entries(lastRun).map(([k, v]) => `${k}: ${v}`).join(", ") || "nothing"}
        </Card>
      )}
      <Card className="mb-5 max-w-2xl p-4">
        <form
          className="flex flex-wrap items-end gap-3 text-sm"
          onSubmit={async (e) => {
            e.preventDefault();
            setError("");
            try {
              await opsApi.createRetentionRule({
                name: form.name, target: form.target, older_than_days: Number(form.older_than_days) || 30,
                max_rows: form.max_rows ? Number(form.max_rows) : undefined
              });
              setForm({ name: "", target: "runs", older_than_days: "30", max_rows: "" });
              reload();
            } catch (err) {
              setError(err instanceof Error ? err.message : "save failed");
            }
          }}
        >
          <Field label="Rule name">
            <Input className="w-44" value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })} required />
          </Field>
          <Field label="Target">
            <Select value={form.target} onChange={(e) => setForm({ ...form, target: e.target.value })}>
              {TARGETS.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </Select>
          </Field>
          <Field label="Older than (days)">
            <Input className="w-24" value={form.older_than_days}
              onChange={(e) => setForm({ ...form, older_than_days: e.target.value })} />
          </Field>
          {form.target === "spans" && (
            <Field label="Row cap (spans)">
              <Input className="w-28" placeholder="100000" value={form.max_rows}
                onChange={(e) => setForm({ ...form, max_rows: e.target.value })} />
            </Field>
          )}
          <Button variant="primary" type="submit">Add rule</Button>
        </form>
      </Card>
      <h3 className="mb-2 text-sm font-semibold text-ink-700">Rules</h3>
      {rules.length === 0 ? (
        <Empty hint="No rules yet. Without one, tables grow forever." />
      ) : (
        <Card className="mb-5 divide-y divide-ink-100">
          {rules.map((r) => (
            <div key={r.id} className="flex flex-wrap items-center gap-2 px-4 py-2.5 text-sm">
              <span className="font-medium text-ink-900">{r.name}</span>
              <span className="font-mono text-xs text-ink-500">
                {r.target} older than {r.older_than_days}d
                {r.max_rows != null ? ` · cap ${Number(r.max_rows).toLocaleString()} rows` : ""}
              </span>
              <StatusBadge status={r.enabled ? "success" : "cancelled"} />
              <span className="ml-auto flex gap-1">
                <Button size="sm" variant="ghost"
                  onClick={() => opsApi.updateRetentionRule(r.id, { enabled: !r.enabled }).then(reload).catch((e) => setError(String(e)))}>
                  {r.enabled ? "Disable" : "Enable"}
                </Button>
                <Button size="sm" variant="ghost" className="text-bad-700 hover:bg-bad-100"
                  onClick={() => opsApi.deleteRetentionRule(r.id).then(reload).catch((e) => setError(String(e)))}>
                  Delete
                </Button>
              </span>
            </div>
          ))}
        </Card>
      )}
      <h3 className="mb-2 text-sm font-semibold text-ink-700">Run history</h3>
      {runs.length === 0 ? (
        <Empty hint="No retention runs yet." />
      ) : (
        <Card className="divide-y divide-ink-100">
          {runs.map((r) => (
            <div key={r.id} className="flex flex-wrap items-center gap-2 px-4 py-2 text-sm">
              <span className="font-mono text-xs text-ink-500">{new Date(r.started_at).toLocaleString()}</span>
              <StatusBadge status={r.status} />
              <span className="tg-nums text-ink-500">
                {Object.entries(r.deleted_counts).map(([k, v]) => `${k}: ${v}`).join(", ")}
              </span>
            </div>
          ))}
        </Card>
      )}
    </Page>
  );
}
