import { useEffect, useState } from "react";
import { gwApi, type Approval } from "./api";
import {
  Alert, Button, Card, Empty, Input, Page,
  Segmented, StatusBadge
} from "./components";

function ApprovalCard({ a, onChanged }: { a: Approval; onChanged: () => void }) {
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const [result, setResult] = useState("");

  const decide = async (approved: boolean) => {
    setError("");
    try {
      await gwApi.decide(a.id, approved, reason);
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : "decision failed");
    }
  };

  // Run now retries the exact bound call through the gateway. The approval is
  // consumed by the execution, so a replay afterwards gets a 410.
  const runNow = async () => {
    setError("");
    setResult("");
    try {
      const r = await gwApi.call({
        server_id: a.server_id, tool: a.tool_name, arguments: a.args,
        caller: a.caller, request_id: a.request_id, approval_id: a.id
      });
      setResult(r.result !== undefined ? `executed: ${JSON.stringify(r.result).slice(0, 200)}` : `status: ${r.status}`);
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : "call failed");
    }
  };

  return (
    <Card className="mb-3 p-4 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono font-semibold text-ink-900">{a.tool_name}</span>
        <StatusBadge status={a.status} />
        <span className="text-ink-500">from {a.caller}</span>
        <span className="ml-auto text-xs text-ink-400">expires {new Date(a.expires_at).toLocaleString()}</span>
      </div>
      <pre className="mt-2 max-h-48 overflow-auto rounded-lg bg-[#0b0e16] p-3 font-mono text-xs text-slate-100">
        {JSON.stringify(a.args, null, 2)}
      </pre>
      {a.decision_reason && <p className="mt-2 text-ink-500">Reason: {a.decision_reason}</p>}
      {error && <div className="mt-2"><Alert>{error}</Alert></div>}
      {result && <p className="mt-2 text-sm text-ok-800">{result}</p>}
      {a.status === "pending" && (
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <Input aria-label="Decision reason" className="w-64"
            placeholder="reason (optional)" value={reason} onChange={(e) => setReason(e.target.value)} />
          <Button variant="primary" onClick={() => decide(true)}>Approve</Button>
          <Button variant="danger" onClick={() => decide(false)}>Deny</Button>
        </div>
      )}
      {a.status === "approved" && (
        <div className="mt-3">
          <Button onClick={runNow}>Run now</Button>
        </div>
      )}
    </Card>
  );
}

export default function ApprovalsView() {
  const [filter, setFilter] = useState("pending");
  const [items, setItems] = useState<Approval[]>([]);
  const [error, setError] = useState("");

  const reload = () =>
    gwApi.approvals(filter || undefined)
      .then((r) => setItems(r.items))
      .catch((e) => setError(e instanceof Error ? e.message : "load failed"));

  useEffect(() => {
    reload();
  }, [filter]);

  return (
    <Page
      title="Approvals"
      sub="Held tool calls wait here. Nothing executes until a human decides."
      actions={
        <>
          <Segmented
            label="Filter approvals"
            value={filter}
            onChange={(v) => setFilter(v)}
            options={[
              { value: "pending", label: "Pending" },
              { value: "", label: "All" },
              { value: "approved", label: "Approved" },
              { value: "denied", label: "Denied" },
              { value: "expired", label: "Expired" },
              { value: "consumed", label: "Consumed" }
            ]}
          />
          <Button onClick={reload}>Refresh</Button>
        </>
      }
    >
      {error && <Alert>{error}</Alert>}
      {items.length === 0 && <Empty hint="Nothing here. Held calls appear under the pending filter." />}
      {items.map((a) => (
        <ApprovalCard key={a.id} a={a} onChanged={reload} />
      ))}
    </Page>
  );
}
