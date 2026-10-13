import { useEffect, useState } from "react";
import { gwApi, type Approval } from "./api";

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
    <div className="mb-2 rounded border p-3 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono font-medium">{a.tool_name}</span>
        <span className={`rounded px-2 py-0.5 text-xs font-medium ${
          a.status === "pending" ? "bg-amber-100 text-amber-800"
          : a.status === "approved" ? "bg-green-100 text-green-800"
          : "bg-gray-100 text-gray-800"}`}>
          {a.status}
        </span>
        <span className="text-gray-500">from {a.caller}</span>
        <span className="text-gray-500">expires {new Date(a.expires_at).toLocaleString()}</span>
      </div>
      <pre className="mt-1 overflow-auto rounded bg-gray-50 p-2 font-mono text-xs">
        {JSON.stringify(a.args, null, 2)}
      </pre>
      {a.decision_reason && <p className="mt-1 text-gray-600">Reason: {a.decision_reason}</p>}
      {error && <p className="mt-1 text-red-700">{error}</p>}
      {result && <p className="mt-1 text-green-700">{result}</p>}
      {a.status === "pending" && (
        <div className="mt-2 flex items-center gap-2">
          <input aria-label="Decision reason" className="w-64 rounded border px-2 py-1"
            placeholder="reason (optional)" value={reason} onChange={(e) => setReason(e.target.value)} />
          <button className="rounded bg-green-700 px-3 py-1 text-white" onClick={() => decide(true)}>
            Approve
          </button>
          <button className="rounded bg-red-700 px-3 py-1 text-white" onClick={() => decide(false)}>
            Deny
          </button>
        </div>
      )}
      {a.status === "approved" && (
        <button className="mt-2 rounded border px-3 py-1" onClick={runNow}>
          Run now
        </button>
      )}
    </div>
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
    <div className="p-4">
      <div className="mb-3 flex items-center gap-2">
        <h2 className="text-lg font-semibold">Approvals</h2>
        <select aria-label="Filter approvals" className="rounded border px-2 py-1 text-sm"
          value={filter} onChange={(e) => setFilter(e.target.value)}>
          <option value="pending">pending</option>
          <option value="">all</option>
          <option value="approved">approved</option>
          <option value="denied">denied</option>
          <option value="expired">expired</option>
          <option value="consumed">consumed</option>
        </select>
        <button className="rounded border px-2 py-1 text-sm" onClick={reload}>
          Refresh
        </button>
      </div>
      {error && <p className="mb-2 text-sm text-red-700">{error}</p>}
      {items.length === 0 && <p className="text-sm text-gray-500">Nothing here.</p>}
      {items.map((a) => (
        <ApprovalCard key={a.id} a={a} onChanged={reload} />
      ))}
    </div>
  );
}
