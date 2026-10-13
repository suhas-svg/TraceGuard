import { useEffect, useState } from "react";
import { gwApi, type McpServer, type Policy } from "./api";

const emptyForm = { name: "", server_id: "", tool_name: "", effect: "allow", priority: "0", conditions: "{}" };

function PolicyForm({
  servers,
  initial,
  onDone
}: {
  servers: McpServer[];
  initial?: Policy;
  onDone: () => void;
}) {
  const [form, setForm] = useState(
    initial
      ? { name: initial.name, server_id: initial.server_id ?? "", tool_name: initial.tool_name ?? "",
          effect: initial.effect, priority: String(initial.priority),
          conditions: JSON.stringify(initial.conditions ?? {}) }
      : emptyForm
  );
  const [error, setError] = useState("");
  const set = (k: string, v: string) => setForm((f) => ({ ...f, [k]: v }));

  return (
    <form
      className="mb-3 grid max-w-2xl gap-2 rounded border p-3 text-sm"
      onSubmit={async (e) => {
        e.preventDefault();
        setError("");
        let conditions: Record<string, unknown> = {};
        try {
          conditions = form.conditions.trim() ? JSON.parse(form.conditions) : {};
        } catch {
          setError("conditions must be valid JSON");
          return;
        }
        const body = { name: form.name, server_id: form.server_id || null,
          tool_name: form.tool_name || null, effect: form.effect,
          priority: Number(form.priority) || 0, conditions };
        try {
          if (initial) await gwApi.updatePolicy(initial.id, body);
          else await gwApi.createPolicy(body);
          onDone();
        } catch (err) {
          setError(err instanceof Error ? err.message : "save failed");
        }
      }}
    >
      <div className="flex gap-2">
        <input aria-label="Rule name" className="w-48 rounded border px-2 py-1" placeholder="rule name"
          value={form.name} onChange={(e) => set("name", e.target.value)} required />
        <select aria-label="Effect" className="rounded border px-2 py-1" value={form.effect} onChange={(e) => set("effect", e.target.value)}>
          <option value="allow">allow</option>
          <option value="deny">deny</option>
          <option value="require_approval">require approval</option>
        </select>
        <input aria-label="Priority" className="w-20 rounded border px-2 py-1" placeholder="priority"
          value={form.priority} onChange={(e) => set("priority", e.target.value)} />
      </div>
      <div className="flex gap-2">
        <select aria-label="Server" className="rounded border px-2 py-1" value={form.server_id} onChange={(e) => set("server_id", e.target.value)}>
          <option value="">all servers</option>
          {servers.map((s) => (
            <option key={s.id} value={s.id}>{s.name}</option>
          ))}
        </select>
        <input aria-label="Tool name" className="w-48 rounded border px-2 py-1" placeholder="tool (blank = all)"
          value={form.tool_name} onChange={(e) => set("tool_name", e.target.value)} />
      </div>
      <textarea aria-label="Conditions JSON" className="rounded border px-2 py-1 font-mono text-xs" rows={3}
        placeholder='{"required":["path"],"arguments":{"path":{"path_within":"/data"}}}'
        value={form.conditions} onChange={(e) => set("conditions", e.target.value)} />
      {error && <p className="text-red-700">{error}</p>}
      <div>
        <button className="rounded bg-gray-800 px-3 py-1 text-white" type="submit">
          {initial ? `Save as v${initial.version + 1}` : "Create rule"}
        </button>
      </div>
    </form>
  );
}

export default function PoliciesView() {
  const [servers, setServers] = useState<McpServer[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [editing, setEditing] = useState<Policy | null>(null);
  const [showNew, setShowNew] = useState(false);
  const [error, setError] = useState("");

  const reload = () =>
    Promise.all([gwApi.servers(), gwApi.policies()])
      .then(([s, p]) => {
        setServers(s.items);
        setPolicies(p.items);
      })
      .catch((e) => setError(e instanceof Error ? e.message : "load failed"));

  useEffect(() => {
    reload();
  }, []);

  return (
    <div className="p-4">
      <h2 className="mb-3 text-lg font-semibold">Tool policies</h2>
      {error && <p className="mb-2 text-sm text-red-700">{error}</p>}
      <h3 className="mb-1 text-sm font-semibold text-gray-600">Upstream servers</h3>
      {servers.map((s) => (
        <div key={s.id} className="mb-1 flex items-center gap-2 text-sm">
          <span className="font-medium">{s.name}</span>
          <span className="font-mono text-gray-500">{s.base_url}</span>
          <button
            className="rounded border px-2 py-0.5 text-xs"
            onClick={() => gwApi.discover(s.id).then(() => reload()).catch((e) => setError(String(e)))}
          >
            Rediscover
          </button>
        </div>
      ))}
      <h3 className="mb-1 mt-4 text-sm font-semibold text-gray-600">Rules (deny wins, priority orders ties)</h3>
      <button className="mb-2 rounded border px-2 py-1 text-sm" onClick={() => { setEditing(null); setShowNew((v) => !v); }}>
        {showNew ? "Cancel" : "New rule"}
      </button>
      {showNew && <PolicyForm servers={servers} onDone={() => { setShowNew(false); reload(); }} />}
      {editing && (
        <PolicyForm servers={servers} initial={editing}
          onDone={() => { setEditing(null); reload(); }} />
      )}
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b text-left text-gray-500">
            <th className="py-1 pr-2">Rule</th>
            <th className="py-1 pr-2">Effect</th>
            <th className="py-1 pr-2">Tool</th>
            <th className="py-1 pr-2">Priority</th>
            <th className="py-1 pr-2">Version</th>
            <th className="py-1 pr-2"></th>
          </tr>
        </thead>
        <tbody>
          {policies.map((p) => (
            <tr key={p.id} className="border-b">
              <td className="py-1 pr-2 font-medium">{p.name}</td>
              <td className="py-1 pr-2">{p.effect}</td>
              <td className="py-1 pr-2 font-mono">{p.tool_name ?? "all"}</td>
              <td className="py-1 pr-2">{p.priority}</td>
              <td className="py-1 pr-2">v{p.version}</td>
              <td className="py-1 pr-2">
                <button className="text-blue-700 underline" onClick={() => { setShowNew(false); setEditing(p); }}>
                  Edit
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
