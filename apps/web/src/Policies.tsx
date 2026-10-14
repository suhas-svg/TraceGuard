import { useEffect, useState } from "react";
import { gwApi, type McpServer, type Policy } from "./api";
import {
  Alert, Badge, Button, Card, Empty, Field, Input, Page,
  Select, Table, Td, Th
} from "./components";

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
    <Card className="mb-4 max-w-2xl p-4">
      <form
        className="grid gap-3 text-sm"
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
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label="Rule name">
            <Input aria-label="Rule name" placeholder="no-shell" value={form.name}
              onChange={(e) => set("name", e.target.value)} required />
          </Field>
          <Field label="Effect">
            <Select aria-label="Effect" value={form.effect} onChange={(e) => set("effect", e.target.value)}>
              <option value="allow">allow</option>
              <option value="deny">deny</option>
              <option value="require_approval">require approval</option>
            </Select>
          </Field>
          <Field label="Priority">
            <Input aria-label="Priority" placeholder="0" value={form.priority}
              onChange={(e) => set("priority", e.target.value)} />
          </Field>
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Server">
            <Select aria-label="Server" value={form.server_id} onChange={(e) => set("server_id", e.target.value)}>
              <option value="">all servers</option>
              {servers.map((s) => (
                <option key={s.id} value={s.id}>{s.name}</option>
              ))}
            </Select>
          </Field>
          <Field label="Tool (blank = all)">
            <Input aria-label="Tool name" placeholder="read_file" value={form.tool_name}
              onChange={(e) => set("tool_name", e.target.value)} />
          </Field>
        </div>
        <Field label="Conditions JSON">
          <textarea aria-label="Conditions JSON"
            className="rounded-lg border border-ink-200 px-2.5 py-1.5 font-mono text-xs focus:border-brand-400"
            rows={3}
            placeholder='{"required":["path"],"arguments":{"path":{"path_within":"/data"}}}'
            value={form.conditions} onChange={(e) => set("conditions", e.target.value)} />
        </Field>
        {error && <Alert>{error}</Alert>}
        <div>
          <Button variant="primary" type="submit">
            {initial ? `Save as v${initial.version + 1}` : "Create rule"}
          </Button>
        </div>
      </form>
    </Card>
  );
}

const effectTone: Record<string, "ok" | "bad" | "warn"> = {
  allow: "ok",
  deny: "bad",
  require_approval: "warn"
};

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
    <Page
      title="Tool policies"
      sub="Deny wins, priority orders ties. Changes version; decisions cite the exact version."
      actions={
        <Button variant="primary" onClick={() => { setEditing(null); setShowNew((v) => !v); }}>
          {showNew ? "Cancel" : "New rule"}
        </Button>
      }
    >
      {error && <Alert>{error}</Alert>}
      <h3 className="mb-2 text-sm font-semibold text-ink-700">Upstream servers</h3>
      <Card className="mb-5 divide-y divide-ink-100">
        {servers.length === 0 && <p className="px-4 py-3 text-sm text-ink-500">No servers registered.</p>}
        {servers.map((s) => (
          <div key={s.id} className="flex items-center gap-3 px-4 py-2.5 text-sm">
            <span className="font-medium text-ink-900">{s.name}</span>
            <span className="truncate font-mono text-xs text-ink-400">{s.base_url}</span>
            <span className="ml-auto">
              <Button size="sm" onClick={() => gwApi.discover(s.id).then(() => reload()).catch((e) => setError(String(e)))}>
                Rediscover
              </Button>
            </span>
          </div>
        ))}
      </Card>
      <h3 className="mb-2 text-sm font-semibold text-ink-700">Rules</h3>
      {showNew && <PolicyForm servers={servers} onDone={() => { setShowNew(false); reload(); }} />}
      {editing && (
        <PolicyForm servers={servers} initial={editing} onDone={() => { setEditing(null); reload(); }} />
      )}
      {policies.length === 0 ? (
        <Empty hint="No rules yet. Unknown tools are denied by default." />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Rule</Th>
              <Th>Effect</Th>
              <Th>Tool</Th>
              <Th>Priority</Th>
              <Th>Version</Th>
              <Th><span className="sr-only">Actions</span></Th>
            </tr>
          </thead>
          <tbody>
            {policies.map((p) => (
              <tr key={p.id} className="transition-colors hover:bg-ink-50/70">
                <Td className="font-medium">{p.name}</Td>
                <Td><Badge tone={effectTone[p.effect] ?? "mute"}>{p.effect}</Badge></Td>
                <Td className="font-mono text-[13px]">{p.tool_name ?? "all"}</Td>
                <Td>{p.priority}</Td>
                <Td>v{p.version}</Td>
                <Td>
                  <Button size="sm" variant="ghost" onClick={() => { setShowNew(false); setEditing(p); }}>
                    Edit
                  </Button>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Page>
  );
}
