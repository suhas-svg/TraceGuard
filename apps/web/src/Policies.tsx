import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  createBudget, formatMicro, gwApi, listBudgets, updateBudget,
  type Budget, type McpServer, type Policy
} from "./api";
import {
  Alert, Badge, Button, Card, Empty, Field, Input, ListSkeleton, Page,
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

function ServerForm({ onDone, onError }: { onDone: () => void; onError: (m: string) => void }) {
  const [form, setForm] = useState({ name: "", base_url: "", auth_secret: "" });
  return (
    <Card className="mb-4 max-w-3xl p-4">
      <form
        className="flex flex-wrap items-end gap-3 text-sm"
        onSubmit={(e) => {
          e.preventDefault();
          gwApi.createServer({
            name: form.name,
            base_url: form.base_url,
            ...(form.auth_secret ? { auth_secret: form.auth_secret } : {})
          })
            .then(onDone)
            .catch((err) => onError(err instanceof Error ? err.message : "register failed"));
        }}
      >
        <Field label="Name">
          <Input aria-label="Server name" className="w-40" placeholder="local-tools" value={form.name}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} required />
        </Field>
        <Field label="Base URL">
          <Input aria-label="Server base url" className="w-72" placeholder="http://host:8092/mcp"
            value={form.base_url} onChange={(e) => setForm((f) => ({ ...f, base_url: e.target.value }))} required />
        </Field>
        <Field label="Auth secret (optional)">
          <Input aria-label="Server auth secret" className="w-44" value={form.auth_secret}
            onChange={(e) => setForm((f) => ({ ...f, auth_secret: e.target.value }))} />
        </Field>
        <Button variant="primary" type="submit">Register server</Button>
      </form>
    </Card>
  );
}

// Discovered tools with a quarantine toggle: a changed definition hash flips
// a tool off until a human puts it back, and that lives here too.
function ServerTools({ server, onError }: { server: McpServer; onError: (m: string) => void }) {
  const [tools, setTools] = useState<{ tool_name: string; quarantined: boolean }[] | null>(null);
  const [busy, setBusy] = useState("");
  const refresh = () =>
    gwApi.discover(server.id)
      .then((r) => setTools(r.tools ?? []))
      .catch((e) => onError(e instanceof Error ? e.message : "discover failed"));
  return (
    <div className="bg-ink-50/50 px-4 py-3">
      {tools === null ? (
        <Button size="sm" onClick={refresh}>Load tools</Button>
      ) : (
        <ul className="grid gap-1.5 text-xs">
          {tools.map((t) => (
            <li key={t.tool_name} className="flex items-center gap-2">
              <span className="font-mono text-ink-800">{t.tool_name}</span>
              <Badge tone={t.quarantined ? "bad" : "ok"}>{t.quarantined ? "quarantined" : "active"}</Badge>
              <Button
                size="sm"
                variant="ghost"
                disabled={busy === t.tool_name}
                onClick={() => {
                  setBusy(t.tool_name);
                  gwApi.quarantine(server.id, t.tool_name, !t.quarantined)
                    .then(refresh)
                    .catch((e) => onError(e instanceof Error ? e.message : "quarantine failed"))
                    .finally(() => setBusy(""));
                }}
              >
                {t.quarantined ? "Re-approve" : "Quarantine"}
              </Button>
            </li>
          ))}
          {tools.length === 0 && <li className="text-ink-500">No tools discovered.</li>}
        </ul>
      )}
    </div>
  );
}

function ServerRow({ server, onChanged, onError }: {
  server: McpServer; onChanged: () => void; onError: (m: string) => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <div className="flex items-center gap-3 px-4 py-2.5 text-sm">
        <span className="font-medium text-ink-900">{server.name}</span>
        <span className="truncate font-mono text-xs text-ink-500">{server.base_url}</span>
        <span className="ml-auto flex gap-2">
          <Button size="sm" variant="ghost" onClick={() => setOpen((v) => !v)}>
            {open ? "Hide tools" : "Tools"}
          </Button>
          <Button size="sm" onClick={() => gwApi.discover(server.id).then(onChanged).catch((e) => onError(String(e)))}>
            Rediscover
          </Button>
        </span>
      </div>
      {open && <ServerTools server={server} onError={onError} />}
    </div>
  );
}

function BudgetRow({ budget, onChanged, onError }: {
  budget: Budget; onChanged: () => void; onError: (m: string) => void;
}) {
  const [limit, setLimit] = useState((budget.limit_micro / 1_000_000).toFixed(2));
  const [effect, setEffect] = useState(budget.effect);
  const used = budget.spent_micro + budget.reserved_micro;
  return (
    <div className="flex flex-wrap items-center gap-3 px-4 py-2.5 text-sm">
      <Badge tone={budget.effect === "block" ? "bad" : "warn"}>{budget.effect}</Badge>
      <span className="font-mono text-xs text-ink-500">{budget.scope}</span>
      <span className="truncate font-mono text-xs text-ink-700" title={budget.ref_id}>
        {budget.ref_id.slice(0, 13)}…
      </span>
      <span className="tg-nums text-xs text-ink-500">
        {formatMicro(used)} / {formatMicro(budget.limit_micro)} · remaining {formatMicro(budget.remaining_micro)}
      </span>
      <span className="ml-auto flex items-center gap-2">
        <Input aria-label={`Limit for ${budget.id}`} className="w-24" value={limit}
          onChange={(e) => setLimit(e.target.value)} />
        <Select aria-label={`Effect for ${budget.id}`} value={effect}
          onChange={(e) => setEffect(e.target.value)}>
          <option value="warn">warn</option>
          <option value="block">block</option>
        </Select>
        <Button size="sm" onClick={() => {
          updateBudget(budget.id, {
            limit_micro: Math.max(0, Math.round(Number(limit || "0") * 1_000_000)),
            effect
          })
            .then(onChanged)
            .catch((e) => onError(e instanceof Error ? e.message : "update failed"));
        }}>
          Save
        </Button>
      </span>
    </div>
  );
}

function BudgetsSection({ onError }: { onError: (m: string) => void }) {
  const queryClient = useQueryClient();
  const query = useQuery({ queryKey: ["budgets"], queryFn: listBudgets });
  const rows = query.data?.items ?? [];
  const [form, setForm] = useState({ scope: "run", ref_id: "", limit: "1.00", effect: "warn" });
  const reload = () => queryClient.invalidateQueries({ queryKey: ["budgets"] });
  return (
    <>
      <h3 className="mb-2 mt-6 text-sm font-semibold text-ink-700">Budgets</h3>
      <Card className="mb-4 p-4">
        <form
          className="flex flex-wrap items-end gap-3 text-sm"
          onSubmit={(e) => {
            e.preventDefault();
            createBudget({
              scope: form.scope, ref_id: form.ref_id,
              limit_micro: Math.max(0, Math.round(Number(form.limit || "0") * 1_000_000)),
              effect: form.effect
            })
              .then(() => { setForm((f) => ({ ...f, ref_id: "" })); reload(); })
              .catch((err) => onError(err instanceof Error ? err.message : "create failed"));
          }}
        >
          <Field label="Scope">
            <Select aria-label="Budget scope" value={form.scope}
              onChange={(e) => setForm((f) => ({ ...f, scope: e.target.value }))}>
              <option value="run">run</option>
              <option value="agent">agent</option>
            </Select>
          </Field>
          <Field label="Reference id">
            <Input aria-label="Budget reference" className="w-72" placeholder="run or agent uuid"
              value={form.ref_id} onChange={(e) => setForm((f) => ({ ...f, ref_id: e.target.value }))} required />
          </Field>
          <Field label="Limit ($)">
            <Input aria-label="Budget limit" className="w-28" value={form.limit}
              onChange={(e) => setForm((f) => ({ ...f, limit: e.target.value }))} />
          </Field>
          <Field label="Effect">
            <Select aria-label="Budget effect" value={form.effect}
              onChange={(e) => setForm((f) => ({ ...f, effect: e.target.value }))}>
              <option value="warn">warn</option>
              <option value="block">block</option>
            </Select>
          </Field>
          <Button variant="primary" type="submit">Add budget</Button>
        </form>
      </Card>
      <Card className="mb-5 divide-y divide-ink-100">
        {query.isPending && <p className="px-4 py-3 text-sm text-ink-500">Loading budgets...</p>}
        {!query.isPending && rows.length === 0 && (
          <p className="px-4 py-3 text-sm text-ink-500">No budgets yet.</p>
        )}
        {rows.map((b) => (
          <BudgetRow key={b.id} budget={b} onChanged={reload} onError={onError} />
        ))}
      </Card>
    </>
  );
}

function AuditSection() {
  const query = useQuery({ queryKey: ["audit-events"], queryFn: () => gwApi.audit() });
  const items = (query.data?.items ?? []).slice(0, 50);
  return (
    <>
      <h3 className="mb-2 mt-6 text-sm font-semibold text-ink-700">Audit history</h3>
      {query.isPending ? (
        <ListSkeleton rows={3} label="Loading audit events..." />
      ) : items.length === 0 ? (
        <Empty hint="No audit events yet. Decisions, approvals, and executions land here." />
      ) : (
        <Card className="mb-5 divide-y divide-ink-100">
          {items.map((e) => (
            <div key={e.id} className="flex flex-wrap items-center gap-3 px-4 py-2 text-xs">
              <span className="tg-nums text-ink-500">{new Date(e.timestamp).toLocaleString()}</span>
              <span className="font-mono text-ink-800">{e.action}</span>
              <Badge tone={e.result === "success" ? "ok" : e.result === "failed" || e.result === "denied" ? "bad" : "mute"}>
                {e.result}
              </Badge>
              <span className="truncate font-mono text-ink-500" title={e.resource_id}>
                {e.resource_type}:{e.resource_id.slice(0, 8)}
              </span>
              <span className="text-ink-500">{e.actor_type}</span>
            </div>
          ))}
        </Card>
      )}
    </>
  );
}

export default function PoliciesView() {
  const [editing, setEditing] = useState<Policy | null>(null);
  const [showNew, setShowNew] = useState(false);
  const [showServer, setShowServer] = useState(false);
  const [error, setError] = useState("");
  const queryClient = useQueryClient();
  const serversQuery = useQuery({ queryKey: ["mcp-servers"], queryFn: () => gwApi.servers() });
  const policiesQuery = useQuery({ queryKey: ["policies"], queryFn: () => gwApi.policies() });
  const servers = serversQuery.data?.items ?? [];
  const policies = policiesQuery.data?.items ?? [];
  const loadError = serversQuery.error ?? policiesQuery.error;
  const loadFailed = loadError ? (loadError instanceof Error ? loadError.message : "load failed") : "";

  const reload = () => queryClient.invalidateQueries();

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
      {(error || loadFailed) && <Alert>{error || loadFailed}</Alert>}
      <div className="mb-2 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-ink-700">Upstream servers</h3>
        <Button size="sm" variant="ghost" onClick={() => setShowServer((v) => !v)}>
          {showServer ? "Cancel" : "Register server"}
        </Button>
      </div>
      {showServer && (
        <ServerForm
          onDone={() => { setShowServer(false); reload(); }}
          onError={setError}
        />
      )}
      <Card className="mb-5 divide-y divide-ink-100">
        {servers.length === 0 && <p className="px-4 py-3 text-sm text-ink-500">No servers registered.</p>}
        {servers.map((s) => (
          <ServerRow key={s.id} server={s} onChanged={reload} onError={setError} />
        ))}
      </Card>
      <h3 className="mb-2 text-sm font-semibold text-ink-700">Rules</h3>
      {showNew && <PolicyForm servers={servers} onDone={() => { setShowNew(false); reload(); }} />}
      {editing && (
        // Keyed by rule id: without it React reuses the instance and the form
        // keeps the previous rule's fields, so saving writes them onto the
        // rule just clicked.
        <PolicyForm key={editing.id} servers={servers} initial={editing}
          onDone={() => { setEditing(null); reload(); }} />
      )}
      {policiesQuery.isPending ? (
        <ListSkeleton rows={3} label="Loading rules..." />
      ) : policies.length === 0 ? (
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
      <BudgetsSection onError={setError} />
      <AuditSection />
    </Page>
  );
}
