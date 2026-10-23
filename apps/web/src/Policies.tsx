import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  adminApi, createBudget, formatMicro, gwApi, listBudgets, updateBudget,
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
            if (initial) await adminApi.updatePolicy(initial.id, body);
            else await adminApi.createPolicy(body);
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
        <p className="text-xs text-ink-500">
          The gateway decides these conditions itself. schema, regex, enum, and max_length are
          enforced here. path_within requires a server- and tool-scoped rule and a pinned
          executor attestation (io.traceguard/path-confinement); calls are refused when the
          executor does not attest to enforcing it, so gateway string comparison is never the
          boundary.
        </p>
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
  const [form, setForm] = useState({ name: "", base_url: "", secret_ref: "" });
  return (
    <Card className="mb-4 max-w-3xl p-4">
      <form
        className="flex flex-wrap items-end gap-3 text-sm"
        onSubmit={(e) => {
          e.preventDefault();
          adminApi.createServer({
            name: form.name,
            base_url: form.base_url,
            ...(form.secret_ref ? { secret_ref: form.secret_ref } : {})
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
        <Field label="Secret ref (optional)">
          <Input aria-label="Server secret reference" className="w-56" placeholder="env:UPSTREAM_TOKEN"
            value={form.secret_ref}
            onChange={(e) => setForm((f) => ({ ...f, secret_ref: e.target.value }))} />
        </Field>
        <Button variant="primary" type="submit">Register server</Button>
      </form>
    </Card>
  );
}

type ServerToolRow = {
  tool_name: string;
  quarantined: boolean;
  quarantine_reason?: string | null;
  definition?: Record<string, unknown> | null;
  previous_definition?: Record<string, unknown> | null;
  definition_hash?: string | null;
  previous_hash?: string | null;
  active_pin_id?: string | null;
  active_pin_version?: number | null;
  candidate_pin_id?: string | null;
  candidate_pin_version?: number | null;
  candidate_status?: "candidate" | "pending_review" | "approved" | "superseded" | null;
};

// FR-017: a quarantined tool shows its reviewer what changed — the previous
// hash beside the new one, and which definition fields differ.
const DIFF_FIELDS = ["title", "description", "inputSchema", "outputSchema", "annotations", "icons", "execution", "_meta"] as const;
function changedFields(prev: Record<string, unknown>, next: Record<string, unknown>): string[] {
  return DIFF_FIELDS.filter((f) => JSON.stringify(prev[f]) !== JSON.stringify(next[f]));
}
const shortHash = (h?: string | null) => (h ? `${h.slice(0, 12)}…` : "?");

// Discovered tools with a quarantine toggle: a changed definition hash flips
// a tool off until a human puts it back, and that lives here too.
function ServerTools({ server, onError }: { server: McpServer; onError: (m: string) => void }) {
  const [tools, setTools] = useState<ServerToolRow[] | null>(null);
  const [busy, setBusy] = useState("");
  const refresh = () =>
    adminApi.discover(server.id)
      .then((r) => setTools(r.tools ?? []))
      .catch((e) => onError(e instanceof Error ? e.message : "discover failed"));
  return (
    <div className="bg-ink-50/50 px-4 py-3">
      {tools === null ? (
        <Button size="sm" onClick={refresh}>Load tools</Button>
      ) : (
        <ul className="grid gap-1.5 text-xs">
          {tools.map((t) => (
            <li key={t.tool_name} className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-ink-800">{t.tool_name}</span>
              <Badge tone={t.quarantined ? "bad" : "ok"}>{t.quarantined ? "quarantined" : "active"}</Badge>
              {t.quarantined ? (
                t.candidate_status === "approved" ? (
                  <span className="text-[11px] text-ink-500">Awaiting signed publish</span>
                ) : t.candidate_pin_id ? (
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={busy === t.tool_name}
                    onClick={() => {
                      setBusy(t.tool_name);
                      const action = t.candidate_status === "pending_review"
                        ? adminApi.approvePin(t.candidate_pin_id!)
                        : adminApi.submitPinReview(t.candidate_pin_id!);
                      action
                        .then(refresh)
                        .catch((e) => onError(e instanceof Error ? e.message : "review failed"))
                        .finally(() => setBusy(""));
                    }}
                  >
                    {t.candidate_status === "pending_review"
                      ? "Approve for publication"
                      : "Submit for review"}
                  </Button>
                ) : t.active_pin_id ? (
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={busy === t.tool_name}
                    onClick={() => {
                      setBusy(t.tool_name);
                      adminApi.submitPinReview(t.active_pin_id!)
                        .then(refresh)
                        .catch((e) => onError(e instanceof Error ? e.message : "review failed"))
                        .finally(() => setBusy(""));
                    }}
                  >
                    Request re-review
                  </Button>
                ) : null
              ) : (
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={busy === t.tool_name}
                  onClick={() => {
                    setBusy(t.tool_name);
                    adminApi.quarantine(server.id, t.tool_name, true)
                      .then(refresh)
                      .catch((e) => onError(e instanceof Error ? e.message : "quarantine failed"))
                      .finally(() => setBusy(""));
                  }}
                >
                  Quarantine
                </Button>
              )}
              {t.quarantined && t.previous_definition && t.definition && (
                <div className="w-full text-[11px] text-ink-500">
                  <span className="font-mono">{shortHash(t.previous_hash)}</span> →{" "}
                  <span className="font-mono">{shortHash(t.definition_hash)}</span>
                  {changedFields(t.previous_definition, t.definition).length > 0 && (
                    <> · changed: {changedFields(t.previous_definition, t.definition).join(", ")}</>
                  )}
                  {t.quarantine_reason && <> · {t.quarantine_reason}</>}
                </div>
              )}
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
          <Button size="sm" onClick={() => adminApi.discover(server.id).then(onChanged).catch((e) => onError(String(e)))}>
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
  const used = Number(budget.spent_micro) + Number(budget.reserved_micro);
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

function SignedPolicySection() {
  const query = useQuery({ queryKey: ["policy-versions"], queryFn: () => gwApi.policyVersions() });
  const items = query.data?.items ?? [];
  const active = items.find((v) => v.active);
  return (
    <>
      <h3 className="mb-2 mt-6 text-sm font-semibold text-ink-700">Signed policy</h3>
      <p className="mb-3 max-w-3xl text-xs text-ink-500">
        Rules above are drafts. Enforcement reads only the active signed bundle: an operator runs
        <span className="mx-1 font-mono">policy-publisher publish</span>
        to sign the current drafts and servers with the signing key, and a changed tool definition
        stays quarantined until a new bundle activates it.
      </p>
      {query.isPending ? (
        <ListSkeleton rows={2} label="Loading signed versions..." />
      ) : items.length === 0 ? (
        <Empty hint="Nothing published yet. Tool calls fail closed until policy-publisher publishes a signed policy." />
      ) : (
        <Card className="mb-5 divide-y divide-ink-100">
          {active && (
            <div className="flex flex-wrap items-center gap-3 px-4 py-3 text-xs">
              <Badge tone="ok">active</Badge>
              <span className="font-medium text-ink-800">v{active.version}</span>
              <span className="truncate font-mono text-ink-500" title={active.content_hash}>
                sha256 {active.content_hash.slice(0, 16)}...
              </span>
              <span className="text-ink-500">by {active.published_by}</span>
              <span className="tg-nums text-ink-500">{new Date(active.published_at).toLocaleString()}</span>
              {active.key_retired && <Badge tone="bad">key retired - republish</Badge>}
            </div>
          )}
          {items.filter((v) => !v.active).slice(0, 5).map((v) => (
            <div key={v.id} className="flex flex-wrap items-center gap-3 px-4 py-2 text-xs text-ink-500">
              <span className="font-medium text-ink-600">v{v.version}</span>
              <span className="truncate font-mono" title={v.content_hash}>
                sha256 {v.content_hash.slice(0, 16)}...
              </span>
              <span>by {v.published_by}</span>
              <span className="tg-nums">{new Date(v.published_at).toLocaleString()}</span>
            </div>
          ))}
        </Card>
      )}
    </>
  );
}

function AuditSection() {
  const query = useQuery({ queryKey: ["audit-events"], queryFn: () => gwApi.audit() });
  const [verification, setVerification] = useState<Awaited<ReturnType<typeof gwApi.auditVerify>> | null>(null);
  const [verifying, setVerifying] = useState(false);
  const items = (query.data?.items ?? []).slice(0, 50);
  return (
    <>
      <div className="mb-2 mt-6 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-ink-700">Audit history</h3>
        <Button
          size="sm"
          variant="ghost"
          disabled={verifying}
          onClick={async () => {
            setVerifying(true);
            try {
              setVerification(await gwApi.auditVerify());
            } finally {
              setVerifying(false);
            }
          }}
        >
          {verifying ? "Verifying..." : "Verify chain"}
        </Button>
      </div>
      {verification && (
        <div className="mb-3 flex flex-wrap items-center gap-3 text-xs">
          <Badge tone={verification.empty ? "mute" : !verification.ok ? "bad" : verification.complete ? "ok" : "warn"}>
            {verification.empty
              ? "no events to verify"
              : !verification.ok
                ? "tampering detected"
                : verification.complete
                  ? "chain verified - full history"
                  : "chain verified - partial history"}
          </Badge>
          {!verification.empty && <span className="text-ink-500">{verification.checked} events recomputed</span>}
          {!verification.empty && !verification.ok && verification.problems.slice(0, 2).map((p) => (
            <span key={p.id} className="truncate font-mono text-ink-500" title={p.problem}>
              {p.id.slice(0, 8)}: {p.problem}
            </span>
          ))}
          {!verification.empty && verification.ok && !verification.complete && (
            <span className="text-ink-500">
              {verification.anchored
                ? `pruned prefix anchored to checkpoint ${verification.anchored.checkpoint_id.slice(0, 8)}`
                : verification.truncated
                  ? "newest segment only (bounded read)"
                  : "partial history is not fully verified"}
            </span>
          )}
        </div>
      )}
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
  const serversQuery = useQuery({ queryKey: ["mcp-servers"], queryFn: () => adminApi.servers() });
  const policiesQuery = useQuery({ queryKey: ["policies"], queryFn: () => adminApi.policies() });
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
      <SignedPolicySection />
      <BudgetsSection onError={setError} />
      <AuditSection />
    </Page>
  );
}
