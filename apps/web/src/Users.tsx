import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { opsApi, type TeamUser, type Workspace } from "./api";
import {
  Alert, Badge, Button, Card, Empty, Field, Input,
  Page, Select
} from "./components";

const SCOPES = ["read", "ingest", "gateway", "approve"];
const ROLES = ["member", "approver", "admin"];

function UserCard({ u, workspaces, wsName, onChanged }: {
  u: TeamUser;
  workspaces: Workspace[];
  wsName: (id: string) => string;
  onChanged: () => void;
}) {
  const [error, setError] = useState("");
  const [keyForm, setKeyForm] = useState({ name: "", scopes: ["read"] as string[], pin: "" });
  const [freshKey, setFreshKey] = useState<string | null>(null);
  const [grantWs, setGrantWs] = useState("");

  const toggleScope = (s: string) =>
    setKeyForm((f) => ({
      ...f,
      scopes: f.scopes.includes(s) ? f.scopes.filter((x) => x !== s) : [...f.scopes, s]
    }));

  const fail = (e: unknown) => setError(e instanceof Error ? e.message : "request failed");

  return (
    <Card className="mb-3 p-4 text-sm">
      {error && <Alert>{error}</Alert>}
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium text-ink-900">{u.email}</span>
        <Badge tone={u.role === "admin" ? "info" : u.role === "approver" ? "warn" : "mute"}>{u.role}</Badge>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        <span className="text-xs text-ink-500">workspaces:</span>
        {u.workspaces.length === 0 && <span className="text-xs text-ink-500">none</span>}
        {u.workspaces.map((w) => (
          <span key={w} className="inline-flex items-center gap-1 rounded-full bg-mute-100 px-2 py-0.5 text-xs text-mute-700">
            {wsName(w)}
            <button aria-label={`Remove from ${wsName(w)}`} className="hover:text-bad-700"
              onClick={() => { setError(""); opsApi.revokeMembership(u.id, w).then(onChanged).catch(fail); }}>
              ×
            </button>
          </span>
        ))}
        <WorkspacePicker options={workspaces} value={grantWs} onPick={(id) => {
          setGrantWs("");
          if (!id) return;
          setError("");
          opsApi.grantMembership(u.id, id).then(onChanged).catch(fail);
        }} exclude={u.workspaces} />
      </div>
      <div className="mt-2 space-y-1">
        {u.keys.map((k) => (
          <div key={k.id} className="flex flex-wrap items-center gap-2 rounded-lg bg-surface-2 px-2.5 py-1.5 text-xs">
            <span className="font-mono font-medium text-ink-800">{k.name}</span>
            <span className="text-ink-500">{k.scopes.join(", ")}</span>
            {k.workspace_id && <span className="text-ink-500">pinned: {wsName(k.workspace_id)}</span>}
            {k.expires_at && (
              <span className="text-ink-500">expires {new Date(k.expires_at).toLocaleDateString()}</span>
            )}
            {k.last_used_at && (
              <span className="text-ink-500">used {new Date(k.last_used_at).toLocaleDateString()}</span>
            )}
            <span className="ml-auto">
              <Button size="sm" variant="ghost" className="text-bad-700 hover:bg-bad-100"
                onClick={() => { setError(""); opsApi.revokeKey(u.id, k.id).then(onChanged).catch(fail); }}>
                Revoke
              </Button>
            </span>
          </div>
        ))}
      </div>
      {freshKey && (
        <div className="mt-2 rounded-lg border border-warn-700/30 bg-warn-100/50 px-3 py-2">
          <p className="text-xs text-warn-700">Copy now. The server never shows it again.</p>
          <p className="mt-1 break-all font-mono text-xs text-ink-900">{freshKey}</p>
        </div>
      )}
      <form
        className="mt-2 flex flex-wrap items-end gap-2"
        onSubmit={async (e) => {
          e.preventDefault();
          setError("");
          setFreshKey(null);
          try {
            const r = await opsApi.mintKey(u.id, {
              name: keyForm.name, scopes: keyForm.scopes,
              ...(keyForm.pin ? { workspace_id: keyForm.pin } : {})
            });
            setFreshKey(r.key);
            setKeyForm({ name: "", scopes: ["read"], pin: "" });
            onChanged();
          } catch (err) {
            fail(err);
          }
        }}
      >
        <Field label="Key name">
          <Input className="w-32" value={keyForm.name}
            onChange={(e) => setKeyForm({ ...keyForm, name: e.target.value })} required />
        </Field>
        <div className="flex flex-col gap-1">
          <span className="text-xs font-medium text-ink-500">Scopes</span>
          <div className="flex gap-1.5">
            {SCOPES.map((s) => (
              <label key={s}
                className={`cursor-pointer rounded-full border px-2 py-0.5 text-xs transition-colors ${
                  keyForm.scopes.includes(s)
                    ? "border-brand-600 bg-brand-50 text-brand-700"
                    : "border-ink-200 text-ink-500 hover:border-ink-300"
                }`}>
                <input type="checkbox" className="sr-only" checked={keyForm.scopes.includes(s)}
                  onChange={() => toggleScope(s)} />
                {s}
              </label>
            ))}
          </div>
        </div>
        <Field label="Pin (optional)">
          <WorkspacePicker options={workspaces} value={keyForm.pin}
            onPick={(id) => setKeyForm({ ...keyForm, pin: id })}
            allowBlank blankLabel="no pin" />
        </Field>
        <Button variant="primary" type="submit">Mint key</Button>
      </form>
    </Card>
  );
}

function WorkspacePicker({ options, value, onPick, exclude, allowBlank, blankLabel }: {
  options: Workspace[];
  value: string;
  onPick: (id: string) => void;
  exclude?: string[];
  allowBlank?: boolean;
  blankLabel?: string;
}) {
  const visible = options.filter((w) => !exclude?.includes(w.id));
  return (
    <Select aria-label="Workspace" className="w-36 text-xs" value={value} onChange={(e) => onPick(e.target.value)}>
      {allowBlank ? <option value="">{blankLabel ?? "grant..."}</option> : <option value="">grant...</option>}
      {visible.map((w) => (
        <option key={w.id} value={w.id}>{w.name}</option>
      ))}
    </Select>
  );
}

export default function UsersView() {
  const [form, setForm] = useState({ email: "", password: "", role: "member" });
  const [wsName, setWsName] = useState("");
  const [error, setError] = useState("");
  const queryClient = useQueryClient();
  const teamQuery = useQuery({ queryKey: ["team"], queryFn: () => opsApi.team() });
  const workspacesQuery = useQuery({ queryKey: ["workspaces"], queryFn: () => opsApi.workspaces() });
  const workspaces = workspacesQuery.data?.items ?? [];
  const loadError = teamQuery.error ?? workspacesQuery.error;
  const denied = loadError instanceof Error && /forbidden|unauthorized/i.test(loadError.message);
  const loadFailed = loadError && !denied ? (loadError instanceof Error ? loadError.message : "load failed") : "";
  const users = teamQuery.data?.items ?? null;

  const reload = () => queryClient.invalidateQueries();

  const nameOf = (id: string) => workspaces.find((w) => w.id === id)?.name ?? id.slice(0, 8);

  if (denied) {
    return (
      <Page title="Users" sub="Team, keys, and workspace membership.">
        <Empty hint="Admin only. Connect with an admin key to manage the team." />
      </Page>
    );
  }

  return (
    <Page
      title="Users"
      sub="Team, keys, and workspace membership. Key plaintext shows once, at mint."
    >
      {(error || loadFailed) && <Alert>{error || loadFailed}</Alert>}
      <div className="mb-5 grid gap-4 lg:grid-cols-2">
        <Card className="p-4">
          <h3 className="mb-2 text-sm font-semibold text-ink-700">New user</h3>
          <form
            className="flex flex-wrap items-end gap-2 text-sm"
            onSubmit={async (e) => {
              e.preventDefault();
              setError("");
              try {
                await opsApi.createUser(form);
                setForm({ email: "", password: "", role: "member" });
                reload();
              } catch (err) {
                setError(err instanceof Error ? err.message : "create failed");
              }
            }}
          >
            <Field label="Email">
              <Input aria-label="New user email" className="w-48" type="email" value={form.email}
                onChange={(e) => setForm({ ...form, email: e.target.value })} required />
            </Field>
            <Field label="Password (12+ chars)">
              <Input aria-label="New user password" className="w-40" type="password" value={form.password}
                onChange={(e) => setForm({ ...form, password: e.target.value })} required />
            </Field>
            <Field label="Role">
              <Select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
                {ROLES.map((r) => (
                  <option key={r} value={r}>{r}</option>
                ))}
              </Select>
            </Field>
            <Button variant="primary" type="submit">Create</Button>
          </form>
        </Card>
        <Card className="p-4">
          <h3 className="mb-2 text-sm font-semibold text-ink-700">New workspace</h3>
          <form
            className="flex flex-wrap items-end gap-2 text-sm"
            onSubmit={async (e) => {
              e.preventDefault();
              setError("");
              try {
                await opsApi.createWorkspace(wsName);
                setWsName("");
                reload();
              } catch (err) {
                setError(err instanceof Error ? err.message : "create failed");
              }
            }}
          >
            <Field label="Name">
              <Input aria-label="New workspace name" className="w-48" value={wsName}
                onChange={(e) => setWsName(e.target.value)} required />
            </Field>
            <Button variant="primary" type="submit">Create</Button>
          </form>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {workspaces.map((w) => (
              <span key={w.id} className="rounded-full bg-mute-100 px-2 py-0.5 font-mono text-xs text-mute-700">
                {w.name}
              </span>
            ))}
          </div>
        </Card>
      </div>
      {users === null ? (
        <p className="text-sm text-ink-500">Loading...</p>
      ) : users.length === 0 && !denied ? (
        <Empty hint="No users yet." />
      ) : (
        users.map((u) => (
          <UserCard key={u.id} u={u} workspaces={workspaces} wsName={nameOf} onChanged={reload} />
        ))
      )}
    </Page>
  );
}
