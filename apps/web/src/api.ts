// Read-only client for the TraceGuard API. The dashboard never writes:
// policy edits and approvals stay in API clients with the right keys.
const stored = (k: string, fallback: string) => {
  try {
    return localStorage.getItem(k) ?? fallback;
  } catch {
    return fallback;
  }
};

export const settings = {
  get url() {
    return stored("tg_url", import.meta.env.VITE_API_URL ?? "http://localhost:8090");
  },
  get key() {
    return stored("tg_key", import.meta.env.VITE_API_KEY ?? "dev_key_change_me");
  },
  get gwUrl() {
    return stored("tg_gw_url", import.meta.env.VITE_GATEWAY_URL ?? "http://localhost:8091");
  },
  get approverKey() {
    return stored("tg_approver_key", import.meta.env.VITE_APPROVER_KEY ?? "dev_approver_change_me");
  },
  save(url: string, key: string, gwUrl: string, approverKey: string) {
    localStorage.setItem("tg_url", url);
    localStorage.setItem("tg_key", key);
    localStorage.setItem("tg_gw_url", gwUrl);
    localStorage.setItem("tg_approver_key", approverKey);
  }
};

export interface RunItem {
  id: string;
  agent_name: string;
  status: string;
  started_at: string;
  ended_at: string | null;
  error_type: string | null;
  input_tokens: string;
  output_tokens: string;
  span_count: string;
}

export interface Span {
  id: string;
  run_id: string;
  parent_span_id: string | null;
  event_id: string;
  operation_type: string;
  started_at: string;
  ended_at: string | null;
  duration_ms: number | null;
  status: string;
  provider: string | null;
  model: string | null;
  input_tokens: number | null;
  output_tokens: number | null;
  usage_source: string | null;
  error_type: string | null;
  attributes: Record<string, unknown>;
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${settings.url}${path}`, {
    headers: { Authorization: `Bearer ${settings.key}` }
  });
  if (res.status === 401) throw new Error("unauthorized: check the API key in settings");
  if (!res.ok) throw new Error(`request failed: ${res.status}`);
  return res.json() as Promise<T>;
}

export function listRuns(opts: { status?: string; limit?: number; cursor?: string }) {
  const p = new URLSearchParams();
  if (opts.status) p.set("status", opts.status);
  if (opts.limit) p.set("limit", String(opts.limit));
  if (opts.cursor) p.set("cursor", opts.cursor);
  return get<{ items: RunItem[]; next_cursor: string | null }>(`/v1/runs?${p}`);
}

export interface RunCounts {
  counts: Record<string, number>;
  total: number;
  denied_spans: number;
}

export function getRunCounts() {
  return get<RunCounts>("/v1/runs/counts");
}

export function getTrace(runId: string) {
  return get<{ run: RunItem; spans: Span[] }>(`/v1/runs/${runId}/trace`);
}

export interface RunUsage {
  input_tokens: number;
  output_tokens: number;
  estimated_cost_micro: number;
  cost_partial: boolean;
  missing_pricing: string[];
}

export function getUsage(runId: string) {
  return get<RunUsage>(`/v1/runs/${runId}/usage`);
}

async function postApi<T>(path: string, body: unknown, method = "POST"): Promise<T> {
  const res = await fetch(`${settings.url}${path}`, {
    method,
    // A bodyless call must not declare a JSON body: Fastify answers 400 to
    // Content-Type: application/json with an empty body, which broke every
    // DELETE and revoke the dashboard sends.
    headers: {
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      Authorization: `Bearer ${settings.key}`
    },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  if (res.status === 401) throw new Error("unauthorized: check the API key in settings");
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error((data as { error?: string }).error ?? `request failed: ${res.status}`);
  }
  return res.json() as Promise<T>;
}

async function deleteApi<T>(path: string): Promise<T> {
  return postApi<T>(path, undefined, "DELETE");
}

export function formatMicro(micro: number): string {
  return `$${(micro / 1_000_000).toFixed(4)}`;
}

export interface EvalSuite {
  id: string;
  name: string;
  version: number;
  description: string;
  locked: boolean;
  case_count: string;
  run_count: string;
}

export interface EvalCase {
  id: string;
  name: string;
  assertions: { type: string }[];
}

export interface EvalResult {
  id: string;
  case_name: string;
  trial: number;
  passed: boolean;
  assertion_results: { type: string; passed: boolean; message: string }[];
  latency_ms: number;
  cost_micro: number | null;
  error_summary: string | null;
  agent_run_id: string | null;
}

export interface EvalRun {
  id: string;
  agent_name: string;
  config_fingerprint: string;
  model: string;
  trials: number;
  status: string;
}

export function listSuites() {
  return get<{ items: EvalSuite[] }>("/v1/evaluations/suites");
}

export function getEvalRun(id: string) {
  return get<{ eval_run: EvalRun; results: EvalResult[] }>(`/v1/evaluations/runs/${id}`);
}

export function compareEvalRuns(ids: string[]) {
  return get<{ runs: Record<string, unknown>[] }>(`/v1/evaluations/runs/compare?ids=${ids.join(",")}`);
}

// Gateway calls go to the gateway process with the agent key. Approval
// decisions are the one call that uses the approver key instead.
async function gw<T>(path: string, init?: RequestInit, approver = false): Promise<T> {
  const res = await fetch(`${settings.gwUrl}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${approver ? settings.approverKey : settings.key}`,
      ...(init?.headers ?? {})
    }
  });
  if (res.status === 401) throw new Error("unauthorized: check the key in settings");
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error((body as { error?: string }).error ?? `request failed: ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export interface McpServer {
  id: string;
  name: string;
  base_url: string;
}

export interface Policy {
  id: string;
  name: string;
  enabled: boolean;
  priority: number;
  server_id: string | null;
  tool_name: string | null;
  effect: string;
  conditions: Record<string, unknown>;
  version: number;
  superseded_by: string | null;
}

export interface Approval {
  id: string;
  request_id: string;
  caller: string;
  server_id: string;
  tool_name: string;
  args: Record<string, unknown>;
  args_hash: string;
  status: string;
  expires_at: string;
  decision_reason: string;
}

export const gwApi = {
  servers: () => gw<{ items: McpServer[] }>("/v1/servers"),
  discover: (id: string) => gw<{ tools: { tool_name: string; quarantined: boolean }[] }>(`/v1/servers/${id}/discover`, { method: "POST", body: "{}" }),
  policies: () => gw<{ items: Policy[] }>("/v1/policies"),
  createPolicy: (p: Record<string, unknown>) =>
    gw<Policy>("/v1/policies", { method: "POST", body: JSON.stringify(p) }),
  updatePolicy: (id: string, p: Record<string, unknown>) =>
    gw<Policy>(`/v1/policies/${id}`, { method: "PUT", body: JSON.stringify(p) }),
  approvals: (status?: string) =>
    gw<{ items: Approval[] }>(`/v1/approvals${status ? `?status=${status}` : ""}`),
  decide: (id: string, approved: boolean, reason: string) =>
    gw<Approval>(`/v1/approvals/${id}/decision`,
      { method: "POST", body: JSON.stringify({ approved, reason }) }, true),
  call: (body: Record<string, unknown>) =>
    gw<{ result?: unknown; approval_id?: string; status?: string; expires_at?: string }>(
      "/v1/gateway/tools/call", { method: "POST", body: JSON.stringify(body) })
};

export interface Webhook {
  id: string;
  name: string;
  url: string;
  events: string[];
  enabled: boolean;
}

export interface Delivery {
  id: string;
  subscription: string;
  event_type: string;
  status: string;
  attempts: number;
  last_error: string | null;
  created_at: string;
}

export interface RetentionRule {
  id: string;
  name: string;
  target: string;
  older_than_days: number;
  enabled: boolean;
}

export interface RetentionRun {
  id: string;
  started_at: string;
  ended_at: string | null;
  deleted_counts: Record<string, number>;
  status: string;
}

export interface CompareRow {
  provider: string;
  model: string;
  input_tokens: number;
  output_tokens: number;
  estimated_micro: number;
  actual_micro: number | null;
  variance_micro: number | null;
  variance_pct: number | null;
  missing_pricing: boolean;
}

export interface TeamUser {
  id: string;
  email: string;
  role: string;
  created_at: string;
  keys: { id: string; name: string; scopes: string[]; workspace_id: string | null;
    expires_at: string | null; last_used_at: string | null }[];
  workspaces: string[];
}

export interface Workspace {
  id: string;
  name: string;
  created_at: string;
}

export const opsApi = {
  team: () => get<{ items: TeamUser[] }>("/v1/users"),
  createUser: (u: { email: string; password: string; role: string }) =>
    postApi<TeamUser>("/v1/users", u),
  mintKey: (userId: string, k: Record<string, unknown>) =>
    postApi<{ id: string; key: string }>(`/v1/users/${userId}/keys`, k),
  revokeKey: (userId: string, keyId: string) =>
    deleteApi<{ ok: boolean }>(`/v1/users/${userId}/keys/${keyId}`),
  grantMembership: (userId: string, workspace_id: string) =>
    postApi<{ ok: boolean }>(`/v1/users/${userId}/memberships`, { workspace_id }),
  revokeMembership: (userId: string, workspaceId: string) =>
    deleteApi<{ ok: boolean }>(`/v1/users/${userId}/memberships/${workspaceId}`),
  workspaces: () => get<{ items: Workspace[] }>("/v1/workspaces"),
  createWorkspace: (name: string) => postApi<Workspace>("/v1/workspaces", { name }),
  compareCosts: (periodStart: string, periodEnd: string, provider?: string) =>
    get<{ period_start: string; period_end: string; rows: CompareRow[] }>(
      `/v1/reconciliation/compare?period_start=${encodeURIComponent(periodStart)}&period_end=${encodeURIComponent(periodEnd)}${provider ? `&provider=${encodeURIComponent(provider)}` : ""}`),
  importActuals: (rows: Record<string, unknown>[]) =>
    postApi<{ accepted: number }>("/v1/reconciliation/actuals", { rows }),
  webhooks: () => get<{ items: Webhook[] }>("/v1/webhooks"),
  createWebhook: (w: Record<string, unknown>) => postApi<Webhook>("/v1/webhooks", w),
  deleteWebhook: (id: string) => deleteApi<{ ok: boolean }>(`/v1/webhooks/${id}`),
  deliveries: (status?: string) =>
    get<{ items: Delivery[] }>(`/v1/webhooks/deliveries${status ? `?status=${status}` : ""}`),
  retryDelivery: (id: string) =>
    postApi<{ status: string; lastError: string | null }>(`/v1/webhooks/deliveries/${id}/retry`, {}),
  retentionRules: () => get<{ items: RetentionRule[] }>("/v1/retention/rules"),
  createRetentionRule: (r: Record<string, unknown>) => postApi<RetentionRule>("/v1/retention/rules", r),
  updateRetentionRule: (id: string, r: Record<string, unknown>) =>
    postApi<RetentionRule>(`/v1/retention/rules/${id}`, r, "PUT"),
  deleteRetentionRule: (id: string) => deleteApi<{ ok: boolean }>(`/v1/retention/rules/${id}`),
  runRetention: () => postApi<{ run_id: string; deleted: Record<string, number> }>("/v1/retention/run", {}),
  retentionRuns: () => get<{ items: RetentionRun[] }>("/v1/retention/runs")
};
