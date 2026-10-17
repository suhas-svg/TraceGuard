// Read-only client for the TraceGuard API. The dashboard never writes:
// policy edits and approvals stay in API clients with the right keys.
const stored = (k: string, fallback: string) => {
  try {
    // An empty stored value is unset, not a value: a cleared field used to
    // win over the default and turn every request into a relative URL.
    return localStorage.getItem(k) || fallback;
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

// Carries the HTTP status, so callers branch on 403 versus 401 instead of
// pattern-matching an English message.
export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

async function explain(res: Response): Promise<string> {
  // The API answers with { error: "code" }; a bare status tells the operator
  // nothing about which code it was.
  const body = (await res.json().catch(() => ({}))) as { error?: string };
  return body.error ?? `request failed: ${res.status}`;
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${settings.url}${path}`, {
    headers: { Authorization: `Bearer ${settings.key}` }
  });
  if (res.status === 401) throw new ApiError("unauthorized: check the API key in settings", 401);
  if (!res.ok) throw new ApiError(await explain(res), res.status);
  return res.json() as Promise<T>;
}

export function listRuns(opts: {
  status?: string;
  agent_id?: string;
  since?: string;
  until?: string;
  provider?: string;
  model?: string;
  eval_run_id?: string;
  limit?: number;
  cursor?: string;
}) {
  const p = new URLSearchParams();
  if (opts.status) p.set("status", opts.status);
  if (opts.agent_id) p.set("agent_id", opts.agent_id);
  if (opts.since) p.set("since", opts.since);
  if (opts.until) p.set("until", opts.until);
  if (opts.provider) p.set("provider", opts.provider);
  if (opts.model) p.set("model", opts.model);
  if (opts.eval_run_id) p.set("eval_run_id", opts.eval_run_id);
  if (opts.limit) p.set("limit", String(opts.limit));
  if (opts.cursor) p.set("cursor", opts.cursor);
  return get<{ items: RunItem[]; next_cursor: string | null }>(`/v1/runs?${p}`);
}

export interface AgentItem {
  id: string;
  name: string;
  adapter_type: string;
  created_at: string;
}

export function listAgents() {
  return get<{ items: AgentItem[] }>("/v1/agents");
}

export interface Overview {
  since: string | null;
  runs: { total: number; by_status: Record<string, number> };
  tokens: {
    input_tokens: number;
    output_tokens: number;
    spans_with_usage: number;
    spans_without_usage: number;
  };
  cost: { estimated_cost_micro: number; cost_partial: boolean; missing_pricing_spans: number };
  latency_ms: { median: number | null; p95: number | null };
  denied_spans: number;
  pending_approvals: number;
}

export function getOverview() {
  return get<Overview>("/v1/overview");
}

export interface Budget {
  id: string;
  scope: string;
  ref_id: string;
  limit_micro: number;
  effect: string;
  spent_micro: number;
  reserved_micro: number;
  remaining_micro: number;
}

export function listBudgets() {
  return get<{ items: Budget[] }>("/v1/budgets");
}

export function createBudget(b: { scope: string; ref_id: string; limit_micro: number; effect: string }) {
  return postApi<Budget>("/v1/budgets", b);
}

export function updateBudget(id: string, b: { limit_micro?: number; effect?: string }) {
  return postApi<Budget>(`/v1/budgets/${id}`, b, "PUT");
}

export interface DiagnosticWarning {
  code: string;
  severity: string;
  message: string;
  details: Record<string, unknown>;
}

export function getDiagnostics(runId: string) {
  return get<{ run_id: string; warnings: DiagnosticWarning[] }>(`/v1/runs/${runId}/diagnostics`);
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
  spans: {
    id: string;
    input_tokens: number | null;
    output_tokens: number | null;
    cost_micro: number | null;
    pricing_id: string | null;
  }[];
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
  if (res.status === 401) throw new ApiError("unauthorized: check the API key in settings", 401);
  if (!res.ok) {
    throw new ApiError(await explain(res), res.status);
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

export function createSuite(body: { name: string; description?: string }) {
  return postApi<EvalSuite>("/v1/evaluations/suites", body);
}

export function addCase(suiteId: string, body: Record<string, unknown>) {
  return postApi<EvalCase>(`/v1/evaluations/suites/${suiteId}/cases`, body);
}

export function runSuite(suiteId: string, body: Record<string, unknown>) {
  return postApi<{ eval_run: EvalRun }>(`/v1/evaluations/suites/${suiteId}/runs`, body);
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
  if (res.status === 401) throw new ApiError("unauthorized: check the key in settings", 401);
  if (!res.ok) {
    throw new ApiError(await explain(res), res.status);
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

export interface AuditEvent {
  id: string;
  timestamp: string;
  actor_type: string;
  actor_id: string;
  action: string;
  resource_type: string;
  resource_id: string;
  result: string;
  metadata: Record<string, unknown>;
}

export const gwApi = {
  servers: () => gw<{ items: McpServer[] }>("/v1/servers"),
  createServer: (s: { name: string; base_url: string; auth_secret?: string }) =>
    gw<McpServer>("/v1/servers", { method: "POST", body: JSON.stringify(s) }),
  discover: (id: string) => gw<{ tools: { tool_name: string; quarantined: boolean }[] }>(`/v1/servers/${id}/discover`, { method: "POST", body: "{}" }),
  policies: () => gw<{ items: Policy[] }>("/v1/policies"),
  createPolicy: (p: Record<string, unknown>) =>
    gw<Policy>("/v1/policies", { method: "POST", body: JSON.stringify(p) }),
  updatePolicy: (id: string, p: Record<string, unknown>) =>
    gw<Policy>(`/v1/policies/${id}`, { method: "PUT", body: JSON.stringify(p) }),
  // The queue is fetched with the approver key: the gateway only opens the
  // sealed arguments for a caller holding the approve scope.
  approvals: (status?: string) =>
    gw<{ items: Approval[] }>(`/v1/approvals${status ? `?status=${status}` : ""}`, undefined, true),
  decide: (id: string, approved: boolean, reason: string) =>
    gw<Approval>(`/v1/approvals/${id}/decision`,
      { method: "POST", body: JSON.stringify({ approved, reason }) }, true),
  call: (body: Record<string, unknown>) =>
    gw<{ result?: unknown; approval_id?: string; status?: string; expires_at?: string }>(
      "/v1/gateway/tools/call", { method: "POST", body: JSON.stringify(body) }),
  quarantine: (serverId: string, tool: string, quarantined: boolean) =>
    gw<{ ok: boolean }>(
      `/v1/servers/${serverId}/tools/${encodeURIComponent(tool)}/quarantine`,
      { method: "PUT", body: JSON.stringify({ quarantined }) }
    ),
  audit: (action?: string) =>
    gw<{ items: AuditEvent[] }>(`/v1/audit-events${action ? `?action=${encodeURIComponent(action)}` : ""}`)
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
  compareCosts: (periodStart: string, periodEnd: string, provider?: string, groupBy?: string) =>
    get<{ period_start: string; period_end: string; group_by: string; rows: CompareRow[] }>(
      `/v1/reconciliation/compare?period_start=${encodeURIComponent(periodStart)}&period_end=${encodeURIComponent(periodEnd)}${provider ? `&provider=${encodeURIComponent(provider)}` : ""}${groupBy && groupBy !== "model" ? `&group_by=${encodeURIComponent(groupBy)}` : ""}`),
  importActuals: (rows: Record<string, unknown>[]) =>
    postApi<{ accepted: number }>("/v1/reconciliation/actuals", { rows }),
  webhooks: () => get<{ items: Webhook[] }>("/v1/webhooks"),
  createWebhook: (w: Record<string, unknown>) => postApi<Webhook>("/v1/webhooks", w),
  deleteWebhook: (id: string) => deleteApi<{ ok: boolean }>(`/v1/webhooks/${id}`),
  deliveries: (status?: string) =>
    // The API caps this at 200; ask for the cap and say so in the UI rather
    // than silently dropping everything past the newest 50.
    get<{ items: Delivery[] }>(`/v1/webhooks/deliveries?limit=200${status ? `&status=${status}` : ""}`),
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
