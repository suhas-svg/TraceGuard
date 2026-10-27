// Dashboard client for the TraceGuard API. Privileged bearer keys are
// exchanged once for short-lived HttpOnly session cookies; only the
// non-secret endpoint URLs are persisted in the browser. State-changing
// requests echo the readable CSRF cookie in X-CSRF-Token (FR-016).
const stored = (k: string, fallback: string) => {
  try {
    // An empty stored value is unset, not a value: a cleared field used to
    // win over the default and turn every request into a relative URL.
    return localStorage.getItem(k) || fallback;
  } catch {
    return fallback;
  }
};

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
type SessionRole = "admin" | "approver";

function cookie(name: string): string {
  for (const part of document.cookie.split(";")) {
    const [key, ...value] = part.trim().split("=");
    if (key === name) return decodeURIComponent(value.join("="));
  }
  return "";
}

function csrfToken(role: SessionRole): string {
  return cookie(role === "approver" ? "tg_approver_csrf" : "tg_csrf");
}

function writeHeaders(method: string, role: SessionRole, json: boolean): Record<string, string> {
  const headers: Record<string, string> = json ? { "content-type": "application/json" } : {};
  if (!SAFE_METHODS.has(method)) headers["x-csrf-token"] = csrfToken(role);
  return headers;
}

// Remove keys written by older dashboards. They are never read again.
try {
  localStorage.removeItem("tg_key");
  localStorage.removeItem("tg_approver_key");
} catch {
  // A browser that blocks storage still works with the URL defaults.
}

export const settings = {
  get url() {
    return stored("tg_url", import.meta.env.VITE_API_URL ?? "http://localhost:8090");
  },
  get gwUrl() {
    return stored("tg_gw_url", import.meta.env.VITE_GATEWAY_URL ?? "http://localhost:8091");
  },
  // The human approval surface runs on the gateway's separate control
  // listener. Unless explicitly configured, assume it is the gateway host
  // on port 8093.
  get gwControlUrl() {
    const explicit = stored("tg_gw_control_url", "") || import.meta.env.VITE_GATEWAY_CONTROL_URL;
    if (explicit) return explicit;
    try {
      const u = new URL(this.gwUrl);
      u.port = "8093";
      return u.origin;
    } catch {
      return "http://localhost:8093";
    }
  },
  save(url: string, gwUrl: string) {
    localStorage.setItem("tg_url", url);
    localStorage.setItem("tg_gw_url", gwUrl);
  }
};

export interface SessionView {
  admin: { principal: { kind: string; userId: string | null; scopes: string[] }; expires_at: string } | null;
  approver: { principal: { kind: string; userId: string | null; scopes: string[] }; expires_at: string } | null;
}

export async function getSession(): Promise<SessionView> {
  const res = await fetch(`${settings.url}/v1/auth/session`, { credentials: "include" });
  if (!res.ok) throw new ApiError(await explain(res), res.status);
  return res.json() as Promise<SessionView>;
}

// Exchange one or both bearer keys for server-side sessions. The keys stay in
// this function's arguments and are never written to storage or returned.
export async function connectSession(
  url: string,
  adminKey: string,
  gwUrl: string,
  approverKey: string
): Promise<{ admin: boolean; approver: boolean }> {
  settings.save(url, gwUrl);
  const roles: SessionRole[] = [];
  for (const key of [adminKey, approverKey]) {
    if (!key.trim()) continue;
    const res = await fetch(`${url}/v1/auth/session`, {
      method: "POST",
      credentials: "include",
      headers: { authorization: `Bearer ${key.trim()}` }
    });
    if (!res.ok) throw new ApiError(await explain(res), res.status);
    const body = (await res.json()) as { role?: SessionRole };
    if (body.role) roles.push(body.role);
  }
  return { admin: roles.includes("admin"), approver: roles.includes("approver") };
}

export async function logoutSession(role: SessionRole): Promise<void> {
  const res = await fetch(`${settings.url}/v1/auth/session?role=${role}`, {
    method: "DELETE",
    credentials: "include",
    headers: writeHeaders("DELETE", role, false)
  });
  if (!res.ok) throw new ApiError(await explain(res), res.status);
}

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
  const res = await fetch(`${settings.url}${path}`, { credentials: "include" });
  if (res.status === 401) throw new ApiError("unauthorized: connect a session in settings", 401);
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
  remaining_micro: number | null;
  /** False when unpriced usage makes a project budget's remainder unknowable. */
  spend_complete?: boolean;
  unpriced_spans?: number;
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
    credentials: "include",
    // A bodyless call must not declare a JSON body: Fastify answers 400 to
    // Content-Type: application/json with an empty body, which broke every
    // DELETE and revoke the dashboard sends.
    headers: writeHeaders(method, "admin", body !== undefined),
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  if (res.status === 401) throw new ApiError("unauthorized: connect a session in settings", 401);
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

// A remainder is unknowable when unpriced usage exists — never render it as
// $0. Each screen keeps its own "unknown" wording; the decision stays here.
export function budgetRemainingHint(
  b: Pick<Budget, "spend_complete" | "remaining_micro">,
  unknownLabel: string
): string {
  if (b.spend_complete === false) return unknownLabel;
  return `remaining ${formatMicro(Math.max(b.remaining_micro ?? 0, 0))}`;
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

// Gateway calls also use the server-side session. The control listener gets
// the approver session; ordinary gateway reads use the admin session.
async function gwFetch<T>(
  base: string, path: string, init: RequestInit | undefined, role: SessionRole
): Promise<T> {
  const method = init?.method ?? "GET";
  const res = await fetch(`${base}${path}`, {
    ...init,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
      ...writeHeaders(method, role, false)
    }
  });
  if (res.status === 401) throw new ApiError("unauthorized: connect a session in settings", 401);
  if (!res.ok) {
    throw new ApiError(await explain(res), res.status);
  }
  return res.json() as Promise<T>;
}

function gw<T>(path: string, init?: RequestInit): Promise<T> {
  return gwFetch<T>(settings.gwUrl, path, init, "admin");
}

// The approval queue and decisions live on the gateway's control listener,
// which always uses the separate approver session.
function gwc<T>(path: string, init?: RequestInit): Promise<T> {
  return gwFetch<T>(settings.gwControlUrl, path, init, "approver");
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
  response_is_error?: boolean | null;
  outcome_summary?: string;
  // FR-021: the trace a call named when the hold was created.
  run_id?: string | null;
  span_id?: string | null;
}

// FR-021: one gateway policy decision, correlated to a run/span/request so
// the trace view can show what the boundary decided for each call.
export interface PolicyDecision {
  id: string;
  timestamp: string;
  workspace_id: string;
  caller: string;
  server_id: string | null;
  tool_name: string;
  args_hash: string;
  decision: string;
  policy_id: string | null;
  policy_version: number | null;
  policy_version_id: string | null;
  matched_rules: { id?: string; name?: string; effect?: string }[] | null;
  reason: string;
  approval_id: string | null;
  overhead_ms: number | null;
  run_id: string | null;
  span_id: string | null;
  request_id: string | null;
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

export interface PolicyVersion {
  id: string;
  version: number;
  content_hash: string;
  previous_version_hash: string | null;
  published_at: string;
  published_by: string;
  key_id: string;
  key_retired: boolean;
  active: boolean;
}

export const adminApi = {
  servers: () => get<{ items: McpServer[] }>("/v1/servers"),
  createServer: (s: { name: string; base_url: string; secret_ref?: string }) =>
    postApi<McpServer>("/v1/servers", s),
  discover: (id: string) =>
    postApi<{ tools: { tool_name: string; quarantined: boolean; quarantine_reason?: string | null;
      definition?: Record<string, unknown> | null; previous_definition?: Record<string, unknown> | null;
      definition_hash?: string | null; previous_hash?: string | null;
      active_pin_id?: string | null; active_pin_version?: number | null;
      candidate_pin_id?: string | null; candidate_pin_version?: number | null;
      candidate_status?: "candidate" | "pending_review" | "approved" | "superseded" | null }[] }>(
      `/v1/servers/${id}/discover`, {}),
  policies: () => get<{ items: Policy[] }>("/v1/policies"),
  createPolicy: (p: Record<string, unknown>) => postApi<Policy>("/v1/policies", p),
  updatePolicy: (id: string, p: Record<string, unknown>) =>
    postApi<Policy>(`/v1/policies/${id}`, p, "PUT"),
  quarantine: (serverId: string, tool: string, quarantined: boolean) =>
    postApi<{ ok: boolean }>(
      `/v1/servers/${serverId}/tools/${encodeURIComponent(tool)}/quarantine`,
      { quarantined }, "PUT"
    ),
  submitPinReview: (pinId: string) =>
    postApi<{ id: string; status: string }>(`/v1/tool-pins/${pinId}/submit-review`, {}),
  approvePin: (pinId: string) =>
    postApi<{ id: string; status: string }>(
      `/v1/tool-pin-candidates/${pinId}/approve-for-publication`, {})
};

export const gwApi = {
  // The queue is fetched from the control listener with the approver session:
  // the control surface never opens sealed arguments for other scopes.
  approvals: (status?: string) =>
    gwc<{ items: Approval[] }>(`/_control/v1/approvals${status ? `?status=${status}` : ""}`),
  decide: (id: string, approved: boolean, reason: string) =>
    gwc<Approval>(`/_control/v1/approvals/${id}/decision`,
      { method: "POST", body: JSON.stringify({ approved, reason }) }),
  audit: (action?: string) =>
    gw<{ items: AuditEvent[] }>(`/v1/audit-events${action ? `?action=${encodeURIComponent(action)}` : ""}`),
  // FR-021: every decision recorded for one run, newest first.
  decisions: (runId: string, limit = 200) =>
    gw<{ items: PolicyDecision[] }>(`/v1/decisions?run_id=${encodeURIComponent(runId)}&limit=${limit}`),
  policyVersions: () => gw<{ items: PolicyVersion[] }>("/v1/policy-versions"),
  auditVerify: () =>
    gw<{ ok: boolean; checked: number; truncated: boolean; problems: { id: string; problem: string }[];
      anchored: { checkpoint_id: string; up_to_timestamp: string; up_to_hash: string; event_count: number } | null;
      empty: boolean; complete: boolean }>(
      "/v1/audit/verify", { method: "POST", body: "{}" }
    )
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
  max_rows: number | string | null;
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
