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
  cost_micro: number;
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
