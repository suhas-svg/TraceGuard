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
  save(url: string, key: string) {
    localStorage.setItem("tg_url", url);
    localStorage.setItem("tg_key", key);
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
