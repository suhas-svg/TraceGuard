import { randomUUID } from "node:crypto";
import type { APIRequestContext, Page } from "@playwright/test";
import { API_KEY, API_URL, APPROVER_KEY, GATEWAY_URL, MOCK_TOOLS_URL } from "./env";

const auth = (key: string) => ({ authorization: `Bearer ${key}` });

export function event(over: Record<string, unknown>): Record<string, unknown> {
  return {
    schema_version: "1",
    event_id: `evt-${randomUUID()}`,
    agent_name: "e2e-agent",
    run_id: randomUUID(),
    span_id: randomUUID(),
    parent_span_id: null,
    event_type: "model.request",
    timestamp: new Date().toISOString(),
    status: "success",
    attributes: {},
    ...over
  };
}

export async function ingest(request: APIRequestContext, events: Record<string, unknown>[]) {
  return request.post(`${API_URL}/v1/ingest/events`, {
    headers: auth(API_KEY),
    data: { events }
  });
}

export async function apiPost(request: APIRequestContext, path: string, data: unknown) {
  return request.post(`${API_URL}${path}`, { headers: auth(API_KEY), data });
}

export async function apiGet(request: APIRequestContext, path: string) {
  return request.get(`${API_URL}${path}`, { headers: auth(API_KEY) });
}

export async function gwPost(
  request: APIRequestContext,
  path: string,
  data: unknown,
  key = API_KEY
) {
  return request.post(`${GATEWAY_URL}${path}`, { headers: auth(key), data });
}

export async function gwCall(request: APIRequestContext, payload: Record<string, unknown>) {
  return gwPost(request, "/v1/gateway/tools/call", payload);
}

export async function upstreamHits(request: APIRequestContext): Promise<number> {
  const res = await request.get(`${MOCK_TOOLS_URL}/hits`);
  return (await res.json()).hits as number;
}

// The dashboard reads its connection settings from localStorage; every page
// must be seeded before its first navigation in the test.
export async function setKeys(page: Page) {
  await page.addInitScript(
    ([apiKey, approverKey, apiUrl, gwUrl]) => {
      localStorage.setItem("tg_key", apiKey);
      localStorage.setItem("tg_approver_key", approverKey);
      localStorage.setItem("tg_url", apiUrl);
      localStorage.setItem("tg_gw_url", gwUrl);
    },
    [API_KEY, APPROVER_KEY, API_URL, GATEWAY_URL] as const
  );
}

// Seeds a complete run through the public ingest API: started, one model
// request, an optional tool call and a terminal event.
export async function seedRun(
  request: APIRequestContext,
  opts: {
    agent_name: string;
    ok?: boolean;
    provider?: string;
    model?: string;
    input_tokens?: number;
    output_tokens?: number;
    tool?: string;
    error_type?: string;
  }
): Promise<string> {
  const runId = randomUUID();
  const base = { run_id: runId, agent_name: opts.agent_name };
  const events: Record<string, unknown>[] = [
    event({ ...base, event_type: "run.started" }),
    event({
      ...base,
      provider: opts.provider ?? "e2e-provider",
      model: opts.model ?? "e2e-model",
      input_tokens: opts.input_tokens ?? 120,
      output_tokens: opts.output_tokens ?? 30,
      usage_source: "provider_reported"
    })
  ];
  if (opts.tool) {
    events.push(event({
      ...base,
      event_type: "tool.invocation",
      status: opts.ok === false ? "failed" : "success",
      error_type: opts.ok === false ? opts.error_type ?? "tool exploded" : null,
      attributes: { server_id: randomUUID(), tool: opts.tool }
    }));
  }
  events.push(event(
    opts.ok === false
      ? { ...base, event_type: "run.failed", status: "failed", error_type: opts.error_type ?? "boom" }
      : { ...base, event_type: "run.completed", status: "success" }
  ));
  const res = await ingest(request, events);
  if (!res.ok()) throw new Error(`ingest failed: ${res.status()} ${await res.text()}`);
  return runId;
}
