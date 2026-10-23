import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildApp } from "../src/index.js";
import { pool } from "../src/db.js";

// §14 fixes the public route names, not just the behavior behind them. These
// tests exercise each exact path so a future refactor cannot silently rename
// the control-plane contract again.
describe("§14 route contract", () => {
  const api = buildApp();
  const key = { authorization: "Bearer test_key" };
  const tag = Date.now().toString(36);
  let serverId = "";
  let serverDraftId = "";
  let policyDraftId = "";
  let budgetId = "";
  let runId = "";

  beforeAll(async () => {
    const created = await api.inject({
      method: "POST", url: "/v1/servers", headers: key,
      payload: { name: `contract-${tag}`, base_url: "http://127.0.0.1:9/mcp" }
    });
    expect(created.statusCode).toBe(201);
    serverId = created.json().id;
  });

  afterAll(async () => {
    await api.close();
    await pool.end();
  });

  it("serves GET /v1/mcp-servers and GET /v1/mcp-servers/:id/tools", async () => {
    const listed = await api.inject({ method: "GET", url: "/v1/mcp-servers", headers: key });
    expect(listed.statusCode).toBe(200);
    expect(listed.json().items.some((s: { id: string }) => s.id === serverId)).toBe(true);

    const tools = await api.inject({
      method: "GET", url: `/v1/mcp-servers/${serverId}/tools`, headers: key
    });
    expect(tools.statusCode).toBe(200);
    expect(tools.json().items).toEqual([]);
  });

  it("serves POST /v1/mcp-servers/:id/disable and refuses refresh", async () => {
    const disabled = await api.inject({
      method: "POST", url: `/v1/mcp-servers/${serverId}/disable`, headers: key
    });
    expect(disabled.statusCode).toBe(200);
    expect(disabled.json().disabled_at).toBeTruthy();

    const refresh = await api.inject({
      method: "POST", url: `/v1/mcp-servers/${serverId}/refresh-tools`, headers: key
    });
    expect(refresh.statusCode).toBe(409);
    expect(refresh.json().error).toBe("server_disabled");

    const audit = await pool.query(
      "SELECT action FROM audit_events WHERE action = 'server.disabled' AND resource_id = $1",
      [serverId]
    );
    expect(audit.rows).toHaveLength(1);
  });

  it("serves server draft create, list, and export", async () => {
    const created = await api.inject({
      method: "POST", url: "/v1/mcp-server-drafts", headers: key,
      payload: { name: `draft-${tag}`, base_url: "http://127.0.0.1:9/mcp" }
    });
    expect(created.statusCode).toBe(201);
    serverDraftId = created.json().id;

    const listed = await api.inject({
      method: "GET", url: "/v1/mcp-server-drafts", headers: key
    });
    expect(listed.statusCode).toBe(200);
    expect(listed.json().items.some((d: { id: string }) => d.id === serverDraftId)).toBe(true);

    const exported = await api.inject({
      method: "POST", url: `/v1/mcp-server-drafts/${serverDraftId}/export`, headers: key
    });
    expect(exported.statusCode).toBe(200);
    expect(exported.json().draft.status).toBe("exported");
  });

  it("serves policy draft list, create, read, update, and export", async () => {
    const created = await api.inject({
      method: "POST", url: "/v1/policy-drafts", headers: key,
      payload: { name: `policy-${tag}`, effect: "allow" }
    });
    expect(created.statusCode).toBe(201);
    policyDraftId = created.json().id;

    const listed = await api.inject({ method: "GET", url: "/v1/policy-drafts", headers: key });
    expect(listed.statusCode).toBe(200);
    expect(listed.json().items.some((p: { id: string }) => p.id === policyDraftId)).toBe(true);

    const fetched = await api.inject({
      method: "GET", url: `/v1/policy-drafts/${policyDraftId}`, headers: key
    });
    expect(fetched.statusCode).toBe(200);
    expect(fetched.json().id).toBe(policyDraftId);

    const patched = await api.inject({
      method: "PATCH", url: `/v1/policy-drafts/${policyDraftId}`, headers: key,
      payload: { name: `policy-${tag}-v2`, effect: "deny" }
    });
    expect(patched.statusCode).toBe(200);
    expect(patched.json().version).toBe(2);

    const exported = await api.inject({
      method: "POST", url: `/v1/policy-drafts/${policyDraftId}/export`, headers: key
    });
    expect(exported.statusCode).toBe(200);
    expect(exported.json().export_format).toBe("traceguard.policy-draft.v1");
  });

  it("serves GET /v1/policy-decisions and GET /v1/approvals", async () => {
    const decisions = await api.inject({
      method: "GET", url: "/v1/policy-decisions", headers: key
    });
    expect(decisions.statusCode).toBe(200);
    expect(Array.isArray(decisions.json().items)).toBe(true);

    const approvals = await api.inject({ method: "GET", url: "/v1/approvals", headers: key });
    expect(approvals.statusCode).toBe(200);
    expect(Array.isArray(approvals.json().items)).toBe(true);
    expect(approvals.headers["cache-control"]).toBe("no-store");
  });

  it("serves PATCH /v1/budgets/:id", async () => {
    const created = await api.inject({
      method: "POST", url: "/v1/budgets", headers: key,
      payload: { scope: "run", ref_id: randomUUID(), limit_micro: 1000 }
    });
    expect(created.statusCode).toBe(201);
    budgetId = created.json().id;

    const patched = await api.inject({
      method: "PATCH", url: `/v1/budgets/${budgetId}`, headers: key,
      payload: { limit_micro: 2000 }
    });
    expect(patched.statusCode).toBe(200);
    expect(Number(patched.json().limit_micro)).toBe(2000);
  });

  it("serves GET /v1/runs/:id/spans", async () => {
    runId = randomUUID();
    const ingested = await api.inject({
      method: "POST", url: "/v1/ingest/events", headers: key,
      payload: { events: [{
        schema_version: "1", event_id: `evt-${randomUUID()}`,
        agent_name: `contract-${tag}`, run_id: runId, span_id: randomUUID(),
        parent_span_id: null, event_type: "model.request",
        timestamp: "2026-10-13T12:00:00.000Z", status: "success", attributes: {}
      }] }
    });
    expect(ingested.statusCode).toBe(200);

    const spans = await api.inject({
      method: "GET", url: `/v1/runs/${runId}/spans`, headers: key
    });
    expect(spans.statusCode).toBe(200);
    expect(spans.json().items).toHaveLength(1);
    expect(spans.json().items[0].run_id).toBe(runId);
  });
});
