import { createServer } from "node:http";
import type { Server as HttpServer } from "node:http";
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { buildApp } from "../src/index.js";
import { buildGateway, buildGatewayControl } from "../src/gateway.js";
import { pool } from "../src/db.js";
import { publishTestPolicy } from "./policy-helper.js";



// FR-021: every gateway decision carries the trace correlation the caller
// supplied (run_id, span_id, request_id), denied calls leave a span carrying
// the same correlation, and the control listener exposes it on the approval
// card so an approver can open the run the held call belongs to.
describe("trace correlation on policy decisions", () => {
  const api = buildApp();
  const gw = buildGateway();
  const ctl = buildGatewayControl();
  const key = { authorization: "Bearer test_key" };
  const approver = { authorization: "Bearer test_approver" };
  const tag = Date.now().toString(36);
  let port = 0;
  let mockServer: HttpServer | null = null;
  let serverId = "";

  const tools = [
    { name: "run_tool", description: "runs", inputSchema: { type: "object", properties: {} } },
    { name: "blocked_tool", description: "blocked", inputSchema: { type: "object", properties: {} } },
    { name: "held_tool", description: "held", inputSchema: { type: "object", properties: {} } }
  ];

  async function startMock(): Promise<void> {
    const newMock = () => {
      const mock = new Server(
        { name: "corr-tools", version: "0.1.0" },
        { capabilities: { tools: {} } }
      );
      mock.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
      mock.setRequestHandler(CallToolRequestSchema, async () => ({
        content: [{ type: "text", text: "ok" }]
      }));
      return mock;
    };
    const server = createServer(async (req, res) => {
      if (req.method === "POST") {
        const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
        res.on("close", () => transport.close().catch(() => undefined));
        await newMock().connect(transport);
        await transport.handleRequest(req, res);
        return;
      }
      res.writeHead(405).end();
    });
    await new Promise<void>((resolve) => server.listen(port, "127.0.0.1", resolve));
    if (!port) port = (server.address() as { port: number }).port;
    mockServer = server;
  }

  async function createRule(payload: Record<string, unknown>): Promise<void> {
    const res = await api.inject({
      method: "POST", url: "/v1/policies", headers: key,
      payload: { enabled: true, priority: 0, ...payload }
    });
    expect(res.statusCode).toBe(201);
  }

  beforeAll(async () => {
    await startMock();
    const reg = await api.inject({
      method: "POST", url: "/v1/servers", headers: key,
      payload: { name: `corr-${tag}`, base_url: `http://127.0.0.1:${port}/mcp` }
    });
    expect(reg.statusCode).toBe(201);
    serverId = reg.json().id as string;
    const disc = await api.inject({ method: "POST", url: `/v1/servers/${serverId}/discover`, headers: key });
    expect(disc.statusCode).toBe(200);
    await createRule({ name: `corr-allow-${tag}`, effect: "allow" });
    await createRule({ name: `corr-deny-${tag}`, server_id: serverId, tool_name: "blocked_tool", effect: "deny" });
    await createRule({
      name: `corr-hold-${tag}`, server_id: serverId, tool_name: "held_tool", effect: "require_approval"
    });
    await publishTestPolicy(pool);
  });

  afterAll(async () => {
    if (mockServer) await new Promise<void>((resolve) => mockServer?.close(() => resolve()));
    await api.close();
    await gw.close();
    await ctl.close();
    await pool.end();
  });

  function call(payload: Record<string, unknown>) {
    return gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key, payload });
  }

  it("records run, span, and request ids on an allowed decision", async () => {
    const runId = randomUUID();
    const spanId = randomUUID();
    const res = await call({
      server_id: serverId, tool: "run_tool", arguments: {}, caller: "corr-allow",
      request_id: "corr-allow-1", run_id: runId, span_id: spanId
    });
    expect(res.statusCode).toBe(200);

    const rows = await pool.query(
      "SELECT decision, run_id, span_id, request_id FROM policy_decisions WHERE run_id = $1", [runId]
    );
    expect(rows.rows).toHaveLength(1);
    expect(rows.rows[0]).toMatchObject({
      decision: "allow", run_id: runId, span_id: spanId, request_id: "corr-allow-1"
    });
  });

  it("carries the correlation on a denied decision and its denied span", async () => {
    const runId = randomUUID();
    const spanId = randomUUID();
    // The run has to exist before a denied span can reference it (FK), so
    // ingest a normal event for it first — exactly like a real trace.
    const ingested = await api.inject({
      method: "POST", url: "/v1/ingest/events", headers: key,
      payload: {
        events: [{
          schema_version: "1",
          event_id: `evt-${randomUUID()}`,
          agent_name: `corr-${tag}`,
          run_id: runId,
          span_id: randomUUID(),
          parent_span_id: null,
          event_type: "model.request",
          timestamp: "2026-10-13T12:00:00.000Z",
          status: "success",
          attributes: {}
        }]
      }
    });
    expect(ingested.statusCode).toBe(200);

    const res = await call({
      server_id: serverId, tool: "blocked_tool", arguments: {}, caller: "corr-deny",
      request_id: "corr-deny-1", run_id: runId, span_id: spanId
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().error).toBe("tool_blocked");

    const decision = await pool.query(
      "SELECT decision, run_id, span_id, request_id FROM policy_decisions WHERE run_id = $1", [runId]
    );
    expect(decision.rows[0]).toMatchObject({ decision: "deny", run_id: runId, span_id: spanId });

    const spans = await pool.query(
      "SELECT status, error_type, attributes FROM spans WHERE run_id = $1 AND error_type = 'policy_denied'",
      [runId]
    );
    expect(spans.rows).toHaveLength(1);
    expect(spans.rows[0].status).toBe("denied");
    expect(spans.rows[0].attributes).toMatchObject({
      request_id: "corr-deny-1", approval_id: null
    });
  });

  it("links a held call's decision to the approval and exposes the run on the control card", async () => {
    const runId = randomUUID();
    const spanId = randomUUID();
    const res = await call({
      server_id: serverId, tool: "held_tool", arguments: {}, caller: "corr-held",
      request_id: "corr-held-1", run_id: runId, span_id: spanId
    });
    expect(res.statusCode).toBe(202);
    const approvalId = res.json().approval_id as string;

    const decision = await pool.query(
      "SELECT decision, approval_id, run_id, span_id, request_id FROM policy_decisions WHERE run_id = $1",
      [runId]
    );
    expect(decision.rows[0]).toMatchObject({
      decision: "need_approval", approval_id: approvalId,
      run_id: runId, span_id: spanId, request_id: "corr-held-1"
    });

    const listed = await ctl.inject({
      method: "GET", url: "/_control/v1/approvals?status=pending", headers: approver
    });
    expect(listed.statusCode).toBe(200);
    const item = (listed.json().items as Record<string, unknown>[]).find((r) => r.id === approvalId);
    expect(item).toBeTruthy();
    expect(item).toMatchObject({ run_id: runId, span_id: spanId, request_id: "corr-held-1" });
  });

  it("filters decisions by run id and refuses unknown trace ids cleanly", async () => {
    const runId = randomUUID();
    await call({
      server_id: serverId, tool: "run_tool", arguments: {}, caller: "corr-filter",
      request_id: "corr-filter-1", run_id: runId
    });
    const filtered = await gw.inject({
      method: "GET", url: `/v1/decisions?run_id=${runId}`, headers: key
    });
    expect(filtered.statusCode).toBe(200);
    const items = filtered.json().items as { run_id: string; request_id: string }[];
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({ run_id: runId, request_id: "corr-filter-1" });

    const other = await gw.inject({
      method: "GET", url: `/v1/decisions?run_id=${randomUUID()}`, headers: key
    });
    expect(other.json().items).toEqual([]);
  });
});
