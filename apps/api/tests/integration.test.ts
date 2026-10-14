import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { buildApp } from "../src/index.js";
import { buildGateway } from "../src/gateway.js";
import { pool } from "../src/db.js";

// Full-path suite against a real database and a real MCP upstream. Every
// denial test asserts both the error AND that the upstream saw nothing.
describe("integration and security", () => {
  const api = buildApp();
  const gw = buildGateway();
  const key = { authorization: "Bearer test_key" };
  const approver = { authorization: "Bearer test_approver" };
  const tag = Date.now().toString(36);
  let upstreamHits = 0;
  let upstreamPort = 0;
  let httpServer: ReturnType<typeof createServer>;
  let serverId = "";

  const mock = new McpServer({ name: "test-tools", version: "0.1.0" });
  mock.registerTool("echo", { description: "echo back", inputSchema: { text: z.string() } },
    async ({ text }) => {
      upstreamHits++;
      return { content: [{ type: "text", text: `echo:${text}` }] };
    });

  beforeAll(async () => {
    httpServer = createServer(async (req, res) => {
      if (req.method === "POST") {
        const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
        res.on("close", () => transport.close().catch(() => undefined));
        await mock.connect(transport);
        await transport.handleRequest(req, res);
        return;
      }
      res.writeHead(404).end();
    });
    await new Promise<void>((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
    upstreamPort = (httpServer.address() as { port: number }).port;
  });

  afterAll(async () => {
    httpServer.close();
    await api.close();
    await gw.close();
    await pool.end();
  });

  const ev = (over: Record<string, unknown>) => ({
    schema_version: "1",
    event_id: `evt-${randomUUID()}`,
    agent_name: `sec-${tag}`,
    run_id: randomUUID(),
    span_id: randomUUID(),
    parent_span_id: null,
    event_type: "model.request",
    timestamp: "2026-10-13T12:00:00.000Z",
    status: "success",
    attributes: {},
    ...over
  });

  it("ingests, reads back, and dedupes retries", async () => {
    const runId = randomUUID();
    const body = { events: [ev({ run_id: runId }), ev({ run_id: runId }), ev({ run_id: runId })] };
    const first = await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key, payload: body });
    expect(first.statusCode).toBe(200);
    expect(first.json().accepted).toBe(3);
    const retry = await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key, payload: body });
    expect(retry.json()).toMatchObject({ accepted: 0, duplicates: 3 });
    const trace = await api.inject({ method: "GET", url: `/v1/runs/${runId}/trace`, headers: key });
    expect(trace.json().spans).toHaveLength(3);
  });

  it("rejects oversized batches and unauthenticated reads", async () => {
    const big = { events: Array.from({ length: 501 }, () => ev({})) };
    const res = await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key, payload: big });
    expect(res.statusCode).toBe(400);
    const unauth = await api.inject({ method: "GET", url: "/v1/runs" });
    expect(unauth.statusCode).toBe(401);
  });

  it("registers upstreams without leaking secrets, and refuses unsafe URLs", async () => {
    const bad = await gw.inject({ method: "POST", url: "/v1/servers", headers: key,
      payload: { name: `bad-${tag}`, base_url: "ftp://evil/x" } });
    expect(bad.statusCode).toBe(400);
    const res = await gw.inject({ method: "POST", url: "/v1/servers", headers: key,
      payload: { name: `mock-${tag}`, base_url: `http://127.0.0.1:${upstreamPort}/mcp`, auth_secret: "s3cret" } });
    expect(res.statusCode).toBe(201);
    serverId = res.json().id;
    const list = await gw.inject({ method: "GET", url: "/v1/servers", headers: key });
    expect(JSON.stringify(list.json())).not.toContain("s3cret");
    const disc = await gw.inject({ method: "POST", url: `/v1/servers/${serverId}/discover`, headers: key });
    expect(disc.json().tools.map((t: { tool_name: string }) => t.tool_name)).toContain("echo");
  });

  it("allows listed calls and blocks denied ones without upstream contact", async () => {
    const allow = await gw.inject({ method: "POST", url: "/v1/policies", headers: key,
      payload: { name: `allow-${tag}`, server_id: serverId, tool_name: "echo", effect: "allow" } });
    expect(allow.statusCode).toBe(201);
    const deny = await gw.inject({ method: "POST", url: "/v1/policies", headers: key,
      payload: { name: `deny-${tag}`, priority: 100, server_id: serverId, tool_name: "echo", effect: "deny",
        conditions: { arguments: { text: { regex: "^nope" } } } } });
    expect(deny.statusCode).toBe(201);
    const before = upstreamHits;
    const ok = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: "hi" }, caller: "t" } });
    expect(ok.statusCode).toBe(200);
    expect(upstreamHits).toBe(before + 1);
    const blocked = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: "nope!" }, caller: "t" } });
    expect(blocked.statusCode).toBe(403);
    expect(upstreamHits).toBe(before + 1);
    const unknown = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "ghost", arguments: {}, caller: "t" } });
    expect(unknown.statusCode).toBe(403);
    expect(upstreamHits).toBe(before + 1);
  });

  it("holds approval calls, refuses agent decisions, enforces single use and expiry", async () => {
    const before = upstreamHits;
    await gw.inject({ method: "POST", url: "/v1/policies", headers: key,
      payload: { name: `appr-${tag}`, priority: 50, server_id: serverId, effect: "require_approval" } });
    const call = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: "wait" }, caller: "t", request_id: `r-${tag}` } });
    expect(call.statusCode).toBe(202);
    expect(upstreamHits).toBe(before);
    const approvalId = call.json().approval_id;
    const agentDecision = await gw.inject({ method: "POST", url: `/v1/approvals/${approvalId}/decision`,
      headers: key, payload: { approved: true } });
    expect(agentDecision.statusCode).toBe(401);
    const decided = await gw.inject({ method: "POST", url: `/v1/approvals/${approvalId}/decision`,
      headers: approver, payload: { approved: true, reason: "test" } });
    expect(decided.json().status).toBe("approved");
    const retry = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: "wait" }, caller: "t",
        request_id: `r-${tag}`, approval_id: approvalId } });
    expect(retry.statusCode).toBe(200);
    expect(upstreamHits).toBe(before + 1);
    const replay = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: "wait" }, caller: "t",
        request_id: `r-${tag}`, approval_id: approvalId } });
    expect(replay.statusCode).toBe(410);
    expect(upstreamHits).toBe(before + 1);
    // Sealed at rest: the stored row carries ciphertext, never the plaintext.
    const stored = await pool.query("SELECT args_enc, args FROM approvals WHERE id = $1", [approvalId]);
    expect(stored.rows[0].args_enc).toBe(true);
    expect(JSON.stringify(stored.rows[0].args)).not.toContain("wait");
    const call2 = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: "late" }, caller: "t", request_id: `r2-${tag}` } });
    const approval2 = call2.json().approval_id;
    await pool.query("UPDATE approvals SET expires_at = now() - interval '1 second' WHERE id = $1", [approval2]);
    const late = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: "late" }, caller: "t",
        request_id: `r2-${tag}`, approval_id: approval2 } });
    expect(late.statusCode).toBe(410);
    expect(upstreamHits).toBe(before + 1);
  });

  it("blocks managed calls past a hard budget", async () => {
    await api.inject({ method: "POST", url: "/v1/pricing", headers: key,
      payload: { provider: `p-${tag}`, model: "m", input_price_per_million: 1000000, output_price_per_million: 1000000 } });
    const runId = randomUUID();
    const budget = await api.inject({ method: "POST", url: "/v1/budgets", headers: key,
      payload: { scope: "run", ref_id: runId, limit_micro: 100, effect: "block" } });
    const check = await api.inject({ method: "POST", url: "/v1/budgets/check", headers: key,
      payload: { budget_id: budget.json().id, max_cost_micro: 1000 } });
    expect(check.statusCode).toBe(409);
  });

  it("replays suites and compares versions", async () => {
    const suite = await api.inject({ method: "POST", url: "/v1/evaluations/suites", headers: key,
      payload: { name: `suite-${tag}` } });
    const suiteId = suite.json().id;
    await api.inject({ method: "POST", url: `/v1/evaluations/suites/${suiteId}/cases`, headers: key,
      payload: { name: "c1", assertions: [{ type: "contains", value: "yes" }],
        exec_config: { output: "yes indeed", latency_ms: 5 } } });
    const runA = await api.inject({ method: "POST", url: `/v1/evaluations/suites/${suiteId}/runs`,
      headers: key, payload: { agent_name: `ea-${tag}`, config_fingerprint: "a" } });
    expect(runA.statusCode).toBe(201);
    const runB = await api.inject({ method: "POST", url: `/v1/evaluations/suites/${suiteId}/runs`,
      headers: key, payload: { agent_name: `ea-${tag}`, config_fingerprint: "b",
        exec_overrides: { c1: { output: "no" } } } });
    const aId = runA.json().eval_run.id;
    const bId = runB.json().eval_run.id;
    const cmp = await api.inject({ method: "GET",
      url: `/v1/evaluations/runs/compare?ids=${aId},${bId}`, headers: key });
    const [a, b] = cmp.json().runs;
    expect(a.pass_rate).toBe(1);
    expect(b.pass_rate).toBe(0);
  });

  it("ingests OTLP traces idempotently and finalizes stale runs", async () => {
    const hex = (n: number) => randomUUID().replace(/-/g, "").slice(0, n);
    const traceId = hex(32);
    const rootId = hex(16);
    const childId = hex(16);
    // Current timestamps: fixed old ones sort off the runs pages on busy DBs.
    const nano = (agoMs: number) => String(BigInt(Date.now() - agoMs) * 1_000_000n);
    const payload = {
      resourceSpans: [{
        resource: { attributes: [
          { key: "service.name", value: { stringValue: `otel-${tag}` } }
        ]},
        scopeSpans: [{ spans: [
          { traceId, spanId: rootId, name: "gen_ai.chat",
            startTimeUnixNano: nano(500), endTimeUnixNano: nano(0),
            attributes: [
              { key: "gen_ai.system", value: { stringValue: "openai" } },
              { key: "gen_ai.request.model", value: { stringValue: "gpt-x" } },
              { key: "gen_ai.usage.input_tokens", value: { intValue: "10" } },
              { key: "gen_ai.usage.output_tokens", value: { intValue: "5" } }
            ]},
          { traceId, spanId: childId, parentSpanId: rootId, name: "gen_ai.execute_tool",
            startTimeUnixNano: nano(400), endTimeUnixNano: nano(300),
            attributes: [
              { key: "gen_ai.tool.name", value: { stringValue: "lookup" } }
            ]}
        ]}]
      }]
    };
    const first = await api.inject({ method: "POST", url: "/v1/traces", headers: key, payload });
    expect(first.statusCode).toBe(200);
    expect(first.json()).toMatchObject({ accepted: 2, duplicates: 0 });
    const retry = await api.inject({ method: "POST", url: "/v1/traces", headers: key, payload });
    expect(retry.json()).toMatchObject({ accepted: 0, duplicates: 2 });
    const runs = await api.inject({ method: "GET", url: "/v1/runs?limit=50", headers: key });
    const run = runs.json().items.find((r: { agent_name: string }) => r.agent_name === `otel-${tag}`);
    expect(run).toBeDefined();
    const trace = await api.inject({ method: "GET", url: `/v1/runs/${run.id}/trace`, headers: key });
    const ops = trace.json().spans.map((s: { operation_type: string }) => s.operation_type).sort();
    expect(ops).toEqual(["model.request", "tool.invocation"]);
    await pool.query("UPDATE runs SET started_at = now() - interval '1 hour' WHERE id = $1", [run.id]);
    const stale = await api.inject({ method: "POST",
      url: "/v1/admin/finalize-stale-runs?older_than_seconds=60", headers: key });
    expect(stale.json().ids).toContain(run.id);
  });

  it("alerts webhooks on denials with a verifiable signature", async () => {
    const received: { headers: Record<string, string | string[] | undefined>; body: string }[] = [];
    const stub = createServer((req, res) => {
      let data = "";
      req.on("data", (c) => (data += c));
      req.on("end", () => {
        received.push({ headers: req.headers, body: data });
        res.writeHead(200).end("ok");
      });
    });
    await new Promise<void>((resolve) => stub.listen(0, "127.0.0.1", resolve));
    const port = (stub.address() as { port: number }).port;
    try {
      const sub = await api.inject({ method: "POST", url: "/v1/webhooks", headers: key,
        payload: { name: `hook-${tag}`, url: `http://127.0.0.1:${port}/ping`,
          secret: "hook-secret", events: ["tool.denied"] } });
      expect(sub.statusCode).toBe(201);
      const listed = await api.inject({ method: "GET", url: "/v1/webhooks", headers: key });
      expect(JSON.stringify(listed.json())).not.toContain("hook-secret");
      await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
        payload: { server_id: serverId, tool: "ghost", arguments: {}, caller: "t" } });
      // Delivery runs beside the response, not inside it, so wait for arrival.
      await vi.waitFor(() => expect(received).toHaveLength(1), { timeout: 10000 });
      const [hit] = received;
      expect(hit.headers["x-traceguard-event"]).toBe("tool.denied");
      const { createHmac } = await import("node:crypto");
      const expectSig = createHmac("sha256", "hook-secret").update(hit.body).digest("hex");
      expect(hit.headers["x-traceguard-signature"]).toBe(expectSig);
      expect(JSON.parse(hit.body).tool).toBe("ghost");
      const deliveries = await api.inject({ method: "GET",
        url: "/v1/webhooks/deliveries", headers: key });
      const row = deliveries.json().items.find(
        (d: { subscription_id: string }) => d.subscription_id === sub.json().id);
      expect(row.status).toBe("delivered");
    } finally {
      stub.close();
    }
  });

  it("retains recent data and deletes only what rules allow", async () => {
    const oldRun = randomUUID();
    await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key,
      payload: { events: [ev({ run_id: oldRun })] } });
    await pool.query("UPDATE runs SET started_at = now() - interval '30 days' WHERE id = $1", [oldRun]);
    const freshRun = randomUUID();
    await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key,
      payload: { events: [ev({ run_id: freshRun })] } });
    // Fixed event timestamps age; pin the fresh run to now so it stays kept.
    await pool.query("UPDATE runs SET started_at = now() WHERE id = $1", [freshRun]);
    const rule = await api.inject({ method: "POST", url: "/v1/retention/rules", headers: key,
      payload: { name: `30d-runs-${tag}`, target: "runs", older_than_days: 30 } });
    expect(rule.statusCode).toBe(201);
    const bad = await api.inject({ method: "POST", url: "/v1/retention/rules", headers: key,
      payload: { name: `bad-${tag}`, target: "audit_events", older_than_days: 1 } });
    expect(bad.statusCode).toBe(400);
    const run = await api.inject({ method: "POST", url: "/v1/retention/run", headers: key });
    expect(run.json().deleted[`30d-runs-${tag}`]).toBeGreaterThanOrEqual(1);
    const gone = await api.inject({ method: "GET", url: `/v1/runs/${oldRun}`, headers: key });
    expect(gone.statusCode).toBe(404);
    const kept = await api.inject({ method: "GET", url: `/v1/runs/${freshRun}`, headers: key });
    expect(kept.statusCode).toBe(200);
    // Compliance tables are never valid targets, even by direct insert.
    await expect(
      pool.query(
        `INSERT INTO retention_rules (workspace_id, name, target, older_than_days)
         VALUES ((SELECT id FROM workspaces WHERE name='default'), $1, 'policies', 1)`,
        [`hack-${tag}`]
      )
    ).rejects.toThrow();
  });

  it("keeps the audit hash chain linked", async () => {
    const rows = await pool.query("SELECT hash, prev_hash FROM audit_events ORDER BY timestamp ASC, id ASC LIMIT 200");
    expect(rows.rows.length).toBeGreaterThan(0);
    let prev = "";
    for (const r of rows.rows) {
      expect(r.prev_hash).toBe(prev);
      prev = r.hash;
    }
  });
}, 60000);
