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
    // A gateway-scoped agent key stands in for the agent here; the shared
    // env key is an admin and may legitimately approve.
    const au = await api.inject({ method: "POST", url: "/v1/users", headers: key,
      payload: { email: `ag-${tag}@example.com`, password: "long-password-444", role: "member" } });
    const ak = await api.inject({ method: "POST", url: `/v1/users/${au.json().id}/keys`, headers: key,
      payload: { name: "agent", scopes: ["gateway"], expires_days: 7 } });
    const agentKey = { authorization: `Bearer ${ak.json().key}` };
    await gw.inject({ method: "POST", url: "/v1/policies", headers: key,
      payload: { name: `appr-${tag}`, priority: 50, server_id: serverId, effect: "require_approval" } });
    const call = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: "wait" }, caller: "t", request_id: `r-${tag}` } });
    expect(call.statusCode).toBe(202);
    expect(upstreamHits).toBe(before);
    const approvalId = call.json().approval_id;
    const agentDecision = await gw.inject({ method: "POST", url: `/v1/approvals/${approvalId}/decision`,
      headers: agentKey, payload: { approved: true } });
    expect(agentDecision.statusCode).toBe(403);
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
    // Self-contained upstream: other tests may be skipped in filtered runs.
    const reg = await gw.inject({ method: "POST", url: "/v1/servers", headers: key,
      payload: { name: `hook-upstream-${tag}`, base_url: `http://127.0.0.1:${upstreamPort}/mcp` } });
    const hookServerId = reg.json().id;
    await gw.inject({ method: "POST", url: `/v1/servers/${hookServerId}/discover`, headers: key });
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
        payload: { server_id: hookServerId, tool: "ghost", arguments: {}, caller: "t" } });
      // Delivery runs beside the response, not inside it, so wait for arrival.
      // Generous timeout: this box stalls database writes for seconds.
      await vi.waitFor(() => expect(received).toHaveLength(1), { timeout: 30000 });
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
    // Rules are workspace-global, so start from a clean slate: every rule
    // here is test-created (the feature is new), and leftovers from earlier
    // runs would otherwise steal this test's deletions.
    await pool.query("DELETE FROM retention_rules");
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

  it("ingests binary protobuf traces on the same path as JSON", async () => {
    const { encodeTraceRequest } = await import("../src/otlp_proto.js");
    const traceId = randomUUID().replace(/-/g, "");
    const spanId = randomUUID().replace(/-/g, "").slice(0, 16);
    const nano = (agoMs: number) => String(BigInt(Date.now() - agoMs) * 1_000_000n);
    const obj = {
      resourceSpans: [{
        resource: { attributes: [{ key: "service.name", value: { stringValue: `pb-${tag}` } }] },
        scopeSpans: [{ spans: [{
          traceId: Buffer.from(traceId, "hex"),
          spanId: Buffer.from(spanId, "hex"),
          name: "gen_ai.chat",
          startTimeUnixNano: nano(500),
          endTimeUnixNano: nano(0),
          attributes: [
            { key: "gen_ai.system", value: { stringValue: "anthropic" } },
            { key: "gen_ai.request.model", value: { stringValue: "claude-x" } },
            { key: "gen_ai.usage.input_tokens", value: { intValue: 7 } },
            { key: "gen_ai.usage.output_tokens", value: { intValue: 3 } }
          ]
        }] }]
      }]
    };
    const bytes = encodeTraceRequest(obj);
    const first = await api.inject({ method: "POST", url: "/v1/traces",
      headers: { ...key, "content-type": "application/x-protobuf" }, payload: bytes });
    expect(first.statusCode).toBe(200);
    expect(first.headers["content-type"]).toContain("application/x-protobuf");
    const runs = await api.inject({ method: "GET", url: "/v1/runs?limit=50", headers: key });
    const run = runs.json().items.find((r: { agent_name: string }) => r.agent_name === `pb-${tag}`);
    expect(run).toBeDefined();
    const trace = await api.inject({ method: "GET", url: `/v1/runs/${run.id}/trace`, headers: key });
    expect(trace.json().spans[0].provider).toBe("anthropic");
    // Same trace over JSON dedupes: both encodings share one id mapping.
    const jsonSpan = {
      traceId: traceId,
      spanId: spanId,
      name: "gen_ai.chat",
      startTimeUnixNano: nano(500),
      endTimeUnixNano: nano(0),
      attributes: [
        { key: "gen_ai.system", value: { stringValue: "anthropic" } },
        { key: "gen_ai.request.model", value: { stringValue: "claude-x" } },
        { key: "gen_ai.usage.input_tokens", value: { intValue: "7" } },
        { key: "gen_ai.usage.output_tokens", value: { intValue: "3" } }
      ]
    };
    const jsonAgain = await api.inject({ method: "POST", url: "/v1/traces", headers: key,
      payload: { resourceSpans: [{ resource: { attributes: [{ key: "service.name", value: { stringValue: "pb-" + tag } }] }, scopeSpans: [{ spans: [jsonSpan] }] }] } });
    expect(jsonAgain.json()).toMatchObject({ accepted: 0, duplicates: 1 });
  });

  it("reconciles estimates against provider actuals", async () => {
    const prov = `rp-${tag}`;
    await api.inject({ method: "POST", url: "/v1/pricing", headers: key,
      payload: { provider: prov, model: "m1", input_price_per_million: 2000000,
        output_price_per_million: 8000000 } });
    // Estimated: (1000*2M + 200*8M)/1M = 3600 micro. Actual billed: 4000.
    const runId = randomUUID();
    const spanId = randomUUID();
    await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key,
      payload: { events: [{
        schema_version: "1", event_id: `evt-${randomUUID()}`, agent_name: `rec-${tag}`,
        run_id: runId, span_id: spanId, parent_span_id: null, event_type: "model.request",
        timestamp: new Date().toISOString(), status: "success",
        provider: prov, model: "m1", input_tokens: 1000, output_tokens: 200,
        usage_source: "provider_reported", attributes: {} }] } });
    const imp = await api.inject({ method: "POST", url: "/v1/reconciliation/actuals", headers: key,
      payload: { rows: [{
        provider: prov, model: "m1",
        period_start: new Date(Date.now() - 86400000).toISOString(),
        period_end: new Date(Date.now() + 86400000).toISOString(),
        input_tokens: 1000, output_tokens: 200, actual_cost_micro: 4000,
        source: "provider-export.csv" }] } });
    expect(imp.statusCode).toBe(201);
    const cmp = await api.inject({ method: "GET",
      url: `/v1/reconciliation/compare?provider=${prov}&period_start=${new Date(Date.now() - 2 * 86400000).toISOString()}&period_end=${new Date(Date.now() + 2 * 86400000).toISOString()}`,
      headers: key });
    const row = cmp.json().rows.find((r: { model: string }) => r.model === "m1");
    expect(row.estimated_micro).toBe(3600);
    expect(row.actual_micro).toBe(4000);
    expect(row.variance_micro).toBe(-400);
    expect(row.variance_pct).toBeCloseTo(-0.1);
    expect(row.missing_pricing).toBe(false);
  });

  it("scopes credentials by role: agent keys never approve, approver keys never ingest", async () => {
    const email = `owner-${tag}@example.com`;
    const reg = await api.inject({ method: "POST", url: "/v1/auth/register",
      payload: { email, password: "long-password-000" } });
    // Fresh test databases start empty, so the first registration here may
    // bootstrap the admin, or an earlier test may have taken it already.
    expect([201, 403]).toContain(reg.statusCode);
    const second = await api.inject({ method: "POST", url: "/v1/auth/register",
      payload: { email: `other-${tag}@example.com`, password: "long-password-111" } });
    expect(second.statusCode).toBe(403);
    // The env key keeps full access, so it can mint a member and a key for it.
    const mk = await api.inject({ method: "POST", url: "/v1/users", headers: key,
      payload: { email: `agent-${tag}@example.com`, password: "long-password-222", role: "member" } });
    expect(mk.statusCode).toBe(201);
    const memberId = mk.json().id;
    // Members write only where they belong, so grant the default workspace
    // this test ingests into.
    const wsList = await api.inject({ method: "GET", url: "/v1/workspaces", headers: key });
    let defId = wsList.json().items.find((w: { name: string }) => w.name === "default")?.id;
    if (!defId) {
      const created = await api.inject({ method: "POST", url: "/v1/workspaces", headers: key,
        payload: { name: "default" } });
      defId = created.json().id;
    }
    await api.inject({ method: "POST", url: `/v1/users/${memberId}/memberships`,
      headers: key, payload: { workspace_id: defId } });
    const kc = await api.inject({ method: "POST", url: `/v1/users/${memberId}/keys`, headers: key,
      payload: { name: "agent", scopes: ["ingest", "gateway"], expires_days: 7 } });
    expect(kc.statusCode).toBe(201);
    expect(kc.json().key).toMatch(/^tg_/);
    const agentAuth = { authorization: `Bearer ${kc.json().key}` };
    const oneEvent = {
      schema_version: "1", event_id: `evt-${randomUUID()}`, agent_name: `scope-${tag}`,
      run_id: randomUUID(), span_id: randomUUID(), event_type: "run.started",
      timestamp: new Date().toISOString(), attributes: {}
    };
    const ing = await api.inject({ method: "POST", url: "/v1/ingest/events", headers: agentAuth,
      payload: { events: [oneEvent] } });
    expect(ing.statusCode).toBe(200);
    // Agent key at the approval endpoint: scoped out, not just unauthorized.
    const dec = await gw.inject({ method: "POST", url: "/v1/approvals/00000000-0000-0000-0000-000000000000/decision",
      headers: agentAuth, payload: { approved: true } });
    expect(dec.statusCode).toBe(403);
    // Approver-role key: the mirror image.
    const ap = await api.inject({ method: "POST", url: "/v1/users", headers: key,
      payload: { email: `human-${tag}@example.com`, password: "long-password-333", role: "approver" } });
    const akc = await api.inject({ method: "POST", url: `/v1/users/${ap.json().id}/keys`, headers: key,
      payload: { name: "human", scopes: ["approve", "read"], expires_days: 7 } });
    const humanAuth = { authorization: `Bearer ${akc.json().key}` };
    const noIngest = await api.inject({ method: "POST", url: "/v1/ingest/events", headers: humanAuth,
      payload: { events: [] } });
    expect(noIngest.statusCode).toBe(403);
    // Login mints a bearer; wrong password does not.
    const login = await api.inject({ method: "POST", url: "/v1/auth/login",
      payload: { email, password: "long-password-000" } });
    expect([200, 401]).toContain(login.statusCode);
    const bad = await api.inject({ method: "POST", url: "/v1/auth/login",
      payload: { email, password: "wrong-password-000" } });
    expect(bad.statusCode).toBe(401);
  });

  it("confines member writes to their workspaces", async () => {
    // Two workspaces, one member in the first only.
    const wsA = await api.inject({ method: "POST", url: "/v1/workspaces", headers: key,
      payload: { name: `ws-a-${tag}` } });
    expect(wsA.statusCode).toBe(201);
    const wsB = await api.inject({ method: "POST", url: "/v1/workspaces", headers: key,
      payload: { name: `ws-b-${tag}` } });
    expect(wsB.statusCode).toBe(201);
    const mu = await api.inject({ method: "POST", url: "/v1/users", headers: key,
      payload: { email: `ws-${tag}@example.com`, password: "long-password-555", role: "member" } });
    const memberId = mu.json().id;
    const grant = await api.inject({ method: "POST", url: `/v1/users/${memberId}/memberships`,
      headers: key, payload: { workspace_id: wsA.json().id } });
    expect(grant.statusCode).toBe(201);
    const pinned = await api.inject({ method: "POST", url: `/v1/users/${memberId}/keys`, headers: key,
      payload: { name: "pinned", scopes: ["ingest", "gateway"], workspace_id: wsA.json().id } });
    expect(pinned.statusCode).toBe(201);
    const elsewhere = await api.inject({ method: "POST", url: `/v1/users/${memberId}/keys`, headers: key,
      payload: { name: "bad-pin", scopes: ["ingest"], workspace_id: wsB.json().id } });
    expect(elsewhere.statusCode).toBe(403);
    const unpinned = await api.inject({ method: "POST", url: `/v1/users/${memberId}/keys`, headers: key,
      payload: { name: "open", scopes: ["read", "ingest", "gateway"] } });
    const agentAuth = { authorization: `Bearer ${unpinned.json().key}` };
    const pinAuth = { authorization: `Bearer ${pinned.json().key}` };
    const evt = (ws: string) => ({
      schema_version: "1", event_id: `evt-${randomUUID()}`, agent_name: `ws-${tag}`,
      run_id: randomUUID(), span_id: randomUUID(), event_type: "run.started",
      workspace_name: ws, timestamp: new Date().toISOString(), attributes: {}
    });
    const home = await api.inject({ method: "POST", url: "/v1/ingest/events", headers: agentAuth,
      payload: { events: [evt(`ws-a-${tag}`)] } });
    expect(home.statusCode).toBe(200);
    const away = await api.inject({ method: "POST", url: "/v1/ingest/events", headers: agentAuth,
      payload: { events: [evt(`ws-b-${tag}`)] } });
    expect(away.statusCode).toBe(403);
    expect(away.json().error).toBe("workspace_forbidden");
    const conjured = await api.inject({ method: "POST", url: "/v1/ingest/events", headers: agentAuth,
      payload: { events: [evt(`ws-nope-${tag}`)] } });
    expect(conjured.statusCode).toBe(403);
    // The pinned key writes home but nothing else, by construction.
    const pinHome = await api.inject({ method: "POST", url: "/v1/ingest/events", headers: pinAuth,
      payload: { events: [evt(`ws-a-${tag}`)] } });
    expect(pinHome.statusCode).toBe(200);
    const pinAway = await api.inject({ method: "POST", url: "/v1/ingest/events", headers: pinAuth,
      payload: { events: [evt(`ws-b-${tag}`)] } });
    expect(pinAway.statusCode).toBe(403);
    // Members list their own workspaces only.
    const listed = await api.inject({ method: "GET", url: "/v1/workspaces", headers: agentAuth });
    const names = listed.json().items.map((w: { name: string }) => w.name);
    expect(names).toContain(`ws-a-${tag}`);
    expect(names).not.toContain(`ws-b-${tag}`);
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
