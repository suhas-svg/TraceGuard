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
    expect(trace.json().run.agent_name).toBe(`sec-${tag}`);
  });

  it("totals runs by status and denied spans, authenticated only", async () => {
    const done = randomUUID();
    const failed = randomUUID();
    await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key, payload: {
      events: [
        ev({ run_id: done, event_type: "run.completed" }),
        ev({ run_id: failed, status: "denied" })
      ]
    } });
    await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key, payload: {
      events: [ev({ run_id: failed, event_type: "run.failed", error_type: "boom" })]
    } });

    const res = await api.inject({ method: "GET", url: "/v1/runs/counts", headers: key });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { counts: Record<string, number>; total: number; denied_spans: number };
    expect(body.counts.success).toBeGreaterThanOrEqual(1);
    expect(body.counts.failed).toBeGreaterThanOrEqual(1);
    expect(body.denied_spans).toBeGreaterThanOrEqual(1);
    // The tiles must agree with the list they sit above.
    expect(body.total).toBe(Object.values(body.counts).reduce((a, b) => a + b, 0));

    const unauth = await api.inject({ method: "GET", url: "/v1/runs/counts" });
    expect(unauth.statusCode).toBe(401);
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
    // Cloud metadata addresses are never valid upstreams, even when private
    // upstreams are allowed.
    const metadata = await gw.inject({ method: "POST", url: "/v1/servers", headers: key,
      payload: { name: `meta-${tag}`, base_url: "http://169.254.169.254/mcp" } });
    expect(metadata.statusCode).toBe(400);
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
    // Sealed at rest while pending/approved: ciphertext, never the plaintext.
    const stored = await pool.query("SELECT args_enc, args FROM approvals WHERE id = $1", [approvalId]);
    expect(stored.rows[0].args_enc).toBe(true);
    expect(JSON.stringify(stored.rows[0].args)).not.toContain("wait");
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
    // Consumption drops the sealed arguments: only the redacted summary and
    // the args hash remain once the call has executed.
    const consumed = await pool.query(
      "SELECT status, args_enc, args, args_summary FROM approvals WHERE id = $1", [approvalId]);
    expect(consumed.rows[0].status).toBe("consumed");
    expect(consumed.rows[0].args_enc).toBe(false);
    expect(consumed.rows[0].args).toEqual({});
    expect(consumed.rows[0].args_summary).toContain("wait");
    const call2 = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: "late" }, caller: "t", request_id: `r2-${tag}` } });
    const approval2 = call2.json().approval_id;
    await pool.query("UPDATE approvals SET expires_at = now() - interval '1 second' WHERE id = $1", [approval2]);
    const late = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: "late" }, caller: "t",
        request_id: `r2-${tag}`, approval_id: approval2 } });
    expect(late.statusCode).toBe(410);
    expect(upstreamHits).toBe(before + 1);
    // Expiry clears the sealed arguments too, keeping the summary.
    const expired = await pool.query(
      "SELECT status, args_enc, args_summary FROM approvals WHERE id = $1", [approval2]);
    expect(expired.rows[0].status).toBe("expired");
    expect(expired.rows[0].args_enc).toBe(false);
    expect(expired.rows[0].args_summary).toContain("late");
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
        exec_config: { output: "yes indeed", latency_ms: 5, input_tokens: 7, output_tokens: 3,
          provider: `ep-${tag}` } } });
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
    // No price row exists for the scripted adapter: cost stays unknown, never
    // zero, while token usage sums the spans the replay wrote.
    expect(a.cost_micro).toBeNull();
    expect(a.input_tokens).toBe(7);
    expect(a.output_tokens).toBe(3);
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
      // notify() writes the delivery row only after its fetch resolves, so
      // poll for the row instead of racing it.
      await vi.waitFor(async () => {
        const deliveries = await api.inject({ method: "GET",
          url: "/v1/webhooks/deliveries", headers: key });
        const row = deliveries.json().items.find(
          (d: { subscription_id: string }) => d.subscription_id === sub.json().id);
        expect(row?.status).toBe("delivered");
      }, { timeout: 30000 });
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

  it("scopes reads to member workspaces", async () => {
    // Reuse the ws-a/ws-b member from the write test via fresh fixtures.
    const wsA = await api.inject({ method: "POST", url: "/v1/workspaces", headers: key,
      payload: { name: `rs-a-${tag}` } });
    const wsB = await api.inject({ method: "POST", url: "/v1/workspaces", headers: key,
      payload: { name: `rs-b-${tag}` } });
    const mu = await api.inject({ method: "POST", url: "/v1/users", headers: key,
      payload: { email: `rs-${tag}@example.com`, password: "long-password-666", role: "member" } });
    const memberId = mu.json().id;
    await api.inject({ method: "POST", url: `/v1/users/${memberId}/memberships`,
      headers: key, payload: { workspace_id: wsA.json().id } });
    const kc = await api.inject({ method: "POST", url: `/v1/users/${memberId}/keys`, headers: key,
      payload: { name: "reader", scopes: ["read", "ingest"] } });
    const reader = { authorization: `Bearer ${kc.json().key}` };
    const evt = (ws: string) => ({
      schema_version: "1", event_id: `evt-${randomUUID()}`, agent_name: `rs-${tag}`,
      run_id: randomUUID(), span_id: randomUUID(), event_type: "run.started",
      workspace_name: ws, timestamp: new Date().toISOString(), attributes: {}
    });
    // One run per workspace, ingested as admin so both exist.
    for (const ws of [`rs-a-${tag}`, `rs-b-${tag}`]) {
      await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key,
        payload: { events: [evt(ws)] } });
    }
    const listed = await api.inject({ method: "GET", url: "/v1/runs?limit=200", headers: reader });
    expect(listed.json().items.length).toBeGreaterThan(0);
    // Every listed run must belong to ws-a.
    for (const r of listed.json().items.filter((x: { agent_name: string }) => x.agent_name === `rs-${tag}`)) {
      expect(r.workspace_id).toBe(wsA.json().id);
    }
    const foreign = listed.json().items.find((x: { agent_name: string }) => x.agent_name === `rs-${tag}` && x.workspace_id === wsB.json().id);
    expect(foreign).toBeUndefined();
    // Direct detail, trace, and usage on the foreign run read as missing.
    const adminList = await api.inject({ method: "GET", url: "/v1/runs?limit=200", headers: key });
    const foreignRun = adminList.json().items.find((x: { workspace_id: string }) => x.workspace_id === wsB.json().id);
    expect(foreignRun).toBeDefined();
    for (const url of [`/v1/runs/${foreignRun.id}`, `/v1/runs/${foreignRun.id}/trace`, `/v1/runs/${foreignRun.id}/usage`]) {
      const res = await api.inject({ method: "GET", url, headers: reader });
      expect(res.statusCode).toBe(404);
    }
    // Servers and policies from the other workspace stay hidden too.
    const srv = await gw.inject({ method: "GET", url: "/v1/servers", headers: reader });
    expect(srv.json().items.every((s: { workspace_id: string }) => s.workspace_id !== wsB.json().id)).toBe(true);
    const pol = await gw.inject({ method: "GET", url: "/v1/policies", headers: reader });
    expect(pol.json().items.every((p: { workspace_id: string }) => p.workspace_id !== wsB.json().id)).toBe(true);
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

  it("agent-scoped rules take effect when the call names its agent", async () => {
    // Agent-scoped rules need a real agent row (FK), which ingest creates.
    const agentName = `ag-deny-${tag}`;
    const ingested = await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key,
      payload: { events: [ev({ agent_name: agentName })] } });
    expect(ingested.statusCode).toBe(200);
    const agentA = (await pool.query("SELECT id FROM agents WHERE name = $1", [agentName])).rows[0].id;
    await gw.inject({ method: "POST", url: "/v1/policies", headers: key,
      payload: { name: `agent-deny-${tag}`, priority: 200, agent_id: agentA, effect: "deny" } });
    const before = upstreamHits;
    const hit = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: "hi" }, caller: "t", agent_id: agentA } });
    expect(hit.statusCode).toBe(403);
    expect(hit.json().reason).toContain(`agent-deny-${tag}`);
    expect(upstreamHits).toBe(before);
    const other = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: "hi" }, caller: "t", agent_id: randomUUID() } });
    expect([200, 202]).toContain(other.statusCode);
  });

  it("records a denied gateway call as a denied span in the run trace", async () => {
    const runId = randomUUID();
    await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key,
      payload: { events: [ev({ run_id: runId })] } });
    const denied = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "ghost", arguments: {}, caller: "t", run_id: runId } });
    expect(denied.statusCode).toBe(403);
    const trace = await api.inject({ method: "GET", url: `/v1/runs/${runId}/trace`, headers: key });
    const span = trace.json().spans.find((s: { status: string }) => s.status === "denied");
    expect(span).toBeDefined();
    expect(span.error_type).toBe("policy_denied");
    expect(span.attributes.tool).toBe("ghost");
  });

  it("consumes an approved call exactly once under concurrent retries", async () => {
    const call = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: "racy" }, caller: "t" } });
    expect(call.statusCode).toBe(202);
    const approvalId = call.json().approval_id;
    await gw.inject({ method: "POST", url: `/v1/approvals/${approvalId}/decision`, headers: approver,
      payload: { approved: true } });
    const before = upstreamHits;
    const payload = { server_id: serverId, tool: "echo", arguments: { text: "racy" }, caller: "t",
      approval_id: approvalId };
    const [a, b] = await Promise.all([
      gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key, payload }),
      gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key, payload })
    ]);
    const codes = [a.statusCode, b.statusCode].sort((x, y) => x - y);
    expect(codes).toEqual([200, 410]);
    expect(upstreamHits).toBe(before + 1);
  });

  it("serializes concurrent budget checks against an exhausted limit", async () => {
    const runId = randomUUID();
    const budget = await api.inject({ method: "POST", url: "/v1/budgets", headers: key,
      payload: { scope: "run", ref_id: runId, limit_micro: 100, effect: "block" } });
    const budgetId = budget.json().id;
    const [a, b] = await Promise.all([
      api.inject({ method: "POST", url: "/v1/budgets/check", headers: key,
        payload: { budget_id: budgetId, max_cost_micro: 60 } }),
      api.inject({ method: "POST", url: "/v1/budgets/check", headers: key,
        payload: { budget_id: budgetId, max_cost_micro: 60 } })
    ]);
    const codes = [a.statusCode, b.statusCode].sort((x, y) => x - y);
    expect(codes).toEqual([200, 409]);
  });

  it("does not re-issue a tool call after an upstream error", async () => {
    let callRequests = 0;
    const flaky = new McpServer({ name: "flaky-tools", version: "0.1.0" });
    flaky.registerTool("boom", { description: "fails at the protocol level", inputSchema: {} },
      async () => ({ content: [{ type: "text", text: "unused" }] }));
    const flakyHttp = createServer(async (req, res) => {
      if (req.method !== "POST") {
        res.writeHead(404).end();
        return;
      }
      let raw = "";
      for await (const chunk of req) raw += chunk;
      const body = JSON.parse(raw) as { method?: string; id?: unknown };
      if (body.method === "tools/call") {
        // The upstream receives the call and answers with an error frame.
        // A failed or lost response must not be auto-reissued: the call
        // already reached the server, and the gateway cannot prove otherwise.
        callRequests++;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: body.id,
          error: { code: -32000, message: "upstream exploded" } }));
        return;
      }
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      res.on("close", () => transport.close().catch(() => undefined));
      await flaky.connect(transport);
      await transport.handleRequest(req, res, body).catch(() => undefined);
    });
    await new Promise<void>((resolve) => flakyHttp.listen(0, "127.0.0.1", resolve));
    const port = (flakyHttp.address() as { port: number }).port;
    try {
      const reg = await gw.inject({ method: "POST", url: "/v1/servers", headers: key,
        payload: { name: `flaky-${tag}`, base_url: `http://127.0.0.1:${port}/mcp` } });
      const sid = reg.json().id;
      await gw.inject({ method: "POST", url: `/v1/servers/${sid}/discover`, headers: key });
      await gw.inject({ method: "POST", url: "/v1/policies", headers: key,
        payload: { name: `flaky-allow-${tag}`, server_id: sid, tool_name: "boom", effect: "allow" } });
      const res = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
        payload: { server_id: sid, tool: "boom", arguments: {}, caller: "t" } });
      expect(res.statusCode).toBe(502);
      expect(callRequests).toBe(1);
      // The failure is evidence too: the decision row and audit both record
      // it, so operators can see why a managed call died.
      const decision = await pool.query(
        "SELECT decision, reason FROM policy_decisions WHERE server_id = $1 ORDER BY timestamp DESC LIMIT 1",
        [sid]
      );
      expect(decision.rows[0].decision).toBe("error");
      expect(String(decision.rows[0].reason)).toContain("upstream error");
      const audited = await pool.query(
        "SELECT result FROM audit_events WHERE action = 'tool.execute' AND resource_id = $1 ORDER BY timestamp DESC LIMIT 1",
        [sid]
      );
      expect(audited.rows[0].result).toBe("failed");
    } finally {
      flakyHttp.close();
      flakyHttp.closeAllConnections();
    }
  });
  it("re-evaluates policy on approval retry: a newer deny beats the approval", async () => {
    const staleArgs = { text: `stale-${tag}` };
    const call = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: staleArgs, caller: "t",
        request_id: `stale-${tag}` } });
    expect(call.statusCode).toBe(202);
    const approvalId = call.json().approval_id;
    const decided = await gw.inject({ method: "POST", url: `/v1/approvals/${approvalId}/decision`,
      headers: approver, payload: { approved: true, reason: "looked fine then" } });
    expect(decided.statusCode).toBe(200);
    // A deny rule lands after the approval was issued. It must win: an
    // approval never overrides an unconditional deny.
    const deny = await gw.inject({ method: "POST", url: "/v1/policies", headers: key,
      payload: { name: `late-deny-${tag}`, priority: 300, server_id: serverId, tool_name: "echo",
        effect: "deny", conditions: { arguments: { text: { enum: [staleArgs.text] } } } } });
    expect(deny.statusCode).toBe(201);
    const before = upstreamHits;
    const retry = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: staleArgs, caller: "t",
        request_id: `stale-${tag}`, approval_id: approvalId } });
    expect(retry.statusCode).toBe(403);
    expect(retry.json().reason).toContain(`late-deny-${tag}`);
    expect(upstreamHits).toBe(before);
    // The denied retry did not consume the approval.
    const row = await pool.query("SELECT status FROM approvals WHERE id = $1", [approvalId]);
    expect(row.rows[0].status).toBe("approved");
  });

  it("denies gateway calls once a covering block budget is exhausted", async () => {
    const runId = randomUUID();
    await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key,
      payload: { events: [ev({ run_id: runId, event_type: "run.started" })] } });
    const budget = await api.inject({ method: "POST", url: "/v1/budgets", headers: key,
      payload: { scope: "run", ref_id: runId, limit_micro: 100, effect: "block" } });
    expect(budget.statusCode).toBe(201);
    await pool.query("UPDATE budgets SET spent_micro = 100 WHERE id = $1", [budget.json().id]);
    const before = upstreamHits;
    const denied = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: "afford?" }, caller: "t",
        run_id: runId } });
    expect(denied.statusCode).toBe(403);
    expect(denied.json().error).toBe("budget_exceeded");
    expect(denied.json().budget_id).toBe(budget.json().id);
    expect(upstreamHits).toBe(before);
    // The denial is visible in the run trace, citing the budget.
    const trace = await api.inject({ method: "GET", url: `/v1/runs/${runId}/trace`, headers: key });
    const span = trace.json().spans.find((s: { status: string }) => s.status === "denied");
    expect(span?.attributes?.reason).toContain("budget exhausted");
  });

  it("settles a reservation exactly once under concurrent retries", async () => {
    const budget = await api.inject({ method: "POST", url: "/v1/budgets", headers: key,
      payload: { scope: "run", ref_id: randomUUID(), limit_micro: 1000000, effect: "block" } });
    const budgetId = budget.json().id;
    const reserve = await api.inject({ method: "POST", url: "/v1/budgets/check", headers: key,
      payload: { budget_id: budgetId, max_cost_micro: 500 } });
    expect(reserve.statusCode).toBe(200);
    const reservationId = reserve.json().reservation_id;
    const [a, b] = await Promise.all([
      api.inject({ method: "POST", url: "/v1/budgets/settle", headers: key,
        payload: { reservation_id: reservationId, actual_cost_micro: 70 } }),
      api.inject({ method: "POST", url: "/v1/budgets/settle", headers: key,
        payload: { reservation_id: reservationId, actual_cost_micro: 70 } })
    ]);
    const codes = [a.statusCode, b.statusCode].sort((x, y) => x - y);
    expect(codes).toEqual([200, 409]);
    // One settle landed: spent counted once, the hold fully released.
    const row = await pool.query(
      "SELECT spent_micro::float8 AS spent, reserved_micro::float8 AS reserved FROM budgets WHERE id = $1",
      [budgetId]);
    expect(row.rows[0].spent).toBe(70);
    expect(row.rows[0].reserved).toBe(0);
  });

  it("redacts secrets at ingest and withholds raw content unless capture is on", async () => {
    const secret = `sk-live-${randomUUID().replace(/-/g, "")}`;
    const runId = randomUUID();
    await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key,
      payload: { events: [ev({ run_id: runId, attributes: {
        api_key: secret, prompt: "the raw prompt", nested: { token: secret } } })] } });
    const trace = await api.inject({ method: "GET", url: `/v1/runs/${runId}/trace`, headers: key });
    const attrs = trace.json().spans[0].attributes;
    expect(JSON.stringify(attrs)).not.toContain(secret);
    expect(attrs.prompt).toBe("[NOT CAPTURED]");
    expect(attrs.nested.token).toBe("[REDACTED]");
    // Capture mode is opt-in: content survives, secrets never do.
    process.env.CAPTURE_RAW_ATTRIBUTES = "true";
    try {
      const runId2 = randomUUID();
      await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key,
        payload: { events: [ev({ run_id: runId2, attributes: { prompt: "the raw prompt", api_key: secret } })] } });
      const t2 = await api.inject({ method: "GET", url: `/v1/runs/${runId2}/trace`, headers: key });
      const a2 = t2.json().spans[0].attributes;
      expect(a2.prompt).toBe("the raw prompt");
      expect(JSON.stringify(a2)).not.toContain(secret);
    } finally {
      delete process.env.CAPTURE_RAW_ATTRIBUTES;
    }
  });

  it("keeps only a redacted summary when an approval is denied or consumed", async () => {
    const secret = `sk-live-${randomUUID().replace(/-/g, "")}`;
    const call = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: secret }, caller: "t",
        request_id: `summ-${tag}` } });
    expect(call.statusCode).toBe(202);
    const deniedId = call.json().approval_id;
    const dec = await gw.inject({ method: "POST", url: `/v1/approvals/${deniedId}/decision`,
      headers: approver, payload: { approved: false, reason: "no" } });
    expect(dec.statusCode).toBe(200);
    const deniedRow = (await pool.query(
      "SELECT status, args_enc, args, args_summary FROM approvals WHERE id = $1", [deniedId])).rows[0];
    expect(deniedRow.status).toBe("denied");
    expect(deniedRow.args_enc).toBe(false);
    expect(deniedRow.args).toEqual({});
    expect(deniedRow.args_summary).toContain("[REDACTED]");
    expect(deniedRow.args_summary).not.toContain(secret);
    // Consumed: the call executes, then the sealed arguments are dropped.
    const call2 = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: `ok-${tag}` }, caller: "t",
        request_id: `summ2-${tag}` } });
    expect(call2.statusCode).toBe(202);
    const okId = call2.json().approval_id;
    await gw.inject({ method: "POST", url: `/v1/approvals/${okId}/decision`, headers: approver,
      payload: { approved: true } });
    const midRow = (await pool.query("SELECT args_enc, args FROM approvals WHERE id = $1", [okId])).rows[0];
    expect(midRow.args_enc).toBe(true);
    expect(JSON.stringify(midRow.args)).not.toContain(`ok-${tag}`);
    const retry = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: `ok-${tag}` }, caller: "t",
        request_id: `summ2-${tag}`, approval_id: okId } });
    expect(retry.statusCode).toBe(200);
    const goneRow = (await pool.query(
      "SELECT status, args_enc, args, args_summary FROM approvals WHERE id = $1", [okId])).rows[0];
    expect(goneRow.status).toBe("consumed");
    expect(goneRow.args_enc).toBe(false);
    expect(goneRow.args).toEqual({});
    expect(goneRow.args_summary).toContain(`ok-${tag}`);
  });

  it("flags loop-shaped runs in diagnostics without blocking anything", async () => {
    const runId = randomUUID();
    await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key,
      payload: { events: [ev({ run_id: runId, event_type: "run.started" })] } });
    const failing = Array.from({ length: 3 }, () =>
      ev({ run_id: runId, event_type: "tool.invocation", status: "failed",
        error_type: "tool_error", attributes: { server_id: "s1", tool: "flaky" } }));
    await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key,
      payload: { events: failing } });
    const res = await api.inject({ method: "GET", url: `/v1/runs/${runId}/diagnostics`, headers: key });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { warnings: { code: string }[] };
    expect(body.warnings.map((w) => w.code)).toContain("repeated_tool_failures");
    const missing = await api.inject({ method: "GET",
      url: `/v1/runs/${randomUUID()}/diagnostics`, headers: key });
    expect(missing.statusCode).toBe(404);
    const unauth = await api.inject({ method: "GET", url: `/v1/runs/${runId}/diagnostics` });
    expect(unauth.statusCode).toBe(401);
  });

  it("serves an overview with usage, spend, latency and queue totals", async () => {
    const runId = randomUUID();
    const prov = `ov-${tag}`;
    await api.inject({ method: "POST", url: "/v1/pricing", headers: key,
      payload: { provider: prov, model: "m", input_price_per_million: 1000000,
        output_price_per_million: 1000000 } });
    const startedAt = new Date(Date.now() - 5000).toISOString();
    await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key, payload: {
      events: [
        // Timestamp after the pricing row so the effective_from LATERAL
        // join resolves it; the `since` window below still includes it.
        ev({ run_id: runId, event_type: "model.request", timestamp: new Date().toISOString(),
          provider: prov, model: "m", input_tokens: 100, output_tokens: 10,
          usage_source: "provider_reported" }),
        ev({ run_id: runId, event_type: "run.completed", timestamp: new Date().toISOString() })
      ]
    } });
    const res = await api.inject({ method: "GET",
      url: `/v1/overview?since=${encodeURIComponent(startedAt)}`, headers: key });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.runs.total).toBeGreaterThanOrEqual(1);
    expect(body.tokens.input_tokens).toBeGreaterThanOrEqual(100);
    // (100 in + 10 out) micro-tokens at 1M micro per million = 110 micro.
    expect(body.cost.estimated_cost_micro).toBeGreaterThanOrEqual(110);
    expect(typeof body.cost.cost_partial).toBe("boolean");
    expect(typeof body.denied_spans).toBe("number");
    expect(typeof body.pending_approvals).toBe("number");
    expect(body.latency_ms.median === null || body.latency_ms.median >= 0).toBe(true);
    const unauth = await api.inject({ method: "GET", url: "/v1/overview" });
    expect(unauth.statusCode).toBe(401);
  });

  it("caps a project's spend, measured from the project rather than a counter", async () => {
    // The default workspace is the project. A project budget measures what the
    // project actually spent, so a one-micro cap is already exceeded by the
    // spend in this database and the first check must refuse it.
    const ws = await api.inject({ method: "GET", url: "/v1/workspaces", headers: key });
    const def = ws.json().items.find((w: { name: string }) => w.name === "default");
    const b = await api.inject({ method: "POST", url: "/v1/budgets", headers: key,
      payload: { scope: "project", ref_id: def.id, limit_micro: 1, effect: "block" } });
    expect(b.statusCode).toBe(201);

    const check = await api.inject({ method: "POST", url: "/v1/budgets/check", headers: key,
      payload: { budget_id: b.json().id, max_cost_micro: 0 } });
    // Measuring the budget's own ledger instead returns 0 spent and a 200 with
    // the whole limit apparently available, which is the bug this pins.
    expect(check.statusCode).toBe(409);
    expect(check.json().spent_micro).toBeGreaterThan(0);

    // The list agrees, so the dashboard cannot show headroom that is not there.
    const list = await api.inject({ method: "GET", url: "/v1/budgets?scope=project&limit=500", headers: key });
    const row = list.json().items.find((x: { id: string }) => x.id === b.json().id);
    expect(row.spent_micro).toBeGreaterThan(0);
    expect(row.remaining_micro).toBeLessThan(0);
  });

  it("refuses a project budget that names no workspace", async () => {
    const res = await api.inject({ method: "POST", url: "/v1/budgets", headers: key,
      payload: { scope: "project", ref_id: randomUUID(), limit_micro: 1000 } });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("unknown_workspace");
  });

  it("groups costs by agent, project, and reporting period", async () => {
    // Section 12.1 names all of these dimensions. Each branch builds different
    // SQL, so each one has to be executed, not just accepted as a parameter.
    const prov = `grp-${tag}`;
    const agentName = `grp-agent-${tag}`;
    await api.inject({ method: "POST", url: "/v1/pricing", headers: key,
      payload: { provider: prov, model: "m", input_price_per_million: 1_000_000,
        output_price_per_million: 0 } });
    const runId = randomUUID();
    await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key, payload: {
      events: [
        ev({ run_id: runId, agent_name: agentName, event_type: "model.request",
          timestamp: new Date().toISOString(), provider: prov, model: "m",
          input_tokens: 500, output_tokens: 0, usage_source: "provider_reported" }),
        ev({ run_id: runId, agent_name: agentName, event_type: "run.completed",
          timestamp: new Date().toISOString() })
      ] } });
    const start = new Date(Date.now() - 3_600_000).toISOString();
    const end = new Date(Date.now() + 60_000).toISOString();
    const q = `period_start=${encodeURIComponent(start)}&period_end=${encodeURIComponent(end)}`;

    const byAgent = await api.inject({ method: "GET",
      url: `/v1/reconciliation/compare?${q}&group_by=agent`, headers: key });
    expect(byAgent.statusCode).toBe(200);
    expect(byAgent.json().group_by).toBe("agent");
    const agentRow = byAgent.json().rows.find((r: { model: string }) => r.model === agentName);
    expect(agentRow?.estimated_micro).toBeGreaterThanOrEqual(500);
    // Actuals are recorded per provider and model, so another dimension reports
    // no actual rather than a share of one that would be invented.
    expect(agentRow?.actual_micro).toBeNull();

    const byProject = await api.inject({ method: "GET",
      url: `/v1/reconciliation/compare?${q}&group_by=project`, headers: key });
    expect(byProject.statusCode).toBe(200);
    expect(byProject.json().rows.length).toBeGreaterThanOrEqual(1);
    expect(byProject.json().rows.every((r: { actual_micro: unknown }) => r.actual_micro === null)).toBe(true);

    const byPeriod = await api.inject({ method: "GET",
      url: `/v1/reconciliation/compare?${q}&group_by=period&bucket=day`, headers: key });
    expect(byPeriod.statusCode).toBe(200);
    expect(byPeriod.json().rows.length).toBeGreaterThanOrEqual(1);
    expect(byPeriod.json().rows.every((r: { estimated_micro: number }) => r.estimated_micro >= 0)).toBe(true);

    const bad = await api.inject({ method: "GET",
      url: `/v1/reconciliation/compare?${q}&group_by=nope`, headers: key });
    expect(bad.statusCode).toBe(400);
    expect(bad.json().error).toBe("invalid_group_by");
  });

  it("filters runs by date window, provider, model and evaluation run", async () => {
    const runId = randomUUID();
    const prov = `flt-${tag}`;
    await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key, payload: {
      events: [ev({ run_id: runId, provider: prov, model: "fm", event_type: "model.request",
        timestamp: new Date(Date.now() - 60000).toISOString() })]
    } });
    const anHourAgo = encodeURIComponent(new Date(Date.now() - 3600000).toISOString());
    const listed = await api.inject({ method: "GET",
      url: `/v1/runs?provider=${prov}&model=fm&since=${anHourAgo}&limit=50`, headers: key });
    const ids = listed.json().items.map((r: { id: string }) => r.id);
    expect(ids).toContain(runId);
    // A window that ends before the run started excludes it.
    const before = await api.inject({ method: "GET",
      url: `/v1/runs?provider=${prov}&until=${anHourAgo}`, headers: key });
    expect(before.json().items).toHaveLength(0);
    const none = await api.inject({ method: "GET", url: `/v1/runs?provider=nope-${tag}`, headers: key });
    expect(none.json().items).toHaveLength(0);
    // eval_run_id narrows to the agent runs replayed by one evaluation run.
    const suite = await api.inject({ method: "POST", url: "/v1/evaluations/suites", headers: key,
      payload: { name: `flt-suite-${tag}` } });
    await api.inject({ method: "POST", url: `/v1/evaluations/suites/${suite.json().id}/cases`, headers: key,
      payload: { name: "c1", assertions: [{ type: "contains", value: "yes" }],
        exec_config: { output: "yes", latency_ms: 1 } } });
    const evalRun = await api.inject({ method: "POST", url: `/v1/evaluations/suites/${suite.json().id}/runs`,
      headers: key, payload: { agent_name: `flt-ea-${tag}` } });
    const evalRunId = evalRun.json().eval_run.id;
    const agentRunId = evalRun.json().results[0].agent_run_id;
    const byEval = await api.inject({ method: "GET",
      url: `/v1/runs?eval_run_id=${evalRunId}&limit=200`, headers: key });
    const evalIds = byEval.json().items.map((r: { id: string }) => r.id);
    expect(evalIds).toContain(agentRunId);
    expect(evalIds).toHaveLength(1);
  });

  it("lists agents for the dashboard filter", async () => {
    // Self-contained: on long-lived dev databases the 500-name page can push
    // older entries past the cutoff, so plant an agent whose name sorts first.
    const listed = `aaa-list-${tag}`;
    await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key,
      payload: { events: [ev({ agent_name: listed, event_type: "run.started" })] } });
    const res = await api.inject({ method: "GET", url: "/v1/agents", headers: key });
    expect(res.statusCode).toBe(200);
    const names = res.json().items.map((a: { name: string }) => a.name);
    expect(names).toContain(listed);
    const unauth = await api.inject({ method: "GET", url: "/v1/agents" });
    expect(unauth.statusCode).toBe(401);
  });

  it("keeps historical estimates on the price version in force at span time", async () => {
    const prov = `hist-${tag}`;
    await api.inject({ method: "POST", url: "/v1/pricing", headers: key,
      payload: { provider: prov, model: "m1", input_price_per_million: 1_000_000, output_price_per_million: 0 } });
    const runId = randomUUID();
    await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key,
      payload: { events: [ev({ run_id: runId, provider: prov, model: "m1",
        input_tokens: 1000, output_tokens: 0, timestamp: new Date().toISOString() })] } });
    const before = await api.inject({ method: "GET", url: `/v1/runs/${runId}/usage`, headers: key });
    expect(before.json().estimated_cost_micro).toBe(1000);
    // A newer price must not rewrite history: estimates pin the price in
    // force when the span ran, not the latest row on the price list.
    await api.inject({ method: "POST", url: "/v1/pricing", headers: key,
      payload: { provider: prov, model: "m1", input_price_per_million: 9_000_000, output_price_per_million: 0 } });
    const after = await api.inject({ method: "GET", url: `/v1/runs/${runId}/usage`, headers: key });
    expect(after.json().estimated_cost_micro).toBe(1000);
  });

  it("warn budgets surface a warning without blocking the call", async () => {
    // Self-contained upstream: other tests may be skipped in filtered runs,
    // and the shared server may not exist yet.
    const reg = await gw.inject({ method: "POST", url: "/v1/servers", headers: key,
      payload: { name: `warn-upstream-${tag}`, base_url: `http://127.0.0.1:${upstreamPort}/mcp` } });
    const warnServerId = reg.json().id;
    await gw.inject({ method: "POST", url: `/v1/servers/${warnServerId}/discover`, headers: key });
    await gw.inject({ method: "POST", url: "/v1/policies", headers: key,
      payload: { name: `warn-allow-${tag}`, server_id: warnServerId, tool_name: "echo", effect: "allow" } });
    const runId = randomUUID();
    const budget = await api.inject({ method: "POST", url: "/v1/budgets", headers: key,
      payload: { scope: "run", ref_id: runId, limit_micro: 100, effect: "warn" } });
    const check = await api.inject({ method: "POST", url: "/v1/budgets/check", headers: key,
      payload: { budget_id: budget.json().id, max_cost_micro: 1000 } });
    expect(check.statusCode).toBe(200);
    expect(check.json().warning).toBeTruthy();
    await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key,
      payload: { events: [ev({ run_id: runId, event_type: "run.started" })] } });
    const call = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: warnServerId, tool: "echo", arguments: { text: "warned" }, caller: "t", run_id: runId } });
    // Warn never blocks: the call may still need approval (202), never 403.
    expect(call.statusCode).not.toBe(403);
    expect([200, 202], `call body: ${call.body}`).toContain(call.statusCode);
  });

  it("exposes the caller identity and revokes login keys on logout", async () => {
    const me = await api.inject({ method: "GET", url: "/v1/auth/me", headers: key });
    expect(me.statusCode).toBe(200);
    expect(me.json()).toMatchObject({ kind: "env", user_id: null });
    expect(me.json().scopes).toContain("admin");
    const envLogout = await api.inject({ method: "POST", url: "/v1/auth/logout", headers: key });
    expect(envLogout.statusCode).toBe(400);
    expect(envLogout.json().error).toBe("env_key_not_revocable");
    const email = `logout-${tag}@example.com`;
    await api.inject({ method: "POST", url: "/v1/users", headers: key,
      payload: { email, password: "long-password-777", role: "member" } });
    const login = await api.inject({ method: "POST", url: "/v1/auth/login",
      payload: { email, password: "long-password-777" } });
    expect(login.statusCode).toBe(200);
    const bearer = { authorization: `Bearer ${login.json().token}` };
    const mine = await api.inject({ method: "GET", url: "/v1/auth/me", headers: bearer });
    expect(mine.statusCode).toBe(200);
    expect(mine.json()).toMatchObject({ kind: "user", email });
    expect(mine.json().scopes).toEqual(expect.arrayContaining(["read", "ingest", "gateway"]));
    const out = await api.inject({ method: "POST", url: "/v1/auth/logout", headers: bearer });
    expect(out.statusCode).toBe(200);
    expect(out.json().ok).toBe(true);
    // The revoked bearer is dead everywhere.
    const after = await api.inject({ method: "GET", url: "/v1/auth/me", headers: bearer });
    expect(after.statusCode).toBe(401);
    const unauth = await api.inject({ method: "GET", url: "/v1/auth/me" });
    expect(unauth.statusCode).toBe(401);
  });

  it("bills cached tokens at the cached rate and never double", async () => {
    const prov = `cache-${tag}`;
    await api.inject({ method: "POST", url: "/v1/pricing", headers: key,
      payload: { provider: prov, model: "m1", input_price_per_million: 1_000_000,
        output_price_per_million: 0, cached_input_price_per_million: 4_000_000 } });
    const runId = randomUUID();
    await api.inject({ method: "POST", url: "/v1/ingest/events", headers: key,
      payload: { events: [ev({ run_id: runId, provider: prov, model: "m1",
        input_tokens: 1000, output_tokens: 0, cached_tokens: 600,
        timestamp: new Date().toISOString() })] } });
    const usage = await api.inject({ method: "GET", url: `/v1/runs/${runId}/usage`, headers: key });
    expect(usage.statusCode).toBe(200);
    // 400 fresh input tokens * 1M/M + 600 cached * 4M/M = 400 + 2400 = 2800 micro.
    // Billing cached at the full input rate would read 1000 here.
    expect(usage.json().estimated_cost_micro).toBe(2800);
    expect(usage.json().spans[0].cached_tokens).toBe(600);
  });

  it("sweeps expired approvals out of the pending queue on list", async () => {
    const reg = await gw.inject({ method: "POST", url: "/v1/servers", headers: key,
      payload: { name: `sweep-upstream-${tag}`, base_url: `http://127.0.0.1:${upstreamPort}/mcp` } });
    const sweepServerId = reg.json().id;
    await gw.inject({ method: "POST", url: `/v1/servers/${sweepServerId}/discover`, headers: key });
    await gw.inject({ method: "POST", url: "/v1/policies", headers: key,
      payload: { name: `sweep-hold-${tag}`, priority: 90, server_id: sweepServerId, effect: "require_approval" } });
    const call = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: sweepServerId, tool: "echo", arguments: { text: `sweep-${tag}` },
        caller: "t", request_id: `sweep-${tag}` } });
    expect(call.statusCode).toBe(202);
    const id = call.json().approval_id;
    await pool.query("UPDATE approvals SET expires_at = now() - interval '1 second' WHERE id = $1", [id]);
    // Listing pending runs the sweep: the dead hold leaves the queue.
    const pending = await gw.inject({ method: "GET", url: "/v1/approvals?status=pending", headers: key });
    expect(pending.json().items.find((a: { id: string }) => a.id === id)).toBeUndefined();
    const expired = await gw.inject({ method: "GET", url: "/v1/approvals?status=expired", headers: key });
    const row = expired.json().items.find((a: { id: string }) => a.id === id);
    expect(row).toBeDefined();
    expect(row.args).toEqual({});
    expect(row.args_summary).toContain("sweep");
  });

  it("reports evaluation violations as unknown when the spans are gone", async () => {
    const suite = await api.inject({ method: "POST", url: "/v1/evaluations/suites", headers: key,
      payload: { name: `viol-${tag}` } });
    const suiteId = suite.json().id;
    await api.inject({ method: "POST", url: `/v1/evaluations/suites/${suiteId}/cases`, headers: key,
      payload: { name: "c1", assertions: [{ type: "status", value: "success" }],
        exec_config: { output: "ok" } } });
    const runA = await api.inject({ method: "POST", url: `/v1/evaluations/suites/${suiteId}/runs`,
      headers: key, payload: { agent_name: `viol-${tag}`, config_fingerprint: "v" } });
    const runB = await api.inject({ method: "POST", url: `/v1/evaluations/suites/${suiteId}/runs`,
      headers: key, payload: { agent_name: `viol-${tag}`, config_fingerprint: "v" } });
    const aId = runA.json().eval_run.id;
    const bId = runB.json().eval_run.id;
    const rowFor = (body: { runs: { eval_run_id: string; violations: unknown }[] }) =>
      body.runs.find((r) => r.eval_run_id === aId);
    // Spans still exist: a clean run reports zero violations, not unknown.
    const before = await api.inject({ method: "GET",
      url: `/v1/evaluations/runs/compare?ids=${aId},${bId}`, headers: key });
    expect(rowFor(before.json())?.violations).toBe(0);
    // Delete the first run's spans: the count is now unknown, not zero.
    const results = await pool.query(
      "SELECT agent_run_id FROM eval_results WHERE eval_run_id = $1", [aId]);
    await pool.query("DELETE FROM spans WHERE run_id = $1", [results.rows[0].agent_run_id]);
    const after = await api.inject({ method: "GET",
      url: `/v1/evaluations/runs/compare?ids=${aId},${bId}`, headers: key });
    expect(rowFor(after.json())?.violations).toBeNull();
  });

  it("releases an abandoned reservation instead of wedging the budget", async () => {
    const budget = await api.inject({ method: "POST", url: "/v1/budgets", headers: key,
      payload: { scope: "run", ref_id: randomUUID(), limit_micro: 1000 } });
    const budgetId = budget.json().id;
    // Reserve the entire limit and abandon the hold: no settle, no release.
    // This is what a caller dying mid-call leaves behind.
    const held = await api.inject({ method: "POST", url: "/v1/budgets/check", headers: key,
      payload: { budget_id: budgetId, max_cost_micro: 1000, ttl_seconds: 300 } });
    expect(held.statusCode).toBe(200);
    expect(new Date(held.json().expires_at).getTime()).toBeGreaterThan(Date.now());
    const whileHeld = await api.inject({ method: "POST", url: "/v1/budgets/check", headers: key,
      payload: { budget_id: budgetId, max_cost_micro: 1 } });
    expect(whileHeld.statusCode).toBe(409);
    // Age that hold past its TTL. Nothing else about the budget changes.
    await pool.query(
      "UPDATE budget_reservations SET expires_at = now() - interval '1 second' WHERE budget_id = $1",
      [budgetId]);
    const afterExpiry = await api.inject({ method: "POST", url: "/v1/budgets/check", headers: key,
      payload: { budget_id: budgetId, max_cost_micro: 1000 } });
    expect(afterExpiry.statusCode).toBe(200);
    const row = await pool.query(
      "SELECT reserved_micro::float8 AS reserved, spent_micro::float8 AS spent FROM budgets WHERE id = $1",
      [budgetId]);
    expect(row.rows[0].reserved).toBe(1000); // the fresh hold only
    expect(row.rows[0].spent).toBe(0);       // an unconfirmed call is not billed
    const released = await pool.query(
      "SELECT released_at FROM budget_reservations WHERE budget_id = $1 AND status = 'released'",
      [budgetId]);
    expect(released.rows.length).toBe(1);
    expect(released.rows[0].released_at).not.toBeNull();
    const audited = await pool.query(
      `SELECT count(*)::int AS n FROM audit_events
        WHERE action = 'budget.reservation_expired' AND resource_id = $1`, [budgetId]);
    expect(audited.rows[0].n).toBe(1);
  });

  it("confines budget reads to member workspaces", async () => {
    const ws = await api.inject({ method: "POST", url: "/v1/workspaces", headers: key,
      payload: { name: `bud-ws-${tag}` } });
    const mine = await api.inject({ method: "POST", url: "/v1/budgets", headers: key,
      payload: { scope: "run", ref_id: randomUUID(), limit_micro: 5000 } });
    const mu = await api.inject({ method: "POST", url: "/v1/users", headers: key,
      payload: { email: `bud-${tag}@example.com`, password: "long-password-666", role: "member" } });
    await api.inject({ method: "POST", url: `/v1/users/${mu.json().id}/memberships`,
      headers: key, payload: { workspace_id: ws.json().id } });
    const kc = await api.inject({ method: "POST", url: `/v1/users/${mu.json().id}/keys`, headers: key,
      payload: { name: "budget-reader", scopes: ["read"] } });
    const member = { authorization: `Bearer ${kc.json().key}` };
    // The budget is real and visible to an unrestricted principal...
    const adminList = await api.inject({ method: "GET", url: "/v1/budgets?limit=500", headers: key });
    expect(adminList.json().items.some((b: { id: string }) => b.id === mine.json().id)).toBe(true);
    // ...but a member of another workspace never sees it.
    const listed = await api.inject({ method: "GET", url: "/v1/budgets?limit=500", headers: member });
    expect(listed.statusCode).toBe(200);
    expect(listed.json().items.some((b: { id: string }) => b.id === mine.json().id)).toBe(false);
    expect(listed.json().items.every(
      (b: { workspace_id: string }) => b.workspace_id === ws.json().id)).toBe(true);
  });

  it("counts windowed budget spend from the ledger, not the lifetime counter", async () => {
    const monthly = await api.inject({ method: "POST", url: "/v1/budgets", headers: key,
      payload: { scope: "run", ref_id: randomUUID(), limit_micro: 1000, period: "month" } });
    const lifetime = await api.inject({ method: "POST", url: "/v1/budgets", headers: key,
      payload: { scope: "run", ref_id: randomUUID(), limit_micro: 1000 } });
    expect(monthly.json().period).toBe("month");
    expect(lifetime.json().period).toBe("lifetime");
    // Identical past-window spend sits behind both budgets.
    for (const id of [monthly.json().id, lifetime.json().id]) {
      await pool.query("UPDATE budgets SET spent_micro = 900 WHERE id = $1", [id]);
      await pool.query(
        `INSERT INTO budget_ledger (budget_id, amount_micro, created_at)
         VALUES ($1, 900, now() - interval '40 days')`, [id]);
    }
    const m = await api.inject({ method: "POST", url: "/v1/budgets/check", headers: key,
      payload: { budget_id: monthly.json().id, max_cost_micro: 500 } });
    expect(m.statusCode).toBe(200); // last month's spend is outside this window
    const l = await api.inject({ method: "POST", url: "/v1/budgets/check", headers: key,
      payload: { budget_id: lifetime.json().id, max_cost_micro: 500 } });
    expect(l.statusCode).toBe(409); // the lifetime counter still counts it
    expect(l.json().spent_micro).toBe(900);
  });

  it("withholds pending approval arguments from callers without the approve scope", async () => {
    const wsList = await api.inject({ method: "GET", url: "/v1/workspaces", headers: key });
    const def = wsList.json().items.find((w: { name: string }) => w.name === "default");
    const mu = await api.inject({ method: "POST", url: "/v1/users", headers: key,
      payload: { email: `peek-${tag}@example.com`, password: "long-password-777", role: "member" } });
    await api.inject({ method: "POST", url: `/v1/users/${mu.json().id}/memberships`,
      headers: key, payload: { workspace_id: def.id } });
    const kc = await api.inject({ method: "POST", url: `/v1/users/${mu.json().id}/keys`, headers: key,
      payload: { name: "peeker", scopes: ["read"] } });
    const peeker = { authorization: `Bearer ${kc.json().key}` };
    await gw.inject({ method: "POST", url: "/v1/policies", headers: key,
      payload: { name: `peek-appr-${tag}`, priority: 200, server_id: serverId,
        tool_name: "echo", effect: "require_approval" } });
    const call = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo",
        arguments: { text: "classified-payload" }, caller: "peek", request_id: `peek-${tag}` } });
    expect(call.statusCode).toBe(202);
    const approvalId = call.json().approval_id;
    // The approver opens the seal for that row...
    const asApprover = await gw.inject({ method: "GET",
      url: "/v1/approvals?status=pending&limit=200", headers: approver });
    const forApprover = asApprover.json().items.find((a: { id: string }) => a.id === approvalId);
    expect(forApprover.args.text).toBe("classified-payload");
    // ...and a read-scoped member of the same workspace, who can see the row,
    // cannot see inside it.
    const asMember = await gw.inject({ method: "GET",
      url: "/v1/approvals?status=pending&limit=200", headers: peeker });
    expect(asMember.statusCode).toBe(200);
    const forMember = asMember.json().items.find((a: { id: string }) => a.id === approvalId);
    expect(forMember).toBeDefined();
    expect(forMember.args_withheld).toBe(true);
    expect(JSON.stringify(forMember)).not.toContain("classified-payload");
  });

  it("rejects an unusable OTLP span instead of storing it at the epoch", async () => {
    const trace = randomUUID().replace(/-/g, "");
    const now = (BigInt(Date.now()) * 1_000_000n).toString();
    const spanId = () => randomUUID().replace(/-/g, "").slice(0, 16);
    const res = await api.inject({ method: "POST", url: "/v1/traces", headers: key,
      payload: { resourceSpans: [{
        resource: { attributes: [{ key: "service.name", value: { stringValue: `otlp-bad-${tag}` } }] },
        scopeSpans: [{ spans: [
          { traceId: trace, spanId: spanId(), name: "gen_ai.request",
            startTimeUnixNano: now, endTimeUnixNano: now },
          { traceId: trace, spanId: spanId(), name: "gen_ai.request",
            startTimeUnixNano: "not-a-number" }
        ] }]
      }] } });
    expect(res.statusCode).toBe(200);
    // The good span lands, the unusable one is reported rather than dropped.
    expect(res.json().accepted).toBe(1);
    expect(res.json().rejected).toBe(1);
    expect(res.json().partialSuccess.rejectedSpans).toBe(1);
    const epoch = await pool.query("SELECT count(*)::int AS n FROM spans WHERE started_at < '2000-01-01'");
    expect(epoch.rows[0].n).toBe(0);
  });

  it("counts a replayed actuals batch as duplicates instead of doubling it", async () => {
    const row = { provider: `recon-${tag}`, model: "m1",
      period_start: "2026-01-01T00:00:00.000Z", period_end: "2026-02-01T00:00:00.000Z",
      input_tokens: 10, output_tokens: 5, actual_cost_micro: 12345, source: "invoice" };
    const first = await api.inject({ method: "POST", url: "/v1/reconciliation/actuals",
      headers: key, payload: { rows: [row] } });
    expect(first.statusCode).toBe(201);
    expect(first.json().accepted).toBe(1);
    const again = await api.inject({ method: "POST", url: "/v1/reconciliation/actuals",
      headers: key, payload: { rows: [row] } });
    expect(again.statusCode).toBe(201);
    expect(again.json().accepted).toBe(0);
    expect(again.json().duplicates).toBe(1);
    const stored = await pool.query(
      `SELECT count(*)::int AS n, COALESCE(SUM(actual_cost_micro), 0)::float8 AS total
         FROM actuals WHERE provider = $1`, [row.provider]);
    expect(stored.rows[0].n).toBe(1);
    expect(stored.rows[0].total).toBe(12345);
  });

  it("replays a case whose only expected value is a string", async () => {
    const suite = await api.inject({ method: "POST", url: "/v1/evaluations/suites", headers: key,
      payload: { name: `str-expected-${tag}` } });
    expect(suite.statusCode).toBe(201);
    const kase = await api.inject({
      method: "POST", url: `/v1/evaluations/suites/${suite.json().id}/cases`, headers: key,
      payload: { name: "greeting", expected: "hello world",
        assertions: [{ type: "exact", value: "hello world" }] }
    });
    // A string expected value is what the replay turns into the scripted
    // output, so the create must accept one.
    expect(kase.statusCode).toBe(201);
    const run = await api.inject({
      method: "POST", url: `/v1/evaluations/suites/${suite.json().id}/runs`, headers: key,
      payload: { agent_name: `str-${tag}`, config_fingerprint: "v1" }
    });
    expect(run.statusCode).toBe(201);
    expect(run.json().results[0].passed).toBe(true);
    expect(run.json().results[0].assertion_results[0].message).toBe("exact match");
  });

  it("serializes concurrent audit appends so the chain does not fork", async () => {
    const marker = `chain-${tag}`;
    const posts = Array.from({ length: 8 }, (_, i) =>
      api.inject({ method: "POST", url: "/v1/pricing", headers: key,
        payload: { provider: marker, model: `m${i}`,
          input_price_per_million: 1, output_price_per_million: 1 } }));
    const results = await Promise.all(posts);
    expect(results.every((r) => r.statusCode === 201)).toBe(true);
    const chain = await pool.query(
      "SELECT hash, prev_hash FROM audit_events WHERE metadata->>'provider' = $1", [marker]);
    expect(chain.rows.length).toBe(8);
    // Two appenders that read the same tail would record the same prev_hash.
    expect(new Set(chain.rows.map((r) => r.prev_hash)).size).toBe(8);
  });
}, 60000);
