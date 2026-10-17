import { createServer } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { buildApp } from "../src/index.js";
import { buildGateway } from "../src/gateway.js";
import { pool } from "../src/db.js";

// §9.2/§9.4 behaviours that the legacy approval flow did not have: queue
// caps, a creation rate limit, an ambiguous-outcome terminal state, MCP tool
// errors recorded as errors rather than success, and the recovery sweep.
describe("approval state machine v2", () => {
  const api = buildApp();
  const gw = buildGateway();
  const key = { authorization: "Bearer test_key" };
  const approver = { authorization: "Bearer test_approver" };
  const tag = Date.now().toString(36);
  let serverId = "";
  let httpServer: ReturnType<typeof createServer>;

  const mock = new McpServer({ name: "approval-tools", version: "0.1.0" });
  mock.registerTool("echo", { description: "echo", inputSchema: { text: z.string() } },
    async ({ text }) => ({ content: [{ type: "text", text: `echo:${text}` }] }));
  // Never resolves: the gateway must time out and refuse to guess the outcome.
  mock.registerTool("hang", { description: "hangs", inputSchema: { text: z.string() } },
    async () => new Promise(() => undefined));
  // A protocol-level tool error is an unambiguous response, not success.
  mock.registerTool("err", { description: "tool error", inputSchema: {} },
    async () => ({ content: [{ type: "text", text: "upstream refused" }], isError: true }));

  beforeAll(async () => {
    httpServer = createServer(async (req, res) => {
      if (req.method === "POST") {
        const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
        res.on("close", () => transport.close().catch(() => undefined));
        await mock.connect(transport);
        await transport.handleRequest(req, res);
        return;
      }
      res.writeHead(405).end();
    });
    await new Promise<void>((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
    const port = (httpServer.address() as { port: number }).port;
    const reg = await gw.inject({ method: "POST", url: "/v1/servers", headers: key,
      payload: { name: `approvals-${tag}`, base_url: `http://127.0.0.1:${port}/mcp` } });
    expect(reg.statusCode).toBe(201);
    serverId = reg.json().id as string;
    const disc = await gw.inject({ method: "POST", url: `/v1/servers/${serverId}/discover`, headers: key });
    expect(disc.statusCode).toBe(200);
    // Every tool in this file needs approval.
    const rule = await gw.inject({ method: "POST", url: "/v1/policies", headers: key,
      payload: { name: `approvals-hold-${tag}`, priority: 10, server_id: serverId,
        effect: "require_approval" } });
    expect(rule.statusCode).toBe(201);
  });

  afterAll(async () => {
    httpServer.close();
    await api.close();
    await gw.close();
    await pool.end();
  });

  const call = (caller: string, tool: string, args: Record<string, unknown> = {}) =>
    gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool, arguments: args, caller } });

  const decide = (id: string, approved = true) =>
    gw.inject({ method: "POST", url: `/v1/approvals/${id}/decision`, headers: approver,
      payload: { approved } });

  it("refuses more than N new approvals per caller per minute", async () => {
    const previous = process.env.APPROVAL_RATE_PER_MINUTE;
    process.env.APPROVAL_RATE_PER_MINUTE = "1";
    try {
      const caller = `rl-${tag}`;
      const first = await call(caller, "echo", { text: "one" });
      expect(first.statusCode).toBe(202);
      const second = await call(caller, "echo", { text: "two" });
      expect(second.statusCode).toBe(429);
      expect(second.json().error).toBe("approval_rate_limited");
    } finally {
      process.env.APPROVAL_RATE_PER_MINUTE = previous;
    }
  });

  it("refuses more than N active pending approvals for one caller", async () => {
    const previous = process.env.APPROVAL_MAX_PENDING_PER_CALLER;
    process.env.APPROVAL_MAX_PENDING_PER_CALLER = "1";
    try {
      const caller = `cap-${tag}`;
      const first = await call(caller, "echo", { text: "first" });
      expect(first.statusCode).toBe(202);
      const second = await call(caller, "echo", { text: "second" });
      expect(second.statusCode).toBe(429);
      expect(second.json().error).toBe("approval_limit");
    } finally {
      process.env.APPROVAL_MAX_PENDING_PER_CALLER = previous;
    }
  });

  it("marks a timeout after dispatch OUTCOME_UNKNOWN and never retries it", async () => {
    const caller = `unk-${tag}`;
    const held = await call(caller, "hang", { text: "x" });
    expect(held.statusCode).toBe(202);
    const id = held.json().approval_id as string;
    expect((await decide(id)).statusCode).toBe(200);

    const previousTimeout = process.env.UPSTREAM_TIMEOUT_MS;
    process.env.UPSTREAM_TIMEOUT_MS = "1500";
    let retry: Awaited<ReturnType<typeof gw.inject>>;
    try {
      retry = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
        payload: { server_id: serverId, tool: "hang", arguments: { text: "x" }, caller, approval_id: id } });
    } finally {
      if (previousTimeout === undefined) delete process.env.UPSTREAM_TIMEOUT_MS;
      else process.env.UPSTREAM_TIMEOUT_MS = previousTimeout;
    }
    expect(retry.statusCode).toBe(502);
    expect(retry.json().error).toBe("outcome_unknown");

    const row = (await pool.query(
      "SELECT status, outcome_summary FROM approvals WHERE id = $1", [id])).rows[0];
    expect(row.status).toBe("outcome_unknown");
    expect(row.outcome_summary).toContain("may have executed");

    const replay = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "hang", arguments: { text: "x" }, caller, approval_id: id } });
    expect(replay.statusCode).toBe(410);
    expect(replay.json().error).toBe("approval_outcome_unknown");
    expect(replay.json().note).toContain("may have executed");
  });

  it("records an MCP tool error as a received response with response_is_error", async () => {
    const caller = `err-${tag}`;
    const held = await call(caller, "err");
    const id = held.json().approval_id as string;
    expect((await decide(id)).statusCode).toBe(200);
    const retry = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "err", arguments: {}, caller, approval_id: id } });
    expect(retry.statusCode).toBe(200);
    expect(retry.json().result.isError).toBe(true);
    const row = (await pool.query(
      "SELECT status, response_is_error FROM approvals WHERE id = $1", [id])).rows[0];
    expect(row.status).toBe("response_received");
    expect(row.response_is_error).toBe(true);
  });

  it("sweeps a stuck EXECUTING row into OUTCOME_UNKNOWN", async () => {
    const caller = `sweep-${tag}`;
    const held = await call(caller, "echo", { text: "sweep" });
    const id = held.json().approval_id as string;
    await pool.query(
      `UPDATE approvals SET status='executing', execution_started_at=now() - interval '1 hour'
        WHERE id = $1`, [id]
    );
    const listed = await gw.inject({ method: "GET", url: "/v1/approvals?status=outcome_unknown", headers: key });
    const row = listed.json().items.find((a: { id: string }) => a.id === id);
    expect(row).toBeDefined();
    expect(row.outcome_summary).toContain("may have executed");
  });
});
