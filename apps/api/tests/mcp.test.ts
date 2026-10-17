import { createServer } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { buildApp } from "../src/index.js";
import { buildGateway } from "../src/gateway.js";
import { pool } from "../src/db.js";

const PROTOCOL = "2026-07-28";

// Narrow suite for the agent-facing MCP surface (§7.2/§9.5): discovery,
// namespaced tool listing with cache metadata, header/body binding, the three
// supported methods, rejection of everything else, and the approval retry
// contract driven by a stable logical request id.
describe("MCP streamable HTTP gateway", () => {
  const api = buildApp();
  const gw = buildGateway();
  const key = { authorization: "Bearer test_key" };
  const approver = { authorization: "Bearer test_approver" };
  const tag = Date.now().toString(36);
  const hits = { echo: 0, hold: 0, wipe: 0 };
  let serverId = "";
  let alias = "";
  let httpServer: ReturnType<typeof createServer>;

  const mock = new McpServer({ name: "mcp-test-tools", version: "0.1.0" });
  mock.registerTool("echo", { description: "echo back", inputSchema: { text: z.string() } },
    async ({ text }) => {
      hits.echo++;
      return { content: [{ type: "text", text: `echo:${text}` }] };
    });
  mock.registerTool("hold", { description: "requires approval", inputSchema: { text: z.string() } },
    async ({ text }) => {
      hits.hold++;
      return { content: [{ type: "text", text: `held:${text}` }] };
    });
  mock.registerTool("wipe", { description: "dangerous", inputSchema: {} },
    async () => {
      hits.wipe++;
      return { content: [{ type: "text", text: "wiped" }] };
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
      // No server-initiated SSE stream in this profile.
      res.writeHead(405).end();
    });
    await new Promise<void>((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
    const port = (httpServer.address() as { port: number }).port;

    const reg = await gw.inject({
      method: "POST", url: "/v1/servers", headers: key,
      payload: { name: `mcp-${tag}`, base_url: `http://127.0.0.1:${port}/mcp` }
    });
    expect(reg.statusCode).toBe(201);
    serverId = reg.json().id as string;
    alias = reg.json().gateway_alias as string;
    expect(alias).toMatch(/^[a-z0-9_]+$/);

    const disc = await gw.inject({ method: "POST", url: `/v1/servers/${serverId}/discover`, headers: key });
    expect(disc.statusCode).toBe(200);
    expect(hits.echo).toBe(0);

    for (const [tool, effect] of [["echo", "allow"], ["hold", "require_approval"], ["wipe", "deny"]] as const) {
      const r = await gw.inject({
        method: "POST", url: "/v1/policies", headers: key,
        payload: { name: `mcp-${tool}-${tag}`, server_id: serverId, tool_name: tool, effect }
      });
      expect([200, 201]).toContain(r.statusCode);
    }
  });

  afterAll(async () => {
    httpServer.close();
    await api.close();
    await gw.close();
    await pool.end();
  });

  const meta = (logical?: string) => ({
    "io.modelcontextprotocol/protocolVersion": PROTOCOL,
    "io.modelcontextprotocol/clientCapabilities": { tools: {} },
    ...(logical ? { "io.traceguard/logical_request_id": logical } : {})
  });

  function rpc(
    method: string,
    params: Record<string, unknown>,
    opts: { name?: string; headers?: Record<string, string> } = {}
  ) {
    return gw.inject({
      method: "POST", url: "/mcp",
      headers: {
        ...key,
        "mcp-protocol-version": PROTOCOL,
        "mcp-method": method,
        ...(opts.name ? { "mcp-name": opts.name } : {}),
        ...(opts.headers ?? {})
      },
      payload: { jsonrpc: "2.0", id: "rpc-1", method, params }
    });
  }

  it("server/discover advertises only the tools capability", async () => {
    const res = await rpc("server/discover", { _meta: meta() });
    expect(res.statusCode).toBe(200);
    const body = res.json() as Record<string, any>;
    expect(body.result.protocolVersion).toBe(PROTOCOL);
    expect(body.result.capabilities).toEqual({ tools: { listChanged: false } });
    expect(body.result.capabilities.resources).toBeUndefined();
    expect(body.result.capabilities.prompts).toBeUndefined();
  });

  it("tools/list returns only pinned, unquarantined tools under namespaced names", async () => {
    const res = await rpc("tools/list", { _meta: meta() });
    expect(res.statusCode).toBe(200);
    const body = res.json() as Record<string, any>;
    const names = body.result.tools.map((t: { name: string }) => t.name);
    expect(names).toContain(`${alias}__echo`);
    expect(names).not.toContain("echo");
    expect(body.result.ttlMs).toBeGreaterThan(0);
    expect(body.result.cacheScope).toBe("workspace");
    expect(body.result.resultType).toBe("complete");
  });

  it("rejects a header that disagrees with the JSON-RPC body", async () => {
    const res = await rpc("tools/list", { _meta: meta() }, { headers: { "mcp-method": "tools/call" } });
    expect(res.statusCode).toBe(400);
    const body = res.json() as Record<string, any>;
    expect(body.error.code).toBe(-32600);
    expect(body.error.data.error).toContain("Mcp-Method");
  });

  it("requires per-request protocol metadata", async () => {
    const res = await rpc("tools/list", {});
    expect(res.statusCode).toBe(400);
    expect((res.json() as Record<string, any>).error.code).toBe(-32600);
  });

  it("rejects unsupported methods without forwarding anything", async () => {
    const res = await rpc("resources/read", { uri: "file:///etc/passwd", _meta: meta() });
    expect(res.statusCode).toBe(200);
    expect((res.json() as Record<string, any>).error.code).toBe(-32601);
    expect(hits.echo).toBe(0);
  });

  it("allows a pinned tool through tools/call", async () => {
    const name = `${alias}__echo`;
    const res = await rpc("tools/call", { name, arguments: { text: "hi" }, _meta: meta() }, { name });
    expect(res.statusCode).toBe(200);
    const body = res.json() as Record<string, any>;
    expect(body.result.content[0].text).toBe("echo:hi");
    expect(hits.echo).toBe(1);
  });

  it("denies a denylisted tool without upstream contact", async () => {
    const name = `${alias}__wipe`;
    const before = hits.wipe;
    const res = await rpc("tools/call", { name, arguments: {}, _meta: meta() }, { name });
    expect((res.json() as Record<string, any>).error.code).toBe(-32001);
    expect(hits.wipe).toBe(before);
  });

  it("refuses an approval-needing call without the shim's logical request id", async () => {
    const name = `${alias}__hold`;
    const res = await rpc("tools/call", { name, arguments: { text: "x" }, _meta: meta() }, { name });
    expect((res.json() as Record<string, any>).error.code).toBe(-32005);
    expect((res.json() as Record<string, any>).error.data.error).toBe("APPROVAL_CLIENT_REQUIRED");
    expect(hits.hold).toBe(0);
  });

  it("returns APPROVAL_PENDING, then executes exactly once on a same-logical-id retry", async () => {
    const name = `${alias}__hold`;
    const logical = `logical-${tag}-hold`;
    const first = await rpc("tools/call", { name, arguments: { text: "x" }, _meta: meta(logical) }, { name });
    const firstBody = first.json() as Record<string, any>;
    expect(firstBody.error.code).toBe(-32002);
    expect(firstBody.error.data.error).toBe("APPROVAL_PENDING");
    expect(firstBody.error.data.logical_request_id).toBe(logical);
    const approvalId = firstBody.error.data.approval_id as string;
    expect(approvalId).toBeTruthy();
    expect(hits.hold).toBe(0);

    const decide = await gw.inject({
      method: "POST", url: `/v1/approvals/${approvalId}/decision`,
      headers: approver, payload: { approved: true }
    });
    expect(decide.statusCode).toBe(200);

    const retry = await rpc("tools/call", { name, arguments: { text: "x" }, _meta: meta(logical) }, { name });
    expect(retry.statusCode).toBe(200);
    expect((retry.json() as Record<string, any>).result.content[0].text).toBe("held:x");
    expect(hits.hold).toBe(1);

    const replay = await rpc("tools/call", { name, arguments: { text: "x" }, _meta: meta(logical) }, { name });
    expect((replay.json() as Record<string, any>).error.code).toBe(-32004);
    expect(hits.hold).toBe(1);
  });

  it("does not expose server-initiated streams", async () => {
    const res = await gw.inject({ method: "GET", url: "/mcp", headers: key });
    expect(res.statusCode).toBe(405);
  });

  it("requires authentication", async () => {
    const res = await gw.inject({
      method: "POST", url: "/mcp",
      payload: { jsonrpc: "2.0", id: 1, method: "server/discover", params: { _meta: meta() } }
    });
    expect(res.statusCode).toBe(401);
  });
});