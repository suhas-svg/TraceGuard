import { createServer } from "node:http";
import type { Server as HttpServer } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { buildApp } from "../src/index.js";
import { buildGateway } from "../src/gateway.js";
import { pool } from "../src/db.js";
import { publishTestPolicy } from "./policy-helper.js";

const PROTOCOL = "2026-07-28";

// §7.5: the pin covers the whole declared definition, a changed definition
// quarantines the tool (with the previous pin kept for the diff), and a
// definition that is unsafe to pin never gets pinned at all. The mock is the
// low-level server so the test controls the exact tool JSON an upstream
// declares — including fields a typed helper would not emit.
describe("tool definition pins", () => {
  const api = buildApp();
  const gw = buildGateway();
  const key = { authorization: "Bearer test_key" };
  const tag = Date.now().toString(36);
  let port = 0;
  let mockServer: HttpServer | null = null;
  let currentTools: Record<string, unknown>[] = [];
  let serverId = "";
  let alias = "";
  let firstHash = "";

  const echo = (over: Record<string, unknown> = {}) => ({
    name: "echo",
    title: "Echo",
    description: "echo back",
    inputSchema: { type: "object", properties: { text: { type: "string" } }, required: ["text"] },
    _meta: { "io.example/flag": 1 },
    ...over
  });

  // Restarting the mock on its own port simulates an upstream whose declared
  // tools changed between two discoveries.
  async function startMock(tools: Record<string, unknown>[]): Promise<void> {
    if (mockServer) {
      await new Promise<void>((resolve) => mockServer?.close(() => resolve()));
    }
    currentTools = tools;
    // A fresh server per request: one Protocol instance cannot be connected to
    // two transports, and two gateway calls can be in flight at once.
    const newMock = () => {
    const mock = new Server(
      { name: "pin-tools", version: "0.1.0" },
      { capabilities: { tools: {} } }
    );
    mock.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: currentTools }));
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

  beforeAll(async () => {
    await startMock([echo()]);
    const reg = await gw.inject({
      method: "POST", url: "/v1/servers", headers: key,
      payload: { name: `pins-${tag}`, base_url: `http://127.0.0.1:${port}/mcp` }
    });
    expect(reg.statusCode).toBe(201);
    serverId = reg.json().id as string;
    alias = reg.json().gateway_alias as string;
    const disc = await gw.inject({ method: "POST", url: `/v1/servers/${serverId}/discover`, headers: key });
    expect(disc.statusCode).toBe(200);
    expect(disc.json().pinned).toEqual(["echo"]);
    await publishTestPolicy(pool);
  });

  afterAll(async () => {
    if (mockServer) await new Promise<void>((resolve) => mockServer?.close(() => resolve()));
    await api.close();
    await gw.close();
    await pool.end();
  });

  function rpc(method: string, params: Record<string, unknown>) {
    return gw.inject({
      method: "POST", url: "/mcp",
      headers: {
        ...key,
        "mcp-protocol-version": PROTOCOL,
        "mcp-method": method,
        ...(method === "tools/call" ? { "mcp-name": String(params.name ?? "") } : {})
      },
      payload: {
        jsonrpc: "2.0", id: "rpc-1", method,
        params: {
          ...params,
          _meta: {
            "io.modelcontextprotocol/protocolVersion": PROTOCOL,
            "io.modelcontextprotocol/clientCapabilities": { tools: {} }
          }
        }
      }
    });
  }

  async function toolRow() {
    const res = await pool.query(
      "SELECT * FROM server_tools WHERE server_id = $1 AND tool_name = 'echo'", [serverId]
    );
    return res.rows[0];
  }

  it("pins every declared field and serves the reviewed definition to clients", async () => {
    const row = await toolRow();
    expect(row.definition_version).toBe(1);
    expect(row.quarantined).toBe(false);
    expect(row.definition).toEqual({
      name: "echo",
      title: "Echo",
      description: "echo back",
      inputSchema: { type: "object", properties: { text: { type: "string" } }, required: ["text"] },
      // Only allowlisted _meta keys are pinned (TOOL_PIN_META_ALLOWLIST).
      _meta: { "io.example/flag": 1 }
    });
    firstHash = row.definition_hash as string;
    expect(firstHash).toMatch(/^[0-9a-f]{64}$/);

    const listed = await rpc("tools/list", {});
    const tool = (listed.json() as { result: { tools: { name: string; title?: string }[] } })
      .result.tools.find((t) => t.name === `${alias}__echo`);
    expect(tool?.title).toBe("Echo");
  });

  it("quarantines any covered field change and keeps the previous pin for the diff", async () => {
    await startMock([echo({
      title: "Echo v2",
      // Previously absent fields and a changed _meta: all covered by the pin.
      outputSchema: { type: "object", properties: { word: { type: "string" } } },
      annotations: { readOnlyHint: true },
      icons: [{ src: "https://example.com/i.png" }],
      execution: { taskSupport: "optional" },
      _meta: { "io.example/flag": 2 }
    })]);
    const disc = await gw.inject({ method: "POST", url: `/v1/servers/${serverId}/discover`, headers: key });
    expect(disc.statusCode).toBe(200);
    expect(disc.json().changed).toEqual(["echo"]);

    const row = await toolRow();
    expect(row.quarantined).toBe(true);
    expect(row.quarantine_reason).toBe("definition changed");
    expect(row.definition_version).toBe(2);
    expect(row.previous_hash).toBe(firstHash);
    expect(row.definition_hash).not.toBe(firstHash);
    expect(row.previous_definition.title).toBe("Echo");
    expect(row.previous_definition.outputSchema).toBeUndefined();
    expect(row.definition.title).toBe("Echo v2");
    expect(row.definition.icons).toEqual([{ src: "https://example.com/i.png" }]);

    // Not listed, and a call is blocked before any upstream contact.
    const listed = await rpc("tools/list", {});
    const names = (listed.json() as { result: { tools: { name: string }[] } })
      .result.tools.map((t) => t.name);
    expect(names).not.toContain(`${alias}__echo`);

    const call = await gw.inject({
      method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: "hi" } }
    });
    expect(call.statusCode).toBe(403);
    expect(call.json().error).toBe("tool_blocked");

    const audited = await pool.query(
      `SELECT metadata FROM audit_events
        WHERE action = 'tool.definition_changed' AND resource_id = $1
        ORDER BY timestamp DESC LIMIT 1`,
      [`${serverId}/echo`]
    );
    expect(audited.rows[0]?.metadata).toMatchObject({
      previous_hash: firstHash, definition_hash: row.definition_hash
    });
  });

  it("re-review clears the quarantine and keeps the new pin version", async () => {
    const review = await gw.inject({
      method: "PUT", url: `/v1/servers/${serverId}/tools/echo/quarantine`, headers: key,
      payload: { quarantined: false }
    });
    expect(review.statusCode).toBe(200);
    const row = await toolRow();
    expect(row.quarantined).toBe(false);
    expect(row.quarantine_reason).toBeNull();
    expect(row.definition_version).toBe(2);
    const audited = await pool.query(
      "SELECT action FROM audit_events WHERE action = 'tool.reapprove' AND resource_id = $1",
      [`${serverId}/echo`]
    );
    expect(audited.rows.length).toBeGreaterThan(0);
  });

  it("keeps the first approved pin across a second drift before review", async () => {
    // Drift once: the approved baseline moves to the v2 definition.
    await startMock([echo({ title: "Echo v3" })]);
    await gw.inject({ method: "POST", url: `/v1/servers/${serverId}/discover`, headers: key });
    const afterFirst = await toolRow();
    expect(afterFirst.quarantined).toBe(true);
    const approvedHash = afterFirst.previous_hash as string;

    // Drift again while still quarantined: §7.5 re-approval is against the
    // reviewed baseline, so the second mistake must not overwrite it.
    await startMock([echo({ title: "Echo v4" })]);
    await gw.inject({ method: "POST", url: `/v1/servers/${serverId}/discover`, headers: key });
    const afterSecond = await toolRow();
    expect(afterSecond.quarantined).toBe(true);
    expect(afterSecond.previous_hash).toBe(approvedHash);
    expect(afterSecond.definition_hash).not.toBe(approvedHash);

    const cleared = await gw.inject({
      method: "PUT", url: `/v1/servers/${serverId}/tools/echo/quarantine`, headers: key,
      payload: { quarantined: false }
    });
    expect(cleared.statusCode).toBe(200);
  });

  it("never pins a definition with an external $ref, and quarantines a trusted pin that gains one", async () => {
    await startMock([
      echo({ inputSchema: { type: "object", properties: { text: { $ref: "https://evil.example/schema.json" } } } }),
      {
        name: "fresh",
        description: "never pinned",
        inputSchema: { type: "object", properties: { x: { $ref: "http://evil.example/x.json" } } }
      }
    ]);
    const disc = await gw.inject({ method: "POST", url: `/v1/servers/${serverId}/discover`, headers: key });
    expect(disc.statusCode).toBe(200);
    const rejected = disc.json().rejected as { name: string; reason: string }[];
    expect(rejected.map((r) => r.name).sort()).toEqual(["echo", "fresh"]);
    expect(rejected.find((r) => r.name === "echo")?.reason).toContain("external $ref");

    const row = await toolRow();
    expect(row.quarantined).toBe(true);
    expect(row.quarantine_reason).toContain("external $ref");
    const fresh = await pool.query(
      "SELECT * FROM server_tools WHERE server_id = $1 AND tool_name = 'fresh'", [serverId]
    );
    expect(fresh.rows.length).toBe(0);
  });
});
