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
    const reg = await api.inject({
      method: "POST", url: "/v1/servers", headers: key,
      payload: { name: `pins-${tag}`, base_url: `http://127.0.0.1:${port}/mcp` }
    });
    expect(reg.statusCode).toBe(201);
    serverId = reg.json().id as string;
    alias = reg.json().gateway_alias as string;
    const disc = await api.inject({ method: "POST", url: `/v1/servers/${serverId}/discover`, headers: key });
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

  async function latestPin() {
    const res = await pool.query(
      `SELECT * FROM tool_pins WHERE server_id = $1 AND tool_name = 'echo'
        ORDER BY version DESC LIMIT 1`,
      [serverId]
    );
    return res.rows[0];
  }

  async function submitAndApprove(pinId: string): Promise<void> {
    const review = await api.inject({
      method: "POST", url: `/v1/tool-pins/${pinId}/submit-review`, headers: key
    });
    expect(review.statusCode).toBe(200);
    expect(review.json().status).toBe("pending_review");

    const approved = await api.inject({
      method: "POST", url: `/v1/tool-pin-candidates/${pinId}/approve-for-publication`, headers: key
    });
    expect(approved.statusCode).toBe(200);
    expect(approved.json().status).toBe("approved");
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

  it("quarantines any covered field change and creates an immutable candidate", async () => {
    await startMock([echo({
      title: "Echo v2",
      // Previously absent fields and a changed _meta: all covered by the pin.
      outputSchema: { type: "object", properties: { word: { type: "string" } } },
      annotations: { readOnlyHint: true },
      icons: [{ src: "https://example.com/i.png" }],
      execution: { taskSupport: "optional" },
      _meta: { "io.example/flag": 2 }
    })]);
    const disc = await api.inject({ method: "POST", url: `/v1/servers/${serverId}/discover`, headers: key });
    expect(disc.statusCode).toBe(200);
    expect(disc.json().changed).toEqual(["echo"]);

    const row = await toolRow();
    expect(row.quarantined).toBe(true);
    expect(row.quarantine_reason).toBe("definition changed");
    // The reviewed active pin is untouched: the drift is a candidate until a
    // reviewer approves it and the publisher activates a new signed bundle.
    expect(row.definition_version).toBe(1);
    expect(row.definition_hash).toBe(firstHash);
    expect(row.definition.title).toBe("Echo");
    expect(row.active_pin_id).toBeTruthy();
    expect(row.candidate_pin_id).toBeTruthy();

    const candidate = await latestPin();
    expect(candidate.id).toBe(row.candidate_pin_id);
    expect(candidate.version).toBe(2);
    expect(candidate.status).toBe("candidate");
    expect(candidate.quarantine_reason).toBe("definition changed");
    expect(candidate.definition.title).toBe("Echo v2");
    expect(candidate.definition.icons).toEqual([{ src: "https://example.com/i.png" }]);
    expect(candidate.definition_hash).not.toBe(firstHash);

    // Refreshing while the upstream still serves the same changed definition
    // keeps the existing candidate and its review state intact.
    const refreshed = await api.inject({
      method: "POST", url: `/v1/servers/${serverId}/discover`, headers: key
    });
    expect(refreshed.statusCode).toBe(200);
    const afterRefresh = await latestPin();
    expect(afterRefresh.id).toBe(candidate.id);
    expect(afterRefresh.status).toBe("candidate");
    expect((await toolRow()).candidate_pin_id).toBe(candidate.id);

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
      previous_hash: firstHash, definition_hash: candidate.definition_hash,
      active_pin_id: row.active_pin_id, candidate_pin_id: candidate.id
    });
  });

  it("activates a reviewed candidate only through signed publication", async () => {
    const candidate = await latestPin();
    expect(candidate.status).toBe("candidate");

    // Clearing quarantine directly is not review and must not make the
    // candidate callable.
    const shortcut = await api.inject({
      method: "PUT", url: `/v1/servers/${serverId}/tools/echo/quarantine`, headers: key,
      payload: { quarantined: false }
    });
    expect(shortcut.statusCode).toBe(409);
    expect(shortcut.json().error).toBe("review_required");

    await submitAndApprove(candidate.id);
    const refreshed = await api.inject({
      method: "POST", url: `/v1/servers/${serverId}/discover`, headers: key
    });
    expect(refreshed.statusCode).toBe(200);
    expect((await latestPin()).status).toBe("approved");
    const beforePublish = await toolRow();
    expect(beforePublish.quarantined).toBe(true);
    expect(beforePublish.definition_version).toBe(1);

    await publishTestPolicy(pool);
    const row = await toolRow();
    expect(row.quarantined).toBe(false);
    expect(row.quarantine_reason).toBeNull();
    expect(row.definition_version).toBe(2);
    expect(row.definition_hash).toBe(candidate.definition_hash);
    expect(row.definition.title).toBe("Echo v2");
    expect(row.active_pin_id).toBe(candidate.id);
    expect(row.candidate_pin_id).toBeNull();

    const audited = await pool.query(
      `SELECT action FROM audit_events
        WHERE action IN ('tool_pin.submitted', 'tool_pin.approved')
          AND resource_id = $1`,
      [candidate.id]
    );
    expect(audited.rows.map((r) => r.action).sort())
      .toEqual(["tool_pin.approved", "tool_pin.submitted"]);
  });

  it("keeps the active pin across repeated drift until the newest candidate is published", async () => {
    // Drift once: v3 is a candidate; the active v2 pin remains in force.
    await startMock([echo({ title: "Echo v3" })]);
    await api.inject({ method: "POST", url: `/v1/servers/${serverId}/discover`, headers: key });
    const afterFirst = await toolRow();
    expect(afterFirst.quarantined).toBe(true);
    expect(afterFirst.definition_version).toBe(2);
    const activeHash = afterFirst.definition_hash as string;
    const firstCandidate = await latestPin();
    expect(firstCandidate.version).toBe(3);
    expect(firstCandidate.status).toBe("candidate");

    // Drift again while still quarantined: the first candidate is superseded
    // and the active reviewed baseline is still untouched.
    await startMock([echo({ title: "Echo v4" })]);
    await api.inject({ method: "POST", url: `/v1/servers/${serverId}/discover`, headers: key });
    const afterSecond = await toolRow();
    expect(afterSecond.quarantined).toBe(true);
    expect(afterSecond.definition_version).toBe(2);
    expect(afterSecond.definition_hash).toBe(activeHash);
    const secondCandidate = await latestPin();
    expect(secondCandidate.version).toBe(4);
    expect(secondCandidate.status).toBe("candidate");

    const stale = await pool.query("SELECT status FROM tool_pins WHERE id = $1", [firstCandidate.id]);
    expect(stale.rows[0].status).toBe("superseded");
    const staleApproval = await api.inject({
      method: "POST", url: `/v1/tool-pin-candidates/${firstCandidate.id}/approve-for-publication`,
      headers: key
    });
    expect(staleApproval.statusCode).toBe(409);

    await submitAndApprove(secondCandidate.id);
    await publishTestPolicy(pool);
    const row = await toolRow();
    expect(row.quarantined).toBe(false);
    expect(row.definition_version).toBe(4);
    expect(row.definition_hash).toBe(secondCandidate.definition_hash);
    expect(row.active_pin_id).toBe(secondCandidate.id);
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
    const disc = await api.inject({ method: "POST", url: `/v1/servers/${serverId}/discover`, headers: key });
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
