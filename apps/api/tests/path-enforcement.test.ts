import { createServer } from "node:http";
import type { Server as HttpServer } from "node:http";
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { buildApp } from "../src/index.js";
import { buildGateway } from "../src/gateway.js";
import { pool } from "../src/db.js";
import { publishTestPolicy } from "./policy-helper.js";


const ROOT = "/data";

// FR-010 / §16.3 T9: path_within is a boundary only when the executor inside
// the upstream enforces it. The pinned definition must attest that enforcement
// (io.traceguard/path-confinement), the publisher refuses anything else, and
// the gateway fails closed if a bundle ever reaches it without the attestation.
describe("executor path confinement", () => {
  const api = buildApp();
  const gw = buildGateway();
  const key = { authorization: "Bearer test_key" };
  const tag = Date.now().toString(36);
  let port = 0;
  let mockServer: HttpServer | null = null;
  let serverId = "";
  let upstreamCalls = 0;
  let originalDefinition: Record<string, unknown> = {};

  const inputSchema = {
    type: "object",
    properties: { path: { type: "string" } },
    required: ["path"]
  };
  const tools = [
    {
      name: "read_file",
      description: "confined read",
      inputSchema,
      _meta: { "io.traceguard/path-confinement": { root: ROOT, enforcement: "executor" } }
    },
    { name: "read_file_unconfined", description: "no attestation", inputSchema }
  ];

  async function startMock(): Promise<void> {
    // A fresh server per request, as in the other suite mocks: one Protocol
    // instance cannot be connected to two transports.
    const newMock = () => {
      const mock = new Server(
        { name: "path-tools", version: "0.1.0" },
        { capabilities: { tools: {} } }
      );
      mock.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
      mock.setRequestHandler(CallToolRequestSchema, async (req) => {
        upstreamCalls += 1;
        const path = (req.params.arguments as { path?: string } | undefined)?.path ?? "";
        return { content: [{ type: "text", text: `contents of ${path}` }] };
      });
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
    await startMock();
    const reg = await api.inject({
      method: "POST", url: "/v1/servers", headers: key,
      payload: { name: `path-${tag}`, base_url: `http://127.0.0.1:${port}/mcp` }
    });
    expect(reg.statusCode).toBe(201);
    serverId = reg.json().id as string;
    const disc = await api.inject({ method: "POST", url: `/v1/servers/${serverId}/discover`, headers: key });
    expect(disc.statusCode).toBe(200);
    expect((disc.json().pinned as string[]).sort()).toEqual(["read_file", "read_file_unconfined"]);
    const row = await pool.query(
      "SELECT definition FROM server_tools WHERE server_id = $1 AND tool_name = 'read_file'",
      [serverId]
    );
    originalDefinition = row.rows[0].definition as Record<string, unknown>;
  });

  afterAll(async () => {
    if (mockServer) await new Promise<void>((resolve) => mockServer?.close(() => resolve()));
    await api.close();
    await gw.close();
    await pool.end();
  });

  async function createRule(payload: Record<string, unknown>): Promise<string> {
    const res = await api.inject({
      method: "POST", url: "/v1/policies", headers: key,
      payload: { enabled: true, priority: 0, effect: "allow", ...payload }
    });
    expect(res.statusCode).toBe(201);
    return res.json().id as string;
  }

  async function dropRule(id: string): Promise<void> {
    await pool.query("DELETE FROM policies WHERE id = $1", [id]);
  }

  function call(tool: string, path: string, caller: string) {
    return gw.inject({
      method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: {
        server_id: serverId, tool, arguments: { path }, caller,
        request_id: `${caller}-${tag}`, run_id: randomUUID()
      }
    });
  }

  it("pins the executor attestation even though the _meta allowlist is narrow", async () => {
    // setup.ts pins only io.example/flag; the confinement key is security
    // material and must be pinned unconditionally.
    const row = await pool.query(
      "SELECT definition FROM server_tools WHERE server_id = $1 AND tool_name = 'read_file'",
      [serverId]
    );
    expect(row.rows[0].definition._meta).toEqual({
      "io.traceguard/path-confinement": { root: ROOT, enforcement: "executor" }
    });
    const unattested = await pool.query(
      "SELECT definition FROM server_tools WHERE server_id = $1 AND tool_name = 'read_file_unconfined'",
      [serverId]
    );
    expect(unattested.rows[0].definition._meta).toBeUndefined();
  });

  it("refuses to publish a path_within rule for a tool with no attestation", async () => {
    const id = await createRule({
      name: `path-no-meta-${tag}`, server_id: serverId, tool_name: "read_file_unconfined",
      conditions: { arguments: { path: { path_within: ROOT } } }
    });
    await expect(publishTestPolicy(pool)).rejects.toThrow(/path-confinement/);
    await dropRule(id);
  });

  it("refuses to publish a path_within constraint outside the attested root", async () => {
    const id = await createRule({
      name: `path-outside-${tag}`, server_id: serverId, tool_name: "read_file",
      conditions: { arguments: { path: { path_within: "/etc" } } }
    });
    await expect(publishTestPolicy(pool)).rejects.toThrow(/outside the executor's attested root/);
    await dropRule(id);
  });

  it("publishes an attested, in-root rule and lets the call through once", async () => {
    await createRule({
      name: `path-ok-${tag}`, server_id: serverId, tool_name: "read_file",
      conditions: { arguments: { path: { path_within: ROOT } } }
    });
    const version = await publishTestPolicy(pool);
    expect(version).toBeGreaterThanOrEqual(1);

    const before = upstreamCalls;
    const res = await call("read_file", `${ROOT}/report.txt`, "path-ok");
    expect(res.statusCode).toBe(200);
    expect(res.json().result.content[0].text).toBe(`contents of ${ROOT}/report.txt`);
    expect(upstreamCalls).toBe(before + 1);
  });

  it("fails closed when a live definition loses the attestation after publish", async () => {
    // Defense in depth: a bundle published before this requirement (or via a
    // path the publisher does not police) can still be evaluated. The pin hash
    // is deliberately left untouched so only the runtime path check can catch
    // it — exactly the case the spec calls "gateway string validation alone is
    // insufficient".
    await pool.query(
      "UPDATE server_tools SET definition = definition - '_meta' WHERE server_id = $1 AND tool_name = 'read_file'",
      [serverId]
    );
    const before = upstreamCalls;
    const res = await call("read_file", `${ROOT}/report.txt`, "path-stale");
    expect(res.statusCode).toBe(403);
    expect(res.json()).toMatchObject({ error: "tool_blocked", code: "path_enforcement" });
    expect(res.json().reason).toMatch(/attestation/);
    expect(upstreamCalls).toBe(before);

    const decision = await pool.query(
      "SELECT decision, reason, run_id FROM policy_decisions WHERE caller = $1 ORDER BY timestamp DESC LIMIT 1",
      ["path-stale"]
    );
    expect(decision.rows[0].decision).toBe("deny");
    expect(decision.rows[0].reason).toMatch(/path enforcement refused/);
    expect(decision.rows[0].run_id).toBeTruthy();

    const audited = await pool.query(
      `SELECT metadata FROM audit_events
        WHERE action = 'tool.execute' AND result = 'denied'
        ORDER BY timestamp DESC LIMIT 1`
    );
    expect(audited.rows[0].metadata).toMatchObject({ reason: "path_enforcement" });
  });

  it("treats a path_within rule outside the root as unenforceable at call time too", async () => {
    // Same defense-in-depth shape, other refusal branch: the attested root is
    // smaller than the constraint. Rewrite the stored rule's constraint —
    // with the definition restored — and expect the runtime check to refuse.
    await pool.query(
      "UPDATE server_tools SET definition = $2::jsonb WHERE server_id = $1 AND tool_name = 'read_file'",
      [serverId, JSON.stringify(originalDefinition)]
    );
    await pool.query(
      "UPDATE policies SET conditions = $2::jsonb WHERE name = $1",
      [`path-ok-${tag}`, JSON.stringify({ arguments: { path: { path_within: ROOT } } })]
    );
    // The active bundle still carries the in-root constraint, so swap in an
    // outside-root one by hand to exercise the runtime comparison directly.
    const outside = await createRule({
      name: `path-runtime-${tag}`, server_id: serverId, tool_name: "read_file",
      conditions: { arguments: { path: { path_within: `${ROOT}/reports` } } }
    });
    const version = await publishTestPolicy(pool);
    expect(version).toBeGreaterThanOrEqual(1);

    // Shrink the attested root in the stored definition so the published
    // in-root constraint is now outside it (pin hash untouched again).
    const shrunk = {
      ...originalDefinition,
      _meta: { "io.traceguard/path-confinement": { root: "/data/other", enforcement: "executor" } }
    };
    await pool.query(
      "UPDATE server_tools SET definition = $2::jsonb WHERE server_id = $1 AND tool_name = 'read_file'",
      [serverId, JSON.stringify(shrunk)]
    );
    const before = upstreamCalls;
    const res = await call("read_file", "/data/other/x.txt", "path-shrunk");
    expect(res.statusCode).toBe(403);
    expect(res.json()).toMatchObject({ error: "tool_blocked", code: "path_enforcement" });
    expect(res.json().reason).toMatch(/outside the executor's attested root/);
    expect(upstreamCalls).toBe(before);
    await dropRule(outside);
  });
});
