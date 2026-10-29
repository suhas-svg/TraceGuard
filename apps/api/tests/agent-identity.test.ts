import { createPublicKey, generateKeyPairSync, randomUUID, sign as cryptoSign } from "node:crypto";
import { createServer } from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { buildApp } from "../src/index.js";
import { buildGateway } from "../src/gateway.js";
import { pool } from "../src/db.js";
import { publishTestPolicy } from "./policy-helper.js";

const ISSUER = "https://issuer.agent-identity.test";
const AUDIENCE = "http://localhost:8091/mcp";
const PROTOCOL = "2026-07-28";
const API_KEY = { authorization: "Bearer test_key" };
const tag = Date.now().toString(36);

const b64 = (value: unknown): string =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

let api: ReturnType<typeof buildApp>;
let gw: ReturnType<typeof buildGateway>;
let workspaceId = "";
let workspaceName = "";
let projectId = "";
let otherProjectId = "";
let serverId = "";
let alias = "";
let principalA = "";
let principalB = "";
let foreignPrincipal = "";
let tokenA = "";
let tokenB = "";
let httpServer: ReturnType<typeof createServer>;
let upstreamHits = 0;

const originalEnv = { ...process.env };
const dir = mkdtempSync(join(tmpdir(), "tg-agent-identity-"));
const kid = `agent-identity-${tag}`;
const ed = generateKeyPairSync("ed25519");
const jwksFile = join(dir, "jwks.json");

function mint(project: string, scope: string, subject: string): string {
  const header = b64({ alg: "EdDSA", typ: "JWT", kid });
  const payload = b64({
    iss: ISSUER,
    aud: AUDIENCE,
    resource: AUDIENCE,
    sub: subject,
    exp: Math.floor(Date.now() / 1000) + 300,
    scope,
    projects: [project],
    workspaces: [workspaceId]
  });
  const signature = cryptoSign(null, Buffer.from(`${header}.${payload}`), ed.privateKey)
    .toString("base64url");
  return `${header}.${payload}.${signature}`;
}

const bearer = (token: string) => ({ authorization: `Bearer ${token}` });
const meta = () => ({
  "io.modelcontextprotocol/protocolVersion": PROTOCOL,
  "io.modelcontextprotocol/clientCapabilities": { tools: {} }
});

function rpc(
  token: string,
  method: string,
  params: Record<string, unknown>,
  name?: string
) {
  return gw.inject({
    method: "POST",
    url: "/mcp",
    headers: {
      ...bearer(token),
      "mcp-protocol-version": PROTOCOL,
      "mcp-method": method,
      ...(name ? { "mcp-name": name } : {})
    },
    payload: { jsonrpc: "2.0", id: "agent-identity", method, params }
  });
}

// §8.2/§9.1: policy and budget agent identity must come from the authenticated
// AgentPrincipal. The request body is not an identity document, so a caller
// cannot select another agent's rules by naming it.
describe("authenticated agent identity", () => {
  beforeAll(async () => {
    writeFileSync(jwksFile, JSON.stringify({
      keys: [{ ...createPublicKey(ed.privateKey).export({ format: "jwk" }), kid, use: "sig" }]
    }));
    process.env.OAUTH_ISSUER = ISSUER;
    process.env.OAUTH_AUDIENCE = AUDIENCE;
    process.env.OAUTH_JWKS_FILE = jwksFile;
    delete process.env.OAUTH_JWKS_URL;

    api = buildApp();
    gw = buildGateway();

    // Server and policy admin routes resolve projects against the default
    // workspace, so keep this fixture there rather than creating a sibling.
    workspaceName = "default";
    const ws = await api.inject({
      method: "POST", url: "/v1/workspaces", headers: API_KEY,
      payload: { name: workspaceName }
    });
    expect([201, 409]).toContain(ws.statusCode);
    workspaceId = ws.statusCode === 201
      ? ws.json().id
      : (await pool.query("SELECT id FROM workspaces WHERE name = 'default'")).rows[0].id;

    const project = async (name: string) => {
      const res = await api.inject({
        method: "POST", url: "/v1/projects", headers: API_KEY,
        payload: { workspace_id: workspaceId, name }
      });
      expect(res.statusCode).toBe(201);
      return res.json().id as string;
    };
    // publishTestPolicy publishes the project named "default"; keep the
    // callable fixture there and use the second project only for isolation.
    // Migration 038's workspace trigger may already have created it.
    const existingDefault = await pool.query(
      "SELECT id FROM projects WHERE workspace_id = $1 AND name = 'default'",
      [workspaceId]
    );
    projectId = existingDefault.rows[0]?.id ?? await project("default");
    otherProjectId = await project(`other-project-${tag}`);

    const provision = async (project: string, subject: string) => {
      const res = await api.inject({
        method: "POST", url: `/v1/projects/${project}/agent-principals`, headers: API_KEY,
        payload: {
          issuer: ISSUER,
          subject,
          display_name: subject,
          allowed_scopes: ["gateway", "read"]
        }
      });
      expect(res.statusCode).toBe(201);
      return res.json().id as string;
    };
    principalA = await provision(projectId, `agent-a-${tag}`);
    principalB = await provision(projectId, `agent-b-${tag}`);
    foreignPrincipal = await provision(otherProjectId, `agent-foreign-${tag}`);
    tokenA = mint(projectId, "gateway read", `agent-a-${tag}`);
    tokenB = mint(projectId, "gateway read", `agent-b-${tag}`);

    httpServer = createServer(async (req, res) => {
      if (req.method === "POST") {
        const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
        res.on("close", () => transport.close().catch(() => undefined));
        const mock = new McpServer({ name: "agent-identity-tools", version: "0.1.0" });
        mock.registerTool("echo", { description: "echo back", inputSchema: { text: z.string() } },
          async ({ text }) => {
            upstreamHits++;
            return { content: [{ type: "text", text: `echo:${text}` }] };
          });
        await mock.connect(transport);
        await transport.handleRequest(req, res);
        return;
      }
      res.writeHead(405).end();
    });
    await new Promise<void>((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
    const port = (httpServer.address() as { port: number }).port;

    const reg = await api.inject({
      method: "POST", url: "/v1/servers", headers: API_KEY,
      payload: {
        name: `agent-identity-${tag}`,
        base_url: `http://127.0.0.1:${port}/mcp`,
        project_id: projectId
      }
    });
    expect(reg.statusCode).toBe(201);
    serverId = reg.json().id;
    alias = reg.json().gateway_alias;

    const disc = await api.inject({
      method: "POST", url: `/v1/servers/${serverId}/discover`, headers: API_KEY
    });
    expect(disc.statusCode).toBe(200);

    const allow = await api.inject({
      method: "POST", url: "/v1/policies", headers: API_KEY,
      payload: {
        name: `allow-echo-${tag}`, priority: 0, server_id: serverId,
        tool_name: "echo", effect: "allow", project_id: projectId
      }
    });
    expect(allow.statusCode).toBe(201);
    const deny = await api.inject({
      method: "POST", url: "/v1/policies", headers: API_KEY,
      payload: {
        name: `agent-deny-${tag}`, priority: 200, agent_id: principalA,
        effect: "deny", project_id: projectId
      }
    });
    expect(deny.statusCode).toBe(201);

    await publishTestPolicy(pool, workspaceName);
  });

  afterAll(async () => {
    if (httpServer) await new Promise<void>((resolve) => httpServer.close(() => resolve()));
    await api.close();
    await gw.close();
    await pool.end();
    rmSync(dir, { recursive: true, force: true });
    for (const key of Object.keys(process.env)) {
      if (!(key in originalEnv)) delete process.env[key];
    }
    Object.assign(process.env, originalEnv);
  });

  it("applies an agent-scoped deny to the authenticated principal", async () => {
    const before = upstreamHits;
    const denied = await gw.inject({
      method: "POST", url: "/v1/gateway/tools/call", headers: bearer(tokenA),
      payload: { server_id: serverId, tool: "echo", arguments: { text: "blocked" } }
    });
    expect(denied.statusCode).toBe(403);
    expect(denied.json().reason).toContain(`agent-deny-${tag}`);
    expect(upstreamHits).toBe(before);

    const allowed = await gw.inject({
      method: "POST", url: "/v1/gateway/tools/call", headers: bearer(tokenB),
      payload: { server_id: serverId, tool: "echo", arguments: { text: "allowed" } }
    });
    expect([200, 202]).toContain(allowed.statusCode);
    expect(upstreamHits).toBe(before + 1);
  });

  it("rejects a body agent_id instead of letting it select another agent", async () => {
    const before = upstreamHits;
    const spoof = await gw.inject({
      method: "POST", url: "/v1/gateway/tools/call", headers: bearer(tokenB),
      payload: {
        server_id: serverId, tool: "echo", arguments: { text: "spoof" },
        agent_id: principalA
      }
    });
    expect(spoof.statusCode).toBe(400);
    expect(spoof.json().error).toBe("agent_id_not_accepted");
    expect(upstreamHits).toBe(before);
  });

  it("applies agent-scoped rules to MCP calls before forwarding", async () => {
    const before = upstreamHits;
    const denied = await rpc(tokenA, "tools/call", {
      name: `${alias}__echo`, arguments: { text: "mcp-blocked" }, _meta: meta()
    }, `${alias}__echo`);
    expect(denied.statusCode).toBe(200);
    expect(denied.json().error.code).toBe(-32001);
    expect(denied.json().error.data.error).toBe("tool_blocked");
    expect(denied.json().error.data.reason).toContain(`agent-deny-${tag}`);
    expect(upstreamHits).toBe(before);

    const allowed = await rpc(tokenB, "tools/call", {
      name: `${alias}__echo`, arguments: { text: "mcp-allowed" }, _meta: meta()
    }, `${alias}__echo`);
    expect(allowed.statusCode).toBe(200);
    expect(allowed.json().result.content[0].text).toBe("echo:mcp-allowed");
    expect(upstreamHits).toBe(before + 1);
  });

  it("rejects policy drafts that name a telemetry agent or a foreign principal", async () => {
    const telemetryAgent = randomUUID();
    await pool.query(
      "INSERT INTO agents (id, workspace_id, name) VALUES ($1,$2,$3)",
      [telemetryAgent, workspaceId, `telemetry-${tag}`]
    );
    const telemetryDraft = await api.inject({
      method: "POST", url: "/v1/policies", headers: API_KEY,
      payload: {
        name: `telemetry-scope-${tag}`, agent_id: telemetryAgent,
        effect: "deny", project_id: projectId
      }
    });
    expect(telemetryDraft.statusCode).toBe(400);
    expect(telemetryDraft.json().reason).toBe("agent_principal_not_in_project");

    const foreignDraft = await api.inject({
      method: "POST", url: "/v1/policies", headers: API_KEY,
      payload: {
        name: `foreign-scope-${tag}`, agent_id: foreignPrincipal,
        effect: "deny", project_id: projectId
      }
    });
    expect(foreignDraft.statusCode).toBe(400);
    expect(foreignDraft.json().reason).toBe("agent_principal_not_in_project");
  });
});
