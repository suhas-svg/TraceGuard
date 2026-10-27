import { createServer } from "node:http";
import type { Server as HttpServer } from "node:http";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { generateSigningKey, contentHashOf } from "@traceguard/policy-signing";
import { buildApp } from "../src/index.js";
import { buildGateway } from "../src/gateway.js";
import { pool } from "../src/db.js";
import { publishTestPolicy } from "./policy-helper.js";
import { publish, trustKey } from "../../../tools/policy-publisher/src/index.js";

const PROTOCOL = "2026-07-28";

// §13.3: the gateway trusts only a signed bundle the operator published.
// Every case here removes, forges, rolls back, or retires something and
// demands the protected call fail closed with no upstream contact.
describe("signed policy enforcement", () => {
  const api = buildApp();
  const gw = buildGateway();
  const key = { authorization: "Bearer test_key" };
  const tag = Date.now().toString(36);
  let port = 0;
  let mockServer: HttpServer | null = null;
  let hits = 0;
  let serverId = "";
  let workspaceId = "";
  let projectId = "";
  let v1Id = "";

  async function startMock(): Promise<void> {
    // A fresh server per request: one Protocol instance cannot be connected to
    // two transports, and two gateway calls can be in flight at once.
    const newMock = () => {
    const mock = new Server({ name: "signed-tools", version: "0.1.0" }, { capabilities: { tools: {} } });
    mock.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [{
        name: "echo",
        description: "echo back",
        inputSchema: { type: "object", properties: { text: { type: "string" } } }
      }]
    }));
    mock.setRequestHandler(CallToolRequestSchema, async () => {
      hits += 1;
      return { content: [{ type: "text", text: "ok" }] };
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

  function call(body: Record<string, unknown>) {
    return gw.inject({
      method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: "hi" }, caller: "t", ...body }
    });
  }

  function listTools() {
    return gw.inject({
      method: "POST", url: "/mcp",
      headers: { ...key, "mcp-protocol-version": PROTOCOL, "mcp-method": "tools/list" },
      payload: { jsonrpc: "2.0", id: "rpc-1", method: "tools/list", params: { _meta: {
        "io.modelcontextprotocol/protocolVersion": PROTOCOL,
        "io.modelcontextprotocol/clientCapabilities": { tools: {} }
      } } }
    });
  }

  function writeAnchor(state: Record<string, { version: number; content_hash: string }>): void {
    const file = join(process.env.GATEWAY_STATE_DIR ?? "", "policy-state.json");
    writeFileSync(file, JSON.stringify(state));
  }

  function readAnchor(): Record<string, { version: number; content_hash: string }> {
    const file = join(process.env.GATEWAY_STATE_DIR ?? "", "policy-state.json");
    return JSON.parse(readFileSync(file, "utf8"));
  }

  async function activeVersionId(): Promise<string> {
    const res = await pool.query(
      "SELECT policy_version_id FROM active_config WHERE project_id = $1", [projectId]
    );
    return String(res.rows[0].policy_version_id);
  }

  beforeAll(async () => {
    await startMock();
    const reg = await api.inject({
      method: "POST", url: "/v1/servers", headers: key,
      payload: { name: `signed-${tag}`, base_url: `http://127.0.0.1:${port}/mcp` }
    });
    expect(reg.statusCode).toBe(201);
    serverId = reg.json().id as string;
    const disc = await api.inject({ method: "POST", url: `/v1/servers/${serverId}/discover`, headers: key });
    expect(disc.statusCode).toBe(200);
    const ws = await pool.query("SELECT id FROM workspaces WHERE name = 'default'");
    workspaceId = String(ws.rows[0].id);
    const project = await pool.query(
      "SELECT id FROM projects WHERE workspace_id = $1 AND name = 'default'", [workspaceId]
    );
    projectId = String(project.rows[0].id);
  });

  afterAll(async () => {
    if (mockServer) await new Promise<void>((resolve) => mockServer?.close(() => resolve()));
    await api.close();
    await gw.close();
    await pool.end();
  });

  it("refuses protected calls and listing until a signed policy is active", async () => {
    const before = hits;
    const res = await call({});
    expect(res.statusCode).toBe(503);
    expect(res.json().error).toBe("policy_unavailable");
    expect(hits).toBe(before);

    const listed = await listTools();
    expect(listed.statusCode).toBe(200);
    const body = listed.json() as { error?: { data?: { error?: string } } };
    expect(body.error?.data?.error).toBe("POLICY_UNAVAILABLE");

    // The refusal is evidence, not silence.
    const decision = await pool.query(
      `SELECT decision, reason FROM policy_decisions WHERE server_id = $1 ORDER BY timestamp DESC LIMIT 1`,
      [serverId]
    );
    expect(decision.rows[0].decision).toBe("deny");
    expect(String(decision.rows[0].reason)).toContain("policy unavailable");

    // The draft rule exists before any bundle does; nothing enforces it yet.
    const rule = await api.inject({ method: "POST", url: "/v1/policies", headers: key,
      payload: { name: `signed-allow-${tag}`, server_id: serverId, tool_name: "echo", effect: "allow" } });
    expect(rule.statusCode).toBe(201);
  });

  it("activates exactly what the signed bundle carries", async () => {
    const before = hits;
    expect(await publishTestPolicy(pool)).toBe(1);
    const res = await call({});
    expect(res.statusCode).toBe(200);
    expect(hits).toBe(before + 1);
    const listed = await listTools();
    const tools = (listed.json() as { result: { tools: { name: string }[] } }).result.tools;
    expect(tools.length).toBe(1);
    expect(tools[0].name).toMatch(/__echo$/);
  });

  it("refuses a server that is not in the active signed policy", async () => {
    const reg = await api.inject({
      method: "POST", url: "/v1/servers", headers: key,
      payload: { name: `signed-extra-${tag}`, base_url: `http://127.0.0.1:${port}/mcp` }
    });
    const extraId = reg.json().id as string;
    await api.inject({ method: "POST", url: `/v1/servers/${extraId}/discover`, headers: key });
    const before = hits;
    const res = await gw.inject({
      method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: extraId, tool: "echo", arguments: { text: "hi" }, caller: "t" }
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().reason).toContain("not in the active signed policy");
    expect(hits).toBe(before);
    // And it is not listed: registration alone is a draft.
    const listed = await listTools();
    const names = (listed.json() as { result: { tools: { name: string }[] } }).result.tools
      .map((t) => t.name);
    expect(names.length).toBe(1);
  });

  it("rejects a forged bundle: bad signature, then a mismatched content hash", async () => {
    const keyRow = await pool.query(
      "SELECT id FROM policy_signing_keys WHERE workspace_id = $1 AND retired_at IS NULL", [workspaceId]
    );
    const forged = {
      bundle_version: 2, protocol_profile: PROTOCOL, workspace_id: workspaceId, version: 2,
      previous_version_hash: null, rules: [
        { id: "11111111-1111-1111-1111-111111111111", name: "forged-allow", enabled: true, priority: 0,
          agent_id: null, server_id: serverId, tool_name: "echo", effect: "allow", conditions: {} }
      ],
      servers: [{ server_id: serverId, alias: `signed_${tag}`, base_url: `http://127.0.0.1:${port}/mcp`, auth_mode: "none" }],
      pins: []
    };
    // Two editions an attacker with INSERT rights could plant: one whose
    // signature does not verify, and one whose content hash does not even
    // match its own bytes. Neither is ever editable (the trigger rejects
    // UPDATE), so each is a separate insert.
    const badSig = await pool.query(
      `INSERT INTO policy_versions
         (workspace_id, version, bundle, content_hash, signature, signing_key_id, previous_version_hash, published_by)
       VALUES ($1, 2, $2::jsonb, $3, 'Zm9yZ2Vk', $4, NULL, 'attacker') RETURNING id`,
      [workspaceId, JSON.stringify(forged), contentHashOf(forged), keyRow.rows[0].id]
    );
    const badHash = await pool.query(
      `INSERT INTO policy_versions
         (workspace_id, version, bundle, content_hash, signature, signing_key_id, previous_version_hash, published_by)
       VALUES ($1, 3, $2::jsonb, $3, 'Zm9yZ2Vk', $4, NULL, 'attacker') RETURNING id`,
      [workspaceId, JSON.stringify({ ...forged, version: 3 }), "0".repeat(64), keyRow.rows[0].id]
    );
    const setActive = (id: string) => pool.query(
      `INSERT INTO active_config (project_id, workspace_id, policy_version_id, updated_at) VALUES ($1,$2,$3,now())
       ON CONFLICT (project_id) DO UPDATE SET policy_version_id=EXCLUDED.policy_version_id, updated_at=now()`,
      [projectId, workspaceId, id]
    );

    try {
      await setActive(String(badSig.rows[0].id));
      const before = hits;
      let res = await call({});
      expect(res.statusCode).toBe(503);
      expect(res.json().reason).toContain("signature");
      expect(hits).toBe(before);

      await setActive(String(badHash.rows[0].id));
      res = await call({});
      expect(res.statusCode).toBe(503);
      expect(res.json().reason).toContain("content hash");
      expect(hits).toBe(before);
    } finally {
      // Remove the planted editions so the genuine history this file goes on
      // to publish is contiguous. The pointer moves off them first (the
      // foreign key would refuse the delete otherwise), then the trigger is
      // disabled: the immutability guard stops normal writes, not a database
      // owner, and that is the boundary the signed checkpoints cover.
      const v1 = await pool.query(
        "SELECT id FROM policy_versions WHERE workspace_id = $1 AND version = 1", [workspaceId]
      );
      v1Id = String(v1.rows[0].id);
      await setActive(v1Id);
      await pool.query("ALTER TABLE policy_versions DISABLE TRIGGER policy_versions_immutable");
      try {
        await pool.query("DELETE FROM policy_versions WHERE published_by = 'attacker'");
      } finally {
        await pool.query("ALTER TABLE policy_versions ENABLE TRIGGER policy_versions_immutable");
      }
    }
    expect((await call({})).statusCode).toBe(200);
  });

  it("refuses a rollback to an older signed version", async () => {
    expect(await publishTestPolicy(pool)).toBe(2);
    expect((await call({})).statusCode).toBe(200);

    // A published edition is immutable even for the runtime that can read it.
    await expect(
      pool.query("UPDATE policy_versions SET published_by = 'x' WHERE id = $1", [v1Id])
    ).rejects.toThrow(/immutable/);

    await pool.query(
      "UPDATE active_config SET policy_version_id = $2 WHERE project_id = $1", [projectId, v1Id]
    );
    const before = hits;
    const res = await call({});
    expect(res.statusCode).toBe(503);
    expect(res.json().reason).toContain("rollback");
    expect(hits).toBe(before);

    // Restore the current pointer for the tests that follow.
    const v2 = await pool.query(
      "SELECT id FROM policy_versions WHERE workspace_id = $1 AND version = 2", [workspaceId]
    );
    await pool.query(
      "UPDATE active_config SET policy_version_id = $2 WHERE project_id = $1", [projectId, v2.rows[0].id]
    );
    expect((await call({})).statusCode).toBe(200);
  });

  it("refuses a fork where the recorded anchor disagrees with the active version", async () => {
    const anchor = readAnchor();
    const good = anchor[projectId];
    writeAnchor({ ...anchor, [projectId]: { version: good.version, content_hash: "0".repeat(64) } });
    try {
      const before = hits;
      const res = await call({});
      expect(res.statusCode).toBe(503);
      expect(res.json().reason).toContain("fork");
      expect(hits).toBe(before);
    } finally {
      writeAnchor({ ...anchor, [projectId]: good });
    }
    expect((await call({})).statusCode).toBe(200);
  });

  it("refuses a bundle signed by a retired key, and accepts the replacement's", async () => {
    const replacement = generateSigningKey();
    const rotated = await trustKey(pool, {
      workspaceId, publicKeyPem: replacement.publicKeyPem, rotate: true, trustedBy: "test"
    });
    expect(rotated.retired.length).toBe(1);

    const before = hits;
    const stale = await call({});
    expect(stale.statusCode).toBe(503);
    expect(stale.json().reason).toContain("retired");
    expect(hits).toBe(before);

    // Re-publish under the new key: the rotation only ends when a bundle
    // signed by the replacement is active.
    await publish(pool, { workspaceId, privateKeyPem: replacement.privateKeyPem, publishedBy: "test" });
    expect((await call({})).statusCode).toBe(200);
  });

  it("records the exact signed version on every decision", async () => {
    const rows = await pool.query(
      `SELECT d.decision, d.policy_version_id, pv.version
         FROM policy_decisions d
         LEFT JOIN policy_versions pv ON pv.id = d.policy_version_id
        WHERE d.server_id = $1 ORDER BY d.timestamp DESC LIMIT 10`,
      [serverId]
    );
    const allow = rows.rows.find((r) => r.decision === "allow");
    expect(allow?.policy_version_id).toBeTruthy();
    expect(Number(allow?.version)).toBeGreaterThanOrEqual(1);
    // The decision that was refused for an unavailable policy cites no
    // version, because there was none to cite.
    const denied = rows.rows.find((r) => r.decision === "deny");
    expect(denied).toBeTruthy();
  });

  it("verifies the audit chain and detects a tampered event", async () => {
    const ok = await gw.inject({ method: "POST", url: "/v1/audit/verify", headers: key });
    expect(ok.statusCode).toBe(200);
    const okBody = ok.json();
    // Surface the verifier's findings: a bare `false` says nothing about
    // whether a link, a hash, or a workspace sequence failed.
    expect(okBody.ok, JSON.stringify(okBody.problems)).toBe(true);
    expect(okBody.checked).toBeGreaterThan(0);

    // A database owner tampering with an event is exactly who this verifier
    // exists for: the append-only trigger has to be disabled first, and that
    // is the boundary the external checkpoint story covers.
    const target = await pool.query(
      "SELECT id, metadata, hash FROM audit_events ORDER BY timestamp ASC, id ASC LIMIT 1"
    );
    const row = target.rows[0];
    await pool.query("ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only");
    try {
      await pool.query(
        "UPDATE audit_events SET metadata = coalesce(metadata,'{}'::jsonb) || '{\"tampered\":true}'::jsonb WHERE id = $1",
        [row.id]
      );
      const bad = await gw.inject({ method: "POST", url: "/v1/audit/verify", headers: key });
      expect(bad.json().ok).toBe(false);
      const problem = (bad.json().problems as { id: string; problem: string }[])[0];
      expect(problem.id).toBe(row.id);
      expect(problem.problem).toContain("modified");
    } finally {
      await pool.query("UPDATE audit_events SET metadata = $2::jsonb WHERE id = $1",
        [row.id, JSON.stringify(row.metadata)]);
      await pool.query("ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only");
    }
    const restored = await gw.inject({ method: "POST", url: "/v1/audit/verify", headers: key });
    expect(restored.json().ok).toBe(true);
    // The append-only guard is real: a plain UPDATE is rejected.
    await expect(
      pool.query("UPDATE audit_events SET result = 'x' WHERE id = $1", [row.id])
    ).rejects.toThrow(/append-only/);
    expect(await activeVersionId()).toBeTruthy();
    const scoped = await pool.query(
      `SELECT count(*)::int AS n FROM audit_events
        WHERE action IN ('policy.published','tool.execute') AND project_id IS NOT NULL`
    );
    expect(scoped.rows[0].n).toBeGreaterThan(0);
  });
});
