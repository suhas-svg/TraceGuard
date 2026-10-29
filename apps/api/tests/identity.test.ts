import { createPublicKey, generateKeyPairSync, randomUUID, sign as cryptoSign } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildApp } from "../src/index.js";
import { buildGatewayControl } from "../src/gateway.js";
import { pool } from "../src/db.js";

// §7.1/§13.1/§14: projects are the policy/data scope, agent principals are
// non-human MCP callers bound to one project, and ingestion keys are a
// separate credential type that can only submit telemetry.
describe("identity model", () => {
  const api = buildApp();
  const key = { authorization: "Bearer test_key" };
  const tag = Date.now().toString(36);
  let workspaceId = "";
  let otherWorkspaceId = "";
  let projectId = "";
  let otherProjectId = "";

  const post = (url: string, body: unknown, headers: Record<string, string> = key) =>
    api.inject({ method: "POST", url, headers, payload: body as never });
  const get = (url: string, headers: Record<string, string> = key) =>
    api.inject({ method: "GET", url, headers });
  const patch = (url: string, body: unknown, headers: Record<string, string> = key) =>
    api.inject({ method: "PATCH", url, headers, payload: body as never });

  const newEvent = (project: string, workspace = workspaceId) => ({
    schema_version: "1",
    event_id: `identity-${randomUUID()}`,
    agent_name: `identity-agent-${tag}`,
    run_id: randomUUID(),
    span_id: randomUUID(),
    parent_span_id: null,
    event_type: "model.request",
    timestamp: "2026-10-13T12:00:00.000Z",
    status: "success",
    attributes: {},
    workspace_id: workspace,
    project_id: project
  });

  beforeAll(async () => {
    const created = await post("/v1/workspaces", { name: `identity-ws-${tag}` });
    expect(created.statusCode).toBe(201);
    workspaceId = created.json().id;
    const other = await post("/v1/workspaces", { name: `identity-other-${tag}` });
    expect(other.statusCode).toBe(201);
    otherWorkspaceId = other.json().id;

    const project = await post("/v1/projects", { workspace_id: workspaceId, name: "alpha" });
    expect(project.statusCode).toBe(201);
    projectId = project.json().id;
    const otherProject = await post("/v1/projects", {
      workspace_id: otherWorkspaceId, name: "beta"
    });
    expect(otherProject.statusCode).toBe(201);
    otherProjectId = otherProject.json().id;
  });

  afterAll(async () => {
    await api.close();
    await pool.end();
  });

  it("creates a default project in every new workspace", async () => {
    const res = await get("/v1/projects");
    expect(res.statusCode).toBe(200);
    const defaults = res.json().items.filter(
      (p: { workspace_id: string; name: string }) =>
        p.workspace_id === workspaceId && p.name === "default");
    expect(defaults).toHaveLength(1);
  });

  it("supports project CRUD and name uniqueness", async () => {
    const one = await get(`/v1/projects/${projectId}`);
    expect(one.statusCode).toBe(200);
    expect(one.json()).toMatchObject({ id: projectId, name: "alpha", status: "active" });

    const updated = await patch(`/v1/projects/${projectId}`, {
      name: `alpha-${tag}`, status: "archived"
    });
    expect(updated.statusCode).toBe(200);
    expect(updated.json()).toMatchObject({ name: `alpha-${tag}`, status: "archived" });

    const duplicate = await post("/v1/projects", {
      workspace_id: workspaceId, name: `alpha-${tag}`
    });
    expect(duplicate.statusCode).toBe(409);
    expect(duplicate.json().error).toBe("project_name_taken");

    const malformed = await get("/v1/projects/not-a-uuid");
    expect(malformed.statusCode).toBe(400);
    const emptyPatch = await patch(`/v1/projects/${projectId}`, {});
    expect(emptyPatch.statusCode).toBe(400);
  });

  it("scopes project lists and reads to a member's workspace", async () => {
    const user = await post("/v1/users", {
      email: `member-${tag}@example.test`,
      password: "correct horse battery",
      role: "member"
    });
    expect(user.statusCode).toBe(201);
    const userId = user.json().id;
    const membership = await post(`/v1/users/${userId}/memberships`, { workspace_id: workspaceId });
    expect(membership.statusCode).toBe(201);
    const memberKey = await post(`/v1/users/${userId}/keys`, {
      name: "member-read", scopes: ["read"], workspace_id: workspaceId
    });
    expect(memberKey.statusCode).toBe(201);
    const member = { authorization: `Bearer ${memberKey.json().key}` };

    const listed = await get("/v1/projects", member);
    expect(listed.statusCode).toBe(200);
    expect(listed.json().items.length).toBeGreaterThan(0);
    for (const p of listed.json().items) expect(p.workspace_id).toBe(workspaceId);
    expect(listed.json().items.some((p: { id: string }) => p.id === otherProjectId)).toBe(false);

    expect((await get(`/v1/projects/${projectId}`, member)).statusCode).toBe(200);
    expect((await get(`/v1/projects/${otherProjectId}`, member)).statusCode).toBe(404);
    expect((await post("/v1/projects", { workspace_id: workspaceId, name: "member-made" }, member))
      .statusCode).toBe(403);

    const me = await get("/v1/auth/me", member);
    expect(me.statusCode).toBe(200);
    expect(me.json()).toMatchObject({ kind: "user", user_id: userId });
    expect(me.json().projects).toContain(projectId);
    expect(me.json().projects).not.toContain(otherProjectId);
  });

  it("issues ingest-only keys and enforces their project boundary", async () => {
    const made = await post(`/v1/projects/${projectId}/ingest-keys`, {
      name: `otlp-${tag}`, expires_days: 7
    });
    expect(made.statusCode).toBe(201);
    const plaintext = made.json().key as string;
    expect(plaintext.startsWith("tgi_")).toBe(true);
    expect(made.json().project_id).toBe(projectId);

    const list = await get(`/v1/projects/${projectId}/ingest-keys`);
    expect(list.statusCode).toBe(200);
    expect(list.json().items[0].key).toBeUndefined();
    expect(list.json().items[0].key_hash).toBeUndefined();

    const ingest = { authorization: `Bearer ${plaintext}` };
    const event = newEvent(projectId);
    const accepted = await api.inject({
      method: "POST", url: "/v1/ingest/events", headers: ingest, payload: { events: [event] }
    });
    expect(accepted.statusCode).toBe(200);
    const run = await pool.query("SELECT project_id FROM runs WHERE id = $1", [event.run_id]);
    expect(run.rows[0]?.project_id).toBe(projectId);

    const foreign = await api.inject({
      method: "POST", url: "/v1/ingest/events", headers: ingest,
      payload: { events: [newEvent(otherProjectId)] }
    });
    expect(foreign.statusCode).toBe(403);
    expect(foreign.json().error).toBe("project_forbidden");

    expect((await get("/v1/projects", ingest)).statusCode).toBe(403);
    expect((await post("/v1/projects", { name: "nope" }, ingest)).statusCode).toBe(403);
    const onMcp = await api.inject({
      method: "POST", url: "/mcp", headers: ingest,
      payload: { jsonrpc: "2.0", id: 1, method: "server/discover", params: {} }
    });
    expect(onMcp.statusCode).toBe(403);
    expect(onMcp.json().error).toBe("ingest_key_scope");

    const revoked = await post(`/v1/ingest-keys/${made.json().id}/revoke`, {});
    expect(revoked.statusCode).toBe(200);
    expect(revoked.json().revoked_at).toBeTruthy();
    const afterRevoke = await api.inject({
      method: "POST", url: "/v1/ingest/events", headers: ingest, payload: { events: [newEvent(projectId)] }
    });
    expect(afterRevoke.statusCode).toBe(401);
  });

  it("refuses human approval and admin scopes on agent principals", async () => {
    const subject = `agent-scope-${tag}`;
    const badCreate = await post(`/v1/projects/${projectId}/agent-principals`, {
      issuer: "https://issuer.identity.test",
      subject,
      allowed_scopes: ["gateway", "approve"]
    });
    expect(badCreate.statusCode).toBe(400);
    expect(badCreate.json().error).toBe("invalid_agent_principal");

    const created = await post(`/v1/projects/${projectId}/agent-principals`, {
      issuer: "https://issuer.identity.test",
      subject,
      allowed_scopes: ["gateway", "read"]
    });
    expect(created.statusCode).toBe(201);

    const badPatch = await patch(`/v1/agent-principals/${created.json().id}`, {
      allowed_scopes: ["admin"]
    });
    expect(badPatch.statusCode).toBe(400);
    expect(badPatch.json().error).toBe("invalid_agent_principal");
  });

  it("maps a validated OAuth subject to its project-scoped agent principal", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tg-identity-"));
    const jwksFile = join(dir, "jwks.json");
    const keys = generateKeyPairSync("ed25519");
    const kid = `identity-${tag}`;
    const previous = {
      issuer: process.env.OAUTH_ISSUER,
      audience: process.env.OAUTH_AUDIENCE,
      file: process.env.OAUTH_JWKS_FILE,
      url: process.env.OAUTH_JWKS_URL,
      nodeEnv: process.env.NODE_ENV
    };
    writeFileSync(jwksFile, JSON.stringify({
      keys: [{ ...createPublicKey(keys.privateKey).export({ format: "jwk" }), kid, use: "sig" }]
    }));
    process.env.OAUTH_ISSUER = "https://issuer.identity.test";
    process.env.OAUTH_AUDIENCE = "http://localhost:8091/mcp";
    process.env.OAUTH_JWKS_FILE = jwksFile;
    delete process.env.OAUTH_JWKS_URL;

    try {
      const principal = await post(`/v1/projects/${projectId}/agent-principals`, {
        issuer: "https://issuer.identity.test",
        subject: "agent-42",
        display_name: "test agent",
        allowed_scopes: ["gateway", "read"]
      });
      expect(principal.statusCode).toBe(201);

      const now = Math.floor(Date.now() / 1000);
      const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
      const header = b64({ alg: "EdDSA", typ: "JWT", kid });
      const payload = b64({
        iss: "https://issuer.identity.test",
        aud: "http://localhost:8091/mcp",
        resource: "http://localhost:8091/mcp",
        sub: "agent-42",
        exp: now + 300,
        scope: "gateway read admin",
        // The issuer may name more than one project, but only the one with a
        // provisioned AgentPrincipal may be acted in.
        projects: [projectId, otherProjectId],
        workspaces: [workspaceId, otherWorkspaceId]
      });
      const signature = cryptoSign(null, Buffer.from(`${header}.${payload}`), keys.privateKey);
      const oauth = { authorization: `Bearer ${header}.${payload}.${signature.toString("base64url")}` };

      const who = await get("/v1/whoami", oauth);
      expect(who.statusCode).toBe(200);
      expect(who.json()).toMatchObject({
        kind: "oauth",
        user_id: "agent-42",
        agent_principal_id: principal.json().id,
        issuer: "https://issuer.identity.test",
        projects: [projectId]
      });
      expect(who.json().scopes.sort()).toEqual(["gateway", "read"]);

      const listed = await get("/v1/projects", oauth);
      expect(listed.statusCode).toBe(200);
      expect(listed.json().items.map((p: { id: string }) => p.id)).toEqual([projectId]);
      expect((await get(`/v1/projects/${projectId}`, oauth)).statusCode).toBe(200);
      expect((await get(`/v1/projects/${otherProjectId}`, oauth)).statusCode).toBe(404);

      // Even if the issuer token carries a human scope, an agent principal
      // cannot reach the human approval listener.
      const ctl = buildGatewayControl();
      try {
        const control = await ctl.inject({
          method: "GET", url: "/_control/v1/approvals", headers: oauth
        });
        expect(control.statusCode).toBe(403);
        expect(control.json().error).toBe("agent_principal_forbidden");
      } finally {
        await ctl.close();
      }

      const disabled = await patch(`/v1/agent-principals/${principal.json().id}`, {
        status: "disabled"
      });
      expect(disabled.statusCode).toBe(200);
      const afterDisable = await get("/v1/whoami", oauth);
      expect(afterDisable.statusCode).toBe(200);
      expect(afterDisable.json().agent_principal_id).toBeNull();

      // Production refuses a valid token with no active principal before it
      // can list or call tools, instead of treating it as a person or an
      // unprovisioned agent. Discovery remains available.
      process.env.NODE_ENV = "production";
      const blocked = await api.inject({
        method: "POST", url: "/mcp", headers: oauth,
        payload: { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }
      });
      expect(blocked.statusCode).toBe(403);
      expect(blocked.json().error).toBe("agent_principal_required");
    } finally {
      for (const [name, value] of [
        ["OAUTH_ISSUER", previous.issuer],
        ["OAUTH_AUDIENCE", previous.audience],
        ["OAUTH_JWKS_FILE", previous.file],
        ["OAUTH_JWKS_URL", previous.url],
        ["NODE_ENV", previous.nodeEnv]
      ] as const) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("deduplicates approvals per project and caller, not globally", async () => {
    const servers = await Promise.all([
      pool.query(
        `INSERT INTO mcp_servers (workspace_id, project_id, name, gateway_alias, base_url)
         VALUES ($1, $2, $3, $4, 'http://127.0.0.1:9') RETURNING id`,
        [workspaceId, projectId, `dedupe-a-${tag}`, `dedupe_a_${tag}`]),
      pool.query(
        `INSERT INTO mcp_servers (workspace_id, project_id, name, gateway_alias, base_url)
         VALUES ($1, $2, $3, $4, 'http://127.0.0.1:9') RETURNING id`,
        [otherWorkspaceId, otherProjectId, `dedupe-b-${tag}`, `dedupe_b_${tag}`])
    ]);
    const args = JSON.stringify({ text: "same" });
    const insert = (project: string, workspace: string, serverId: string) => pool.query(
      `INSERT INTO approvals
         (request_id, workspace_id, project_id, caller, server_id, tool_name,
          args_hash, args, expires_at)
       VALUES ($1, $2, $3, $4, $5, 'echo', $6, $7::jsonb, now() + interval '15 minutes')`,
      ["shared-logical-id", workspace, project, "caller-1", serverId, "hash", args]);

    await expect(insert(projectId, workspaceId, servers[0].rows[0].id)).resolves.toBeTruthy();
    await expect(insert(otherProjectId, otherWorkspaceId, servers[1].rows[0].id)).resolves.toBeTruthy();
    await expect(insert(projectId, workspaceId, servers[0].rows[0].id)).rejects.toMatchObject({
      code: "23505"
    });
  });

  it("returns whoami identity, scopes, and project scope for an env key", async () => {
    const res = await get("/v1/whoami");
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      kind: "env", user_id: null, agent_principal_id: null,
      scopes: ["admin", "ingest", "gateway", "read"], projects: "all"
    });
  });
});
