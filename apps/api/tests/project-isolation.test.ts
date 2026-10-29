import { createPublicKey, generateKeyPairSync, randomUUID, sign as cryptoSign } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildApp } from "../src/index.js";
import { buildGateway, buildGatewayControl } from "../src/gateway.js";
import { pool } from "../src/db.js";

// FR-001 / §7.1: a project is the policy and data boundary inside a
// workspace. A project-pinned agent must not be able to read another
// project's runs, traces, approvals, budgets, decisions, or audit events even
// when both projects belong to the same workspace. OAuth agent principals are
// the only production identity that carries a project list, so these tests
// mint a real JWT against a real JWKS and use the API's own provisioning
// route instead of faking a principal.

const ISSUER = "https://issuer.isolation.test";
const AUDIENCE = "http://localhost:8091/mcp";
const API_KEY = { authorization: "Bearer test_key" };
const tag = Date.now().toString(36);

const b64 = (value: unknown): string =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

let api: ReturnType<typeof buildApp>;
let gw: ReturnType<typeof buildGateway>;
let ctl: ReturnType<typeof buildGatewayControl>;
let workspaceId: string;
let projectA: string;
let projectB: string;
let runA: string;
let runB: string;
let agentA: string;
let agentB: string;
let serverA: string;
let serverB: string;
let approvalA: string;
let approvalB: string;
let budgetA: string;
let budgetB: string;
let auditA1: string;
let auditA2: string;
let auditB: string;
let tokenA: string;
let humanApproverToken: string;
let humanAdminToken: string;
const originalEnv = { ...process.env };
const dir = mkdtempSync(join(tmpdir(), "tg-isolation-"));
const kid = `isolation-${tag}`;
const ed = generateKeyPairSync("ed25519");
const jwksFile = join(dir, "jwks.json");

function mint(projectId: string, scope: string, subject = `agent-${tag}`): string {
  const header = b64({ alg: "EdDSA", typ: "JWT", kid });
  const payload = b64({
    iss: ISSUER,
    aud: AUDIENCE,
    resource: AUDIENCE,
    sub: subject,
    exp: Math.floor(Date.now() / 1000) + 300,
    scope,
    projects: [projectId],
    workspaces: [workspaceId]
  });
  const signature = cryptoSign(null, Buffer.from(`${header}.${payload}`), ed.privateKey)
    .toString("base64url");
  return `${header}.${payload}.${signature}`;
}

const bearer = (token: string) => ({ authorization: `Bearer ${token}` });
const ids = (items: Array<{ id: string }>) => items.map((item) => item.id);

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
  ctl = buildGatewayControl();

  const ws = await api.inject({
    method: "POST", url: "/v1/workspaces", headers: API_KEY,
    payload: { name: `isolation-${tag}` }
  });
  expect(ws.statusCode).toBe(201);
  workspaceId = ws.json().id;

  const project = async (name: string) => {
    const res = await api.inject({
      method: "POST", url: "/v1/projects", headers: API_KEY,
      payload: { workspace_id: workspaceId, name }
    });
    expect(res.statusCode).toBe(201);
    return res.json().id as string;
  };
  projectA = await project("alpha");
  projectB = await project("beta");

  agentA = randomUUID();
  agentB = randomUUID();
  await pool.query(
    "INSERT INTO agents (id, workspace_id, name) VALUES ($1,$2,$3), ($4,$2,$5)",
    [agentA, workspaceId, `agent-alpha-${tag}`, agentB, `agent-beta-${tag}`]
  );

  runA = randomUUID();
  runB = randomUUID();
  await pool.query(
    `INSERT INTO runs (id, workspace_id, project_id, agent_id, status, started_at)
     VALUES ($1,$2,$3,$4,'success',now()), ($5,$2,$6,$7,'success',now())`,
    [runA, workspaceId, projectA, agentA, runB, projectB, agentB]
  );

  for (const [runId, marker] of [
    [runA, "alpha"],
    [runB, "beta"]
  ]) {
    await pool.query(
      `INSERT INTO spans (id, run_id, event_id, operation_type, name, started_at, status,
                          provider, model, input_tokens, output_tokens, usage_source)
       VALUES ($1,$2,$3,'model.request',$4,now(),'success','openai','gpt-4o',10,5,'provider_reported')`,
      [randomUUID(), runId, `iso-span-${marker}-${tag}`, `span-${marker}`]
    );
  }

  serverA = randomUUID();
  serverB = randomUUID();
  await pool.query(
    `INSERT INTO mcp_servers (id, workspace_id, project_id, name, gateway_alias, base_url)
     VALUES ($1,$2,$3,$4,$5,'https://example.test/mcp'),
            ($6,$2,$7,$8,$9,'https://example.test/mcp')`,
    [serverA, workspaceId, projectA, `alpha-${tag}`, `alpha_${tag}`,
     serverB, projectB, `beta-${tag}`, `beta_${tag}`]
  );

  approvalA = randomUUID();
  approvalB = randomUUID();
  await pool.query(
    `INSERT INTO approvals (id, request_id, workspace_id, project_id, caller, server_id,
                            tool_name, args_hash, args, expires_at)
     VALUES ($1,$2,$3,$4,'caller-alpha',$5,'echo','hash-a','{}'::jsonb, now() + interval '15 minutes'),
            ($6,$7,$3,$8,'caller-beta',$9,'echo','hash-b','{}'::jsonb, now() + interval '15 minutes')`,
    [approvalA, `req-alpha-${tag}`, workspaceId, projectA, serverA,
     approvalB, `req-beta-${tag}`, projectB, serverB]
  );

  budgetA = randomUUID();
  budgetB = randomUUID();
  await pool.query(
    `INSERT INTO budgets (id, workspace_id, project_id, scope, ref_id, limit_micro)
     VALUES ($1,$2,$3,'project',$3,100000), ($4,$2,$5,'project',$5,100000)`,
    [budgetA, workspaceId, projectA, budgetB, projectB]
  );

  auditA1 = randomUUID();
  auditA2 = randomUUID();
  auditB = randomUUID();
  await pool.query(
    `INSERT INTO audit_events (id, timestamp, actor_type, action, resource_type, result,
                               workspace_id, project_id)
     VALUES ($1, now() - interval '2 seconds', 'system', 'isolation.fixture', 'test', 'success', $4, $5),
            ($2, now() - interval '1 second', 'system', 'isolation.fixture', 'test', 'success', $4, $5),
            ($3, now(), 'system', 'isolation.fixture', 'test', 'success', $4, $6)`,
    [auditA1, auditA2, auditB, workspaceId, projectA, projectB]
  );

  const principal = await api.inject({
    method: "POST", url: `/v1/projects/${projectA}/agent-principals`, headers: API_KEY,
    payload: {
      issuer: ISSUER,
      subject: `agent-${tag}`,
      display_name: "isolation reader",
      allowed_scopes: ["read"]
    }
  });
  expect(principal.statusCode).toBe(201);

  tokenA = mint(projectA, "read");
  humanApproverToken = mint(projectA, "read approve", `human-approver-${tag}`);
  humanAdminToken = mint(projectA, "read admin", `human-admin-${tag}`);
});

afterAll(async () => {
  await api?.close();
  await gw?.close();
  await ctl?.close();
  await pool.end();
  for (const key of ["OAUTH_ISSUER", "OAUTH_AUDIENCE", "OAUTH_JWKS_FILE", "OAUTH_JWKS_URL"]) {
    if (originalEnv[key] === undefined) delete process.env[key];
    else process.env[key] = originalEnv[key];
  }
  rmSync(dir, { recursive: true, force: true });
});

describe("project isolation for a project-pinned agent", () => {
  it("scopes run lists, counts, overview, agents, and run detail", async () => {
    const token = bearer(tokenA);

    const runs = await api.inject({ method: "GET", url: "/v1/runs", headers: token });
    expect(runs.statusCode).toBe(200);
    expect(ids(runs.json().items)).toEqual([runA]);

    const counts = await api.inject({ method: "GET", url: "/v1/runs/counts", headers: token });
    expect(counts.statusCode).toBe(200);
    expect(counts.json().total).toBe(1);
    expect(counts.json().counts.success).toBe(1);

    const overview = await api.inject({ method: "GET", url: "/v1/overview", headers: token });
    expect(overview.statusCode).toBe(200);
    expect(overview.json().runs.total).toBe(1);
    expect(overview.json().pending_approvals).toBe(1);

    const agents = await api.inject({ method: "GET", url: "/v1/agents", headers: token });
    expect(agents.statusCode).toBe(200);
    expect(ids(agents.json().items)).toEqual([agentA]);

    for (const suffix of ["", "/trace", "/spans", "/diagnostics", "/usage"]) {
      const own = await api.inject({
        method: "GET", url: `/v1/runs/${runA}${suffix}`, headers: token
      });
      expect(own.statusCode, suffix).toBe(200);
      const foreign = await api.inject({
        method: "GET", url: `/v1/runs/${runB}${suffix}`, headers: token
      });
      expect(foreign.statusCode, suffix).toBe(404);
    }
  });

  it("scopes the approval queue, decisions, audit events, and budgets", async () => {
    const token = bearer(tokenA);

    const approvals = await api.inject({
      method: "GET", url: "/v1/approvals", headers: token
    });
    expect(approvals.statusCode).toBe(200);
    expect(ids(approvals.json().items)).toEqual([approvalA]);

    const decisions = await gw.inject({
      method: "GET", url: "/v1/decisions", headers: token
    });
    expect(decisions.statusCode).toBe(200);
    expect(decisions.json().items).toEqual([]);

    const auditToken = bearer(humanAdminToken);
    const firstAudit = await gw.inject({
      method: "GET", url: "/v1/audit-events?action=isolation.fixture&limit=1", headers: auditToken
    });
    expect(firstAudit.statusCode).toBe(200);
    expect(ids(firstAudit.json().items)).toEqual([auditA2]);
    expect(firstAudit.json().next_cursor).toBeTruthy();
    const secondAudit = await gw.inject({
      method: "GET",
      url: `/v1/audit-events?action=isolation.fixture&limit=1&cursor=${encodeURIComponent(firstAudit.json().next_cursor)}`,
      headers: auditToken
    });
    expect(secondAudit.statusCode).toBe(200);
    expect(ids(secondAudit.json().items)).toEqual([auditA1]);
    expect(secondAudit.json().next_cursor).toBeNull();

    const budgets = await api.inject({
      method: "GET", url: "/v1/budgets", headers: token
    });
    expect(budgets.statusCode).toBe(200);
    expect(ids(budgets.json().items)).toEqual([budgetA]);

    const tools = await api.inject({
      method: "GET", url: `/v1/mcp-servers/${serverA}/tools`, headers: token
    });
    expect(tools.statusCode).toBe(200);
    const foreignTools = await api.inject({
      method: "GET", url: `/v1/mcp-servers/${serverB}/tools`, headers: token
    });
    expect(foreignTools.statusCode).toBe(404);

    // Retention is workspace-scoped, so even a project-pinned admin cannot
    // reach it. Agent principals now lack admin entirely, so use the human
    // admin token to exercise the workspace-scope check rather than the
    // generic scope denial.
    const retention = await api.inject({
      method: "GET", url: "/v1/retention/rules", headers: bearer(humanAdminToken)
    });
    expect(retention.statusCode).toBe(403);
    expect(retention.json().error).toBe("retention_requires_workspace_scope");
  });

  it("rejects agent principals from the control listener", async () => {
    const token = bearer(tokenA);
    for (const [method, url, payload] of [
      ["GET", "/_control/v1/approvals", undefined],
      ["GET", `/_control/v1/approvals/${approvalA}`, undefined],
      ["POST", `/_control/v1/approvals/${approvalA}/decision`, { approved: true }]
    ] as const) {
      const res = await ctl.inject({ method, url, headers: token, payload: payload as never });
      expect(res.statusCode, url).toBe(403);
      expect(res.json().error, url).toBe("agent_principal_forbidden");
    }
  });

  it("scopes the control approval queue, detail, and decision for a human approver", async () => {
    const token = bearer(humanApproverToken);

    const list = await ctl.inject({
      method: "GET", url: "/_control/v1/approvals", headers: token
    });
    expect(list.statusCode).toBe(200);
    expect(ids(list.json().items)).toEqual([approvalA]);

    const own = await ctl.inject({
      method: "GET", url: `/_control/v1/approvals/${approvalA}`, headers: token
    });
    expect(own.statusCode).toBe(200);
    const foreign = await ctl.inject({
      method: "GET", url: `/_control/v1/approvals/${approvalB}`, headers: token
    });
    expect(foreign.statusCode).toBe(404);

    const foreignDecision = await ctl.inject({
      method: "POST", url: `/_control/v1/approvals/${approvalB}/decision`, headers: token,
      payload: { approved: true, reason: "not mine" }
    });
    expect(foreignDecision.statusCode).toBe(404);

    const decision = await ctl.inject({
      method: "POST", url: `/_control/v1/approvals/${approvalA}/decision`, headers: token,
      payload: { approved: true, reason: "isolated approval" }
    });
    expect(decision.statusCode).toBe(200);
    expect(decision.json().status).toBe("approved");
  });
});
