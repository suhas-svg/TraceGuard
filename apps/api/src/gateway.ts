import Fastify from "fastify";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { PoolClient } from "pg";
import { pool } from "./db.js";
import { audit } from "./audit.js";
import {
  evaluate,
  requestHash,
  sha256Hex,
  stableStringify,
  type PolicyRule
} from "./policy.js";
import { callUpstreamTool, checkUpstreamUrl, definitionHash, discoverTools } from "./upstream.js";
import { hashesEqual, parseKey, seal, tryOpen } from "./seal.js";
import { authHook, scopeClause, workspaceAllowed } from "./auth.js";
import { notify } from "./notify.js";

const API_KEY = process.env.API_KEY ?? "";
const APPROVER_KEY = process.env.APPROVER_KEY ?? "";
const PORT = Number(process.env.GATEWAY_PORT ?? 8091);
const APPROVAL_TTL_SECONDS = Number(process.env.APPROVAL_TTL_SECONDS ?? 300);
// Same single-origin CORS as the API, for the policy screens.
const DASHBOARD_ORIGIN = process.env.DASHBOARD_ORIGIN ?? "http://localhost:5173";
if (!API_KEY) throw new Error("API_KEY is required");
if (!APPROVER_KEY) throw new Error("APPROVER_KEY is required");
// Pending approval arguments are sealed at rest. The gateway cannot start
// without the key, so there is no silent plaintext mode. Rotation sets the
// previous key alongside: old rows still open, new rows seal with primary.
const ARGS_KEY = parseKey(process.env.APPROVAL_ARGS_KEY ?? "");
const ARGS_KEYS = [
  ARGS_KEY,
  ...((process.env.APPROVAL_ARGS_KEY_PREVIOUS ?? "").trim()
    ? [parseKey(process.env.APPROVAL_ARGS_KEY_PREVIOUS ?? "")]
    : [])
];

// Reads one approval's arguments. New rows unseal with the request id as
// associated data; rows written before sealing stay readable as plaintext.
function storedArgs(row: {
  args_enc: boolean; args: unknown; request_id: string;
}): Record<string, unknown> {
  if (!row.args_enc) return row.args as Record<string, unknown>;
  const envelope = row.args as { sealed?: string };
  if (!envelope || typeof envelope.sealed !== "string") throw new Error("bad sealed envelope");
  return tryOpen(ARGS_KEYS, envelope.sealed, row.request_id);
}

async function defaultWorkspaceId(client: PoolClient): Promise<string> {
  const found = await client.query("SELECT id FROM workspaces WHERE name = 'default'");
  if (found.rows[0]) return found.rows[0].id;
  const created = await client.query("INSERT INTO workspaces (name) VALUES ('default') RETURNING id");
  return created.rows[0].id;
}

async function recordDecision(client: PoolClient, d: {
  workspace_id: string; caller: string; server_id: string | null; tool_name: string;
  args_hash: string; decision: string; policy_id?: string | null; policy_version?: number | null;
  matched?: unknown[]; reason?: string; approval_id?: string | null;
}): Promise<void> {
  await client.query(
    `INSERT INTO policy_decisions
       (workspace_id, caller, server_id, tool_name, args_hash, decision,
        policy_id, policy_version, matched_rules, reason, approval_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11)`,
    [d.workspace_id, d.caller, d.server_id, d.tool_name, d.args_hash, d.decision,
     d.policy_id ?? null, d.policy_version ?? null,
     JSON.stringify(d.matched ?? []), d.reason ?? "", d.approval_id ?? null]
  );
}

export function buildGateway() {
  const app = Fastify({ logger: true, genReqId: () => randomUUID() });

  app.get("/healthz", async () => ({ ok: true }));

  app.addHook("onRequest", async (req, reply) => {
    reply.header("Access-Control-Allow-Origin", DASHBOARD_ORIGIN);
    reply.header("Access-Control-Allow-Headers", "authorization, content-type");
    if (req.method === "OPTIONS") return reply.code(204).send();
    // One scoped-auth table for every route. Agent keys carry gateway scope
    // only, so they can never reach the approval decision endpoint no
    // matter how the call is framed; it needs approve scope.
    await authHook(req, reply);
  });

  const serverSchema = z.object({
    name: z.string().min(1).max(128),
    base_url: z.string().url(),
    auth_secret: z.string().max(1024).nullable().optional()
  });

  app.post("/v1/servers", async (req, reply) => {
    const parsed = serverSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_server" });
    const urlCheck = checkUpstreamUrl(parsed.data.base_url);
    if (!urlCheck.ok) return reply.code(400).send({ error: "unsafe_upstream", reason: urlCheck.reason });
    const client = await pool.connect();
    try {
      const workspaceId = await defaultWorkspaceId(client);
      const res = await client.query(
        `INSERT INTO mcp_servers (workspace_id, name, base_url, auth_secret)
         VALUES ($1,$2,$3,$4) RETURNING id, workspace_id, name, base_url, created_at`,
        [workspaceId, parsed.data.name, parsed.data.base_url, parsed.data.auth_secret ?? null]
      );
      await audit(pool, { actor_type: "admin", action: "server.register",
        resource_type: "mcp_server", resource_id: res.rows[0].id,
        result: "success", metadata: { name: parsed.data.name } });
      return reply.code(201).send(res.rows[0]);
    } catch (err: unknown) {
      if ((err as { code?: string }).code === "23505") {
        return reply.code(409).send({ error: "server_name_taken" });
      }
      throw err;
    } finally {
      client.release();
    }
  });

  app.get("/v1/servers", async (req) => {
    // auth_secret is never selected here, so reads cannot leak it.
    const params: unknown[] = [];
    const scope = scopeClause(req.principal, params, "workspace_id");
    const res = await pool.query(
      `SELECT id, workspace_id, name, base_url, created_at FROM mcp_servers
       ${scope ? `WHERE ${scope}` : ""} ORDER BY created_at DESC`, params
    );
    return { items: res.rows };
  });

  app.post("/v1/servers/:id/discover", async (req, reply) => {
    const { id } = req.params as { id: string };
    const client = await pool.connect();
    try {
      const srv = await client.query("SELECT * FROM mcp_servers WHERE id = $1", [id]);
      if (!srv.rows[0]) return reply.code(404).send({ error: "server_not_found" });
      const server = srv.rows[0];
      const tools = await discoverTools(server.base_url, server.auth_secret);
      await client.query("BEGIN");
      for (const t of tools) {
        const hash = definitionHash(t);
        const existing = await client.query(
          "SELECT definition_hash FROM server_tools WHERE server_id = $1 AND tool_name = $2",
          [id, t.name]
        );
        if (!existing.rows[0]) {
          await client.query(
            `INSERT INTO server_tools (server_id, tool_name, description, input_schema, definition_hash)
             VALUES ($1,$2,$3,$4::jsonb,$5)`,
            [id, t.name, t.description, JSON.stringify(t.inputSchema), hash]
          );
        } else if (existing.rows[0].definition_hash !== hash) {
          // Upstream changed the tool definition: quarantine until re-approved.
          await client.query(
            `UPDATE server_tools SET description=$3, input_schema=$4::jsonb,
               definition_hash=$5, quarantined=true, updated_at=now()
             WHERE server_id=$1 AND tool_name=$2`,
            [id, t.name, t.description, JSON.stringify(t.inputSchema), hash]
          );
        }
      }
      await client.query("COMMIT");
      const listed = await client.query(
        "SELECT server_id, tool_name, description, quarantined, updated_at FROM server_tools WHERE server_id = $1 ORDER BY tool_name",
        [id]
      );
      await audit(pool, { actor_type: "admin", action: "server.discover",
        resource_type: "mcp_server", resource_id: id, result: "success",
        metadata: { tool_count: tools.length } });
      return { tools: listed.rows };
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      return reply.code(502).send({ error: "upstream_unreachable" });
    } finally {
      client.release();
    }
  });

  app.put("/v1/servers/:sid/tools/:tool/quarantine", async (req, reply) => {
    const { sid, tool } = req.params as { sid: string; tool: string };
    const parsed = z.object({ quarantined: z.boolean() }).safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_body" });
    const res = await pool.query(
      "UPDATE server_tools SET quarantined=$3, updated_at=now() WHERE server_id=$1 AND tool_name=$2 RETURNING tool_name, quarantined",
      [sid, tool, parsed.data.quarantined]
    );
    if (!res.rows[0]) return reply.code(404).send({ error: "tool_not_found" });
    await audit(pool, { actor_type: "admin", action: "tool.reapprove",
      resource_type: "server_tool", resource_id: `${sid}/${tool}`,
      result: "success", metadata: { quarantined: parsed.data.quarantined } });
    return res.rows[0];
  });

  const policySchema = z.object({
    name: z.string().min(1).max(128),
    enabled: z.boolean().default(true),
    priority: z.number().int().default(0),
    agent_id: z.string().uuid().nullable().optional(),
    server_id: z.string().uuid().nullable().optional(),
    tool_name: z.string().max(128).nullable().optional(),
    effect: z.enum(["allow", "deny", "require_approval"]),
    conditions: z.record(z.unknown()).default({})
  });

  app.post("/v1/policies", async (req, reply) => {
    const parsed = policySchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_policy" });
    const client = await pool.connect();
    try {
      const workspaceId = await defaultWorkspaceId(client);
      const p = parsed.data;
      const res = await client.query(
        `INSERT INTO policies
           (workspace_id, name, enabled, priority, agent_id, server_id, tool_name, effect, conditions)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb) RETURNING *`,
        [workspaceId, p.name, p.enabled, p.priority, p.agent_id ?? null,
         p.server_id ?? null, p.tool_name ?? null, p.effect, JSON.stringify(p.conditions)]
      );
      await audit(pool, { actor_type: "admin", action: "policy.create",
        resource_type: "policy", resource_id: res.rows[0].id, result: "success",
        metadata: { name: p.name, effect: p.effect, version: 1 } });
      return reply.code(201).send(res.rows[0]);
    } finally {
      client.release();
    }
  });

  app.get("/v1/policies", async (req) => {
    const q = req.query as { server_id?: string; all?: string };
    const params: unknown[] = [];
    const where = ["superseded_by IS NULL"];
    if (q.server_id) {
      params.push(q.server_id);
      where.push(`server_id = $${params.length}`);
    }
    if (q.all === "true") where.shift();
    const scope = scopeClause(req.principal, params, "workspace_id");
    if (scope) where.push(scope);
    const res = await pool.query(
      `SELECT * FROM policies ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY priority DESC, created_at DESC`,
      params
    );
    return { items: res.rows };
  });

  app.put("/v1/policies/:id", async (req, reply) => {
    const { id } = req.params as { id: string };
    const parsed = policySchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_policy" });
    const client = await pool.connect();
    try {
      const old = await client.query("SELECT * FROM policies WHERE id = $1", [id]);
      if (!old.rows[0]) return reply.code(404).send({ error: "policy_not_found" });
      if (old.rows[0].superseded_by) return reply.code(409).send({ error: "policy_superseded" });
      await client.query("BEGIN");
      const p = parsed.data;
      const next = await client.query(
        `INSERT INTO policies
           (workspace_id, name, enabled, priority, agent_id, server_id, tool_name,
            effect, conditions, version, previous_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11) RETURNING *`,
        [old.rows[0].workspace_id, p.name, p.enabled, p.priority, p.agent_id ?? null,
         p.server_id ?? null, p.tool_name ?? null, p.effect,
         JSON.stringify(p.conditions), old.rows[0].version + 1, id]
      );
      await client.query("UPDATE policies SET superseded_by = $2 WHERE id = $1",
        [id, next.rows[0].id]);
      await client.query("COMMIT");
      await audit(pool, { actor_type: "admin", action: "policy.update",
        resource_type: "policy", resource_id: next.rows[0].id, result: "success",
        metadata: { previous_id: id, version: next.rows[0].version } });
      return next.rows[0];
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  });

  const callSchema = z.object({
    server_id: z.string().uuid(),
    tool: z.string().min(1).max(128),
    arguments: z.record(z.unknown()).default({}),
    agent_name: z.string().max(128).optional(),
    caller: z.string().max(128).optional(),
    request_id: z.string().max(128).optional(),
    approval_id: z.string().uuid().optional()
  });

  async function forward(
    client: PoolClient,
    server: { id: string; base_url: string; auth_secret: string | null; workspace_id: string },
    tool: string,
    args: Record<string, unknown>,
    caller: string,
    decisionMeta: { approval_id?: string | null; policy_id?: string | null; policy_version?: number | null; matched?: unknown[] }
  ): Promise<unknown> {
    // Gateway fails closed: any upstream or policy error denies, never allows.
    const result = await callUpstreamTool(server.base_url, server.auth_secret, tool, args);
    await recordDecision(client, {
      workspace_id: server.workspace_id, caller, server_id: server.id, tool_name: tool,
      args_hash: sha256Hex(stableStringify(args)), decision: decisionMeta.approval_id ? "approved_retry" : "allow",
      policy_id: decisionMeta.policy_id, policy_version: decisionMeta.policy_version,
      matched: decisionMeta.matched, reason: decisionMeta.approval_id ? "approved" : "allowed",
      approval_id: decisionMeta.approval_id ?? null
    });
    await audit(pool, { actor_type: "agent", actor_id: caller, action: "tool.execute",
      resource_type: "server_tool", resource_id: `${server.id}/${tool}`, result: "allowed" });
    return result;
  }

  app.post("/v1/gateway/tools/call", async (req, reply) => {
    const parsed = callSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_call" });
    const { server_id, tool, arguments: args } = parsed.data;
    const caller = parsed.data.caller ?? parsed.data.agent_name ?? "agent";
    const client = await pool.connect();
    try {
      const srv = await client.query("SELECT * FROM mcp_servers WHERE id = $1", [server_id]);
      if (!srv.rows[0]) {
        await audit(pool, { actor_type: "agent", actor_id: caller, action: "tool.execute",
          resource_type: "server_tool", resource_id: `${server_id}/${tool}`, result: "unknown_server" });
        return reply.code(404).send({ error: "server_not_found" });
      }
      const server = srv.rows[0];

      if (!workspaceAllowed(req.principal, server.workspace_id)) {
        return reply.code(403).send({ error: "workspace_forbidden", workspace_id: server.workspace_id });
      }

      const toolRow = await client.query(
        "SELECT * FROM server_tools WHERE server_id = $1 AND tool_name = $2", [server_id, tool]
      );
      if (!toolRow.rows[0] || toolRow.rows[0].quarantined) {
        await recordDecision(client, { workspace_id: server.workspace_id, caller,
          server_id, tool_name: tool, args_hash: sha256Hex(stableStringify(args)),
          decision: "deny", reason: toolRow.rows[0] ? "tool quarantined" : "unknown tool" });
        await audit(pool, { actor_type: "agent", actor_id: caller, action: "tool.execute",
          resource_type: "server_tool", resource_id: `${server_id}/${tool}`, result: "denied" });
        // Alerts never block the denial they report.
        void notify(server.workspace_id, "tool.denied",
          { caller, server_id, tool, reason: toolRow.rows[0] ? "quarantined" : "unknown" });
        return reply.code(403).send({ error: "tool_blocked", reason: "unknown or quarantined tool" });
      }

      // Approval retry: the client presents a prior approval for this exact call.
      if (parsed.data.approval_id) {
        const ap = await client.query("SELECT * FROM approvals WHERE id = $1", [parsed.data.approval_id]);
        if (!ap.rows[0]) return reply.code(404).send({ error: "approval_not_found" });
        const approval = ap.rows[0];
        if (approval.status === "consumed") {
          return reply.code(410).send({ error: "approval_consumed" });
        }
        if (approval.status !== "pending" && approval.status !== "approved") {
          return reply.code(403).send({ error: "approval_not_granted", status: approval.status });
        }
        if (new Date(approval.expires_at).getTime() < Date.now()) {
          await client.query("UPDATE approvals SET status='expired' WHERE id=$1", [approval.id]);
          await recordDecision(client, { workspace_id: server.workspace_id, caller,
            server_id, tool_name: tool, args_hash: sha256Hex(stableStringify(args)),
            decision: "deny", reason: "approval expired", approval_id: approval.id });
          return reply.code(410).send({ error: "approval_expired" });
        }
        const want = requestHash(caller, server_id, tool, args, approval.request_id);
        if (!hashesEqual(want, approval.args_hash) || approval.caller !== caller) {
          await recordDecision(client, { workspace_id: server.workspace_id, caller,
            server_id, tool_name: tool, args_hash: sha256Hex(stableStringify(args)),
            decision: "deny", reason: "approval binding mismatch", approval_id: approval.id });
          return reply.code(403).send({ error: "approval_binding_mismatch" });
        }
        if (approval.status === "pending") {
          return reply.code(202).send({ approval_id: approval.id, status: "pending",
            expires_at: approval.expires_at });
        }
        await client.query("UPDATE approvals SET status='consumed', decided_at=now() WHERE id=$1", [approval.id]);
        let stored: Record<string, unknown>;
        try {
          stored = storedArgs(approval);
        } catch {
          return reply.code(500).send({ error: "approval_unreadable" });
        }
        try {
          const result = await forward(client, server, tool, stored,
            caller, { approval_id: approval.id });
          return { result, approval_id: approval.id };
        } catch {
          return reply.code(502).send({ error: "upstream_failed" });
        }
      }

      const policyRows = await client.query(
        "SELECT * FROM policies WHERE workspace_id = $1 AND superseded_by IS NULL", [server.workspace_id]
      );
      const rules: PolicyRule[] = policyRows.rows.map((r) => ({
        id: r.id, version: r.version, name: r.name, enabled: r.enabled, priority: r.priority,
        agent_id: r.agent_id, server_id: r.server_id, tool_name: r.tool_name,
        effect: r.effect, conditions: (r.conditions ?? {}) as PolicyRule["conditions"]
      }));
      const verdict = evaluate(rules, {
        caller, agent_id: null, server_id, tool_name: tool, args: args as Record<string, unknown>
      });
      const argsHash = sha256Hex(stableStringify(args));

      if (verdict.decision === "deny") {
        await recordDecision(client, { workspace_id: server.workspace_id, caller, server_id,
          tool_name: tool, args_hash: argsHash, decision: "deny",
          policy_id: verdict.rule?.id ?? null, policy_version: verdict.rule?.version ?? null,
          matched: verdict.matched, reason: verdict.reason });
        await audit(pool, { actor_type: "agent", actor_id: caller, action: "tool.execute",
          resource_type: "server_tool", resource_id: `${server_id}/${tool}`, result: "denied",
          metadata: { rule: verdict.rule?.name ?? null } });
        void notify(server.workspace_id, "tool.denied",
          { caller, server_id, tool, rule: verdict.rule?.name ?? null, reason: verdict.reason });
        return reply.code(403).send({ error: "tool_blocked", reason: verdict.reason });
      }

      if (verdict.decision === "need_approval") {
        const requestId = parsed.data.request_id ?? `req-${randomUUID()}`;
        const hash = requestHash(caller, server_id, tool, args as Record<string, unknown>, requestId);
        const expiresAt = new Date(Date.now() + APPROVAL_TTL_SECONDS * 1000).toISOString();
        const sealed = seal(ARGS_KEY, args as Record<string, unknown>, requestId);
        const ap = await client.query(
          `INSERT INTO approvals
             (request_id, workspace_id, caller, server_id, tool_name, args_hash, args, args_enc, requested_by, expires_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10)
           ON CONFLICT (request_id) DO NOTHING RETURNING id, request_id, status, expires_at`,
          [requestId, server.workspace_id, caller, server_id, tool, hash,
           JSON.stringify({ sealed }), true, caller, expiresAt]
        );
        const row = ap.rows[0] ?? (await client.query("SELECT id, request_id, status, expires_at FROM approvals WHERE request_id=$1", [requestId])).rows[0];
        await recordDecision(client, { workspace_id: server.workspace_id, caller, server_id,
          tool_name: tool, args_hash: argsHash, decision: "need_approval",
          policy_id: verdict.rule?.id ?? null, policy_version: verdict.rule?.version ?? null,
          matched: verdict.matched, reason: verdict.reason, approval_id: row.id });
        await audit(pool, { actor_type: "agent", actor_id: caller, action: "approval.request",
          resource_type: "approval", resource_id: row.id, result: "pending" });
        void notify(server.workspace_id, "approval.requested",
          { approval_id: row.id, caller, server_id, tool });
        return reply.code(202).send({ approval_id: row.id, status: row.status, expires_at: row.expires_at });
      }

      try {
        const result = await forward(client, server, tool, args as Record<string, unknown>, caller,
          { policy_id: verdict.rule?.id ?? null, policy_version: verdict.rule?.version ?? null, matched: verdict.matched });
        return { result };
      } catch {
        return reply.code(502).send({ error: "upstream_failed" });
      }
    } finally {
      client.release();
    }
  });

  app.get("/v1/approvals", async (req) => {
    const q = req.query as { status?: string; limit?: string };
    const limit = Math.min(Math.max(Number(q.limit ?? 50), 1), 200);
    const params: unknown[] = [];
    const where: string[] = [];
    if (q.status) {
      params.push(q.status);
      where.push(`status = $${params.length}`);
    }
    // Approvers open plaintext here, so the list itself must already be
    // confined to their workspaces.
    const ascope = scopeClause(req.principal, params, "workspace_id");
    if (ascope) where.push(ascope);
    params.push(limit);
    const res = await pool.query(
      `SELECT * FROM approvals ${where.length ? "WHERE " + where.join(" AND ") : ""}
       ORDER BY requested_at DESC LIMIT $${params.length}`, params
    );
    // Approvers see plaintext; the seal opens here, inside the gateway.
    // A row that will not open is shown redacted, never dropped silently.
    const items = res.rows.map((row) => {
      if (!row.args_enc) return row;
      try {
        return { ...row, args: storedArgs(row) };
      } catch {
        return { ...row, args: {}, decrypt_error: true };
      }
    });
    return { items };
  });

  app.post("/v1/approvals/:id/decision", async (req, reply) => {
    const { id } = req.params as { id: string };
    const parsed = z.object({ approved: z.boolean(), reason: z.string().max(512).default("") }).safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_decision" });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const ap = await client.query("SELECT * FROM approvals WHERE id = $1", [id]);
      if (!ap.rows[0]) {
        await client.query("ROLLBACK");
        return reply.code(404).send({ error: "approval_not_found" });
      }
      const approval = ap.rows[0];
      if (approval.status !== "pending") {
        await client.query("ROLLBACK");
        return reply.code(409).send({ error: "approval_not_pending", status: approval.status });
      }
      // Approvals from other workspaces read as missing here too.
      if (!workspaceAllowed(req.principal, approval.workspace_id)) {
        await client.query("ROLLBACK");
        return reply.code(404).send({ error: "approval_not_found" });
      }
      if (new Date(approval.expires_at).getTime() < Date.now()) {
        await client.query("UPDATE approvals SET status='expired' WHERE id=$1", [id]);
        await client.query("COMMIT");
        return reply.code(410).send({ error: "approval_expired" });
      }
      // Single decision wins: only one row can leave pending state.
      const updated = await client.query(
        `UPDATE approvals SET status=$2, decided_by='approver', decided_at=now(), decision_reason=$3
         WHERE id=$1 AND status='pending' RETURNING *`,
        [id, parsed.data.approved ? "approved" : "denied", parsed.data.reason]
      );
      if (!updated.rows[0]) {
        await client.query("ROLLBACK");
        return reply.code(409).send({ error: "approval_decided_elsewhere" });
      }
      await client.query("COMMIT");
      await audit(pool, { actor_type: "approver", action: "approval.decide",
        resource_type: "approval", resource_id: id,
        result: parsed.data.approved ? "approved" : "denied",
        metadata: { reason: parsed.data.reason } });
      void notify(approval.workspace_id, "approval.decided",
        { approval_id: id, result: parsed.data.approved ? "approved" : "denied" });
      return updated.rows[0];
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  });

  app.get("/v1/decisions", async (req) => {
    const q = req.query as { server_id?: string; tool?: string; limit?: string };
    const limit = Math.min(Math.max(Number(q.limit ?? 50), 1), 200);
    const params: unknown[] = [];
    const where: string[] = [];
    if (q.server_id) {
      params.push(q.server_id);
      where.push(`server_id = $${params.length}`);
    }
    if (q.tool) {
      params.push(q.tool);
      where.push(`tool_name = $${params.length}`);
    }
    const dscope = scopeClause(req.principal, params, "workspace_id");
    if (dscope) where.push(dscope);
    params.push(limit);
    const res = await pool.query(
      `SELECT * FROM policy_decisions ${where.length ? "WHERE " + where.join(" AND ") : ""}
       ORDER BY timestamp DESC LIMIT $${params.length}`, params
    );
    return { items: res.rows };
  });

  app.get("/v1/audit-events", async (req) => {
    const q = req.query as { action?: string; limit?: string };
    const limit = Math.min(Math.max(Number(q.limit ?? 50), 1), 200);
    const params: unknown[] = [];
    const where: string[] = [];
    if (q.action) {
      params.push(q.action);
      where.push(`action = $${params.length}`);
    }
    params.push(limit);
    const res = await pool.query(
      `SELECT * FROM audit_events ${where.length ? "WHERE " + where.join(" AND ") : ""}
       ORDER BY timestamp DESC LIMIT $${params.length}`, params
    );
    return { items: res.rows };
  });

  return app;
}

const isMain = process.argv[1]?.endsWith("gateway.js") || process.argv[1]?.endsWith("gateway.ts");
if (isMain) {
  buildGateway().listen({ port: PORT, host: "0.0.0.0" });
}
