import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { PoolClient } from "pg";
import { argConditionsSchema, hasPathWithin } from "@traceguard/schemas";
import { pool } from "./db.js";
import { audit } from "./audit.js";
import { scopeClause } from "./auth.js";
import { projectClause, resolveProject } from "./project-scope.js";
import { gatewayAlias } from "./mcp.js";
import {
  checkUpstreamUrlResolved, definitionHash, definitionIssue, discoverTools,
  pinnedDefinition
} from "./upstream.js";

async function defaultWorkspaceId(client: PoolClient): Promise<string> {
  const found = await client.query("SELECT id FROM workspaces WHERE name = 'default'");
  if (found.rows[0]) return found.rows[0].id;
  const created = await client.query("INSERT INTO workspaces (name) VALUES ('default') RETURNING id");
  return created.rows[0].id;
}

export function registerAdminRoutes(app: FastifyInstance): void {
  const serverSchema = z.object({
    name: z.string().min(1).max(128),
    base_url: z.string().url(),
    auth_secret: z.string().max(1024).nullable().optional(),
    project_id: z.string().uuid().optional()
  });

  app.post("/v1/servers", async (req, reply) => {
    const parsed = serverSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_server" });
    const urlCheck = await checkUpstreamUrlResolved(parsed.data.base_url);
    if (!urlCheck.ok) {
      // Â§10.3: a refused destination is a security event, not just a 400.
      await audit(pool, { actor_type: "admin", action: "server.rejected",
        resource_type: "mcp_server", resource_id: parsed.data.name, result: "rejected",
        metadata: { reason: urlCheck.reason } });
      return reply.code(400).send({ error: "unsafe_upstream", reason: urlCheck.reason });
    }
    const client = await pool.connect();
    try {
      const workspaceId = await defaultWorkspaceId(client);
      const projectContext = await resolveProject(client, req.principal, {
        workspaceId, projectId: parsed.data.project_id ?? null
      });
      if (!projectContext) return reply.code(403).send({ error: "project_forbidden" });
      // The stable alias namespaces every exposed tool (Â§7.5) and is part of
      // the signed server manifest once bundles land.
      const alias = gatewayAlias(parsed.data.name);
      const res = await client.query(
        `INSERT INTO mcp_servers
           (workspace_id, project_id, name, gateway_alias, base_url, auth_secret)
         VALUES ($1,$2,$3,$4,$5,$6)
         RETURNING id, workspace_id, project_id, name, gateway_alias, base_url, created_at`,
        [workspaceId, projectContext.project.id, parsed.data.name, alias,
         parsed.data.base_url, parsed.data.auth_secret ?? null]
      );
      await audit(pool, { actor_type: "admin", action: "server.register",
        resource_type: "mcp_server", resource_id: res.rows[0].id,
        result: "success", workspace_id: res.rows[0].workspace_id,
        project_id: res.rows[0].project_id, metadata: { name: parsed.data.name } });
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
    const where: string[] = [];
    const scope = scopeClause(req.principal, params, "workspace_id");
    if (scope) where.push(scope);
    const pscope = projectClause(req.principal, params, "project_id");
    if (pscope) where.push(pscope);
    const res = await pool.query(
      `SELECT id, workspace_id, project_id, name, gateway_alias, base_url, created_at FROM mcp_servers
       ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY created_at DESC`, params
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
      // Re-validate at discover time: a name that resolved publicly at
      // registration must not quietly point at a private range now.
      const recheck = await checkUpstreamUrlResolved(server.base_url);
      if (!recheck.ok) {
        return reply.code(400).send({ error: "unsafe_upstream", reason: recheck.reason });
      }
      const tools = await discoverTools(server.base_url, server.auth_secret);
      const rejected: { name: string; reason: string }[] = [];
      const pinned: string[] = [];
      const changed: string[] = [];
      await client.query("BEGIN");
      for (const t of tools) {
        const issue = definitionIssue(t);
        if (issue) {
          // Â§7.5: an unsafe or oversized definition is never pinned. If one
          // was pinned before, quarantine it â€” the upstream no longer serves
          // what was reviewed, so the old pin must not stay callable.
          rejected.push({ name: t.name, reason: issue });
          const prior = await client.query(
            `UPDATE server_tools SET quarantined=true, quarantine_reason=$3, updated_at=now()
              WHERE server_id=$1 AND tool_name=$2 AND quarantined=false
              RETURNING tool_name`,
            [id, t.name, issue]
          );
          if (prior.rows[0]) {
            await audit(client, { actor_type: "system", action: "tool.quarantined",
              resource_type: "server_tool", resource_id: `${id}/${t.name}`,
              result: "quarantine", workspace_id: server.workspace_id,
              project_id: server.project_id, metadata: { reason: issue } });
          }
          await audit(client, { actor_type: "system", action: "tool.definition_rejected",
            resource_type: "server_tool", resource_id: `${id}/${t.name}`,
            result: "rejected", workspace_id: server.workspace_id,
            project_id: server.project_id, metadata: { reason: issue } });
          continue;
        }
        const hash = definitionHash(t);
        const definition = pinnedDefinition(t);
        const existing = await client.query(
          "SELECT definition_hash FROM server_tools WHERE server_id = $1 AND tool_name = $2",
          [id, t.name]
        );
        if (!existing.rows[0]) {
          await client.query(
            `INSERT INTO server_tools
               (server_id, tool_name, description, input_schema, definition, definition_hash)
             VALUES ($1,$2,$3,$4::jsonb,$5::jsonb,$6)`,
            [id, t.name, t.description ?? "", JSON.stringify(t.inputSchema), JSON.stringify(definition), hash]
          );
          pinned.push(t.name);
          await audit(client, { actor_type: "system", action: "tool.pinned",
            resource_type: "server_tool", resource_id: `${id}/${t.name}`,
            result: "success", workspace_id: server.workspace_id,
            project_id: server.project_id, metadata: { definition_hash: hash } });
        } else if (existing.rows[0].definition_hash !== hash) {
          // Upstream changed the tool definition: quarantine until reviewed.
          // The old definition is kept so the UI can show the field-level
          // diff; re-approval records a new version instead of rewriting it.
          await client.query(
            `UPDATE server_tools SET description=$3, input_schema=$4::jsonb,
               previous_definition=CASE WHEN quarantined THEN previous_definition ELSE definition END,
          previous_hash=CASE WHEN quarantined THEN previous_hash ELSE definition_hash END,
               definition=$5::jsonb, definition_hash=$6, definition_version=definition_version+1,
               quarantined=true, quarantine_reason='definition changed', updated_at=now()
             WHERE server_id=$1 AND tool_name=$2`,
            [id, t.name, t.description ?? "", JSON.stringify(t.inputSchema),
             JSON.stringify(definition), hash]
          );
          changed.push(t.name);
          await audit(client, { actor_type: "system", action: "tool.definition_changed",
            resource_type: "server_tool", resource_id: `${id}/${t.name}`,
            result: "quarantine", workspace_id: server.workspace_id,
            project_id: server.project_id,
            metadata: { previous_hash: existing.rows[0].definition_hash, definition_hash: hash } });
          await audit(client, { actor_type: "system", action: "tool.quarantined",
            resource_type: "server_tool", resource_id: `${id}/${t.name}`,
            result: "quarantine", workspace_id: server.workspace_id,
            project_id: server.project_id, metadata: { reason: "definition changed" } });
        }
      }
      await client.query("COMMIT");
      const listed = await client.query(
        `SELECT server_id, tool_name, description, input_schema, definition, previous_definition,
                definition_hash, previous_hash, definition_version, quarantined, quarantine_reason, updated_at
           FROM server_tools WHERE server_id = $1 ORDER BY tool_name`,
        [id]
      );
      await audit(pool, { actor_type: "admin", action: "server.discover",
        resource_type: "mcp_server", resource_id: id, result: "success",
        workspace_id: server.workspace_id, project_id: server.project_id,
        metadata: { tool_count: tools.length, pinned, changed, rejected: rejected.map((r) => r.name) } });
      return { tools: listed.rows, pinned, changed, rejected };
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      // Never swallow the cause: the caller gets a stable code, the operator
      // gets the reason in the log.
      req.log.error({ err }, "tool discovery failed");
      return reply.code(502).send({ error: "upstream_unreachable" });
    } finally {
      client.release();
    }
  });

  app.put("/v1/servers/:sid/tools/:tool/quarantine", async (req, reply) => {
    const { sid, tool } = req.params as { sid: string; tool: string };
    const parsed = z.object({ quarantined: z.boolean() }).safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_body" });
    // Un-quarantining is the human review step: the definition is marked as
    // reviewed, but it still executes only once a signed bundle activates
    // its pin (run policy-publisher publish). Clearing the reason is what
    // tells the publisher this pin carries a current review.
    const res = await pool.query(
      `UPDATE server_tools SET quarantined=$3, quarantine_reason=$4, updated_at=now()
        WHERE server_id=$1 AND tool_name=$2
        RETURNING tool_name, quarantined, definition_version, definition_hash`,
      [sid, tool, parsed.data.quarantined, parsed.data.quarantined ? "quarantined by reviewer" : null]
    );
    if (!res.rows[0]) return reply.code(404).send({ error: "tool_not_found" });
    const scope = await pool.query(
      "SELECT workspace_id, project_id FROM mcp_servers WHERE id = $1", [sid]
    );
    await audit(pool, { actor_type: "admin", action: "tool.reapprove",
      resource_type: "server_tool", resource_id: `${sid}/${tool}`,
      result: "success", workspace_id: scope.rows[0]?.workspace_id ?? null,
      project_id: scope.rows[0]?.project_id ?? null,
      metadata: { quarantined: parsed.data.quarantined } });
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
    // The typed condition shape, not a free record: an unsupported pattern is
    // refused here rather than at bundle load (T8).
    conditions: argConditionsSchema.default({ required: [] }),
    project_id: z.string().uuid().optional()
  }).superRefine((rule, ctx) => {
    // FR-010: a path constraint needs a scoped target so the pinned executor
    // attestation can be checked at publish and at call time.
    if (hasPathWithin(rule.conditions) && (!rule.server_id || !rule.tool_name)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["conditions"],
        message: "path_within requires a server- and tool-scoped rule"
      });
    }
  });

  app.post("/v1/policies", async (req, reply) => {
    const parsed = policySchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_policy" });
    const client = await pool.connect();
    try {
      const workspaceId = await defaultWorkspaceId(client);
      const projectContext = await resolveProject(client, req.principal, {
        workspaceId, projectId: parsed.data.project_id ?? null
      });
      if (!projectContext) return reply.code(403).send({ error: "project_forbidden" });
      const p = parsed.data;
      const res = await client.query(
        `INSERT INTO policies
           (workspace_id, project_id, name, enabled, priority, agent_id, server_id, tool_name, effect, conditions)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb) RETURNING *`,
        [workspaceId, projectContext.project.id, p.name, p.enabled, p.priority,
         p.agent_id ?? null, p.server_id ?? null, p.tool_name ?? null, p.effect,
         JSON.stringify(p.conditions)]
      );
      await audit(pool, { actor_type: "admin", action: "policy.create",
        resource_type: "policy", resource_id: res.rows[0].id, result: "success",
        workspace_id: res.rows[0].workspace_id, project_id: res.rows[0].project_id,
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
    const pscope = projectClause(req.principal, params, "project_id");
    if (pscope) where.push(pscope);
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
      await client.query("BEGIN");
      // Locked so the "is this rule still live" check and the version insert
      // are one unit. Read outside the transaction, two concurrent updates
      // both find a live row and both insert a new version, leaving the rule
      // with two live heads and a version an operator believes was retired.
      const old = await client.query("SELECT * FROM policies WHERE id = $1 FOR UPDATE", [id]);
      if (!old.rows[0]) {
        await client.query("ROLLBACK");
        return reply.code(404).send({ error: "policy_not_found" });
      }
      if (old.rows[0].superseded_by) {
        await client.query("ROLLBACK");
        return reply.code(409).send({ error: "policy_superseded" });
      }
      const p = parsed.data;
      const next = await client.query(
        `INSERT INTO policies
           (workspace_id, project_id, name, enabled, priority, agent_id, server_id, tool_name,
            effect, conditions, version, previous_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12) RETURNING *`,
        [old.rows[0].workspace_id, old.rows[0].project_id, p.name, p.enabled, p.priority,
         p.agent_id ?? null, p.server_id ?? null, p.tool_name ?? null, p.effect,
         JSON.stringify(p.conditions), old.rows[0].version + 1, id]
      );
      await client.query("UPDATE policies SET superseded_by = $2 WHERE id = $1",
        [id, next.rows[0].id]);
      await client.query("COMMIT");
      await audit(pool, { actor_type: "admin", action: "policy.update",
        resource_type: "policy", resource_id: next.rows[0].id, result: "success",
        workspace_id: next.rows[0].workspace_id, project_id: next.rows[0].project_id,
        metadata: { previous_id: id, version: next.rows[0].version } });
      return next.rows[0];
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  });
}
