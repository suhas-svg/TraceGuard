import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import type { PoolClient } from "pg";
import { argConditionsSchema, hasPathWithin } from "@traceguard/schemas";
import { pool } from "./db.js";
import { audit } from "./audit.js";
import { scopeClause, workspaceAllowed } from "./auth.js";
import { projectClause, resolveProject } from "./project-scope.js";
import { gatewayAlias } from "./mcp.js";
import {
  checkUpstreamUrlResolved, definitionHash, definitionIssue, discoverTools,
  pinnedDefinition
} from "./upstream.js";
import { resolveSecretRef, secretRefIssue } from "./secret-ref.js";

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
    // §7.3/§7.4: a reference only. The credential itself must never arrive
    // here, be stored in the database, or be returned by the API.
    secret_ref: z.string().max(512).nullable().optional(),
    project_id: z.string().uuid().optional()
  });

  app.post("/v1/servers", async (req, reply) => {
    const parsed = serverSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_server" });
    const refIssue = secretRefIssue(parsed.data.secret_ref);
    if (refIssue) {
      return reply.code(400).send({ error: "invalid_secret_ref", reason: refIssue });
    }
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
           (workspace_id, project_id, name, gateway_alias, base_url, secret_ref)
         VALUES ($1,$2,$3,$4,$5,$6)
         RETURNING id, workspace_id, project_id, name, gateway_alias, base_url, secret_ref, created_at`,
        [workspaceId, projectContext.project.id, parsed.data.name, alias,
         parsed.data.base_url, parsed.data.secret_ref ?? null]
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

  const listServers = async (req: FastifyRequest) => {
    // secret_ref names where the gateway can find the credential; the value
    // is not stored in this table and is never selected here.
    const params: unknown[] = [];
    const where: string[] = [];
    const scope = scopeClause(req.principal, params, "workspace_id");
    if (scope) where.push(scope);
    const pscope = projectClause(req.principal, params, "project_id");
    if (pscope) where.push(pscope);
    const res = await pool.query(
      `SELECT id, workspace_id, project_id, name, gateway_alias, base_url, secret_ref,
              disabled_at, created_at
         FROM mcp_servers
       ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY created_at DESC`, params
    );
    return { items: res.rows };
  };
  app.get("/v1/servers", listServers);
  app.get("/v1/mcp-servers", listServers);

  // §13.1: drafts are untrusted proposals. They cannot serve traffic and are
  // not part of the signed manifest; export hands the proposal to the operator
  // publication flow.
  app.post("/v1/mcp-server-drafts", async (req, reply) => {
    const parsed = serverSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_server_draft" });
    const refIssue = secretRefIssue(parsed.data.secret_ref);
    if (refIssue) {
      return reply.code(400).send({ error: "invalid_secret_ref", reason: refIssue });
    }
    const urlCheck = await checkUpstreamUrlResolved(parsed.data.base_url);
    if (!urlCheck.ok) {
      return reply.code(400).send({ error: "unsafe_upstream", reason: urlCheck.reason });
    }
    const client = await pool.connect();
    try {
      const workspaceId = await defaultWorkspaceId(client);
      const projectContext = await resolveProject(client, req.principal, {
        workspaceId, projectId: parsed.data.project_id ?? null
      });
      if (!projectContext) return reply.code(403).send({ error: "project_forbidden" });
      const res = await client.query(
        `INSERT INTO mcp_server_drafts
           (workspace_id, project_id, name, base_url, gateway_alias, secret_ref, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
        [workspaceId, projectContext.project.id, parsed.data.name, parsed.data.base_url,
         gatewayAlias(parsed.data.name), parsed.data.secret_ref ?? null,
         req.principal?.userId ?? null]
      );
      await audit(pool, { actor_type: "admin", action: "mcp_server.draft_created",
        resource_type: "mcp_server_draft", resource_id: res.rows[0].id, result: "success",
        workspace_id: res.rows[0].workspace_id, project_id: res.rows[0].project_id,
        metadata: { name: parsed.data.name } });
      return reply.code(201).send(res.rows[0]);
    } finally {
      client.release();
    }
  });

  app.get("/v1/mcp-server-drafts", async (req) => {
    const params: unknown[] = [];
    const where: string[] = [];
    const scope = scopeClause(req.principal, params, "workspace_id");
    if (scope) where.push(scope);
    const pscope = projectClause(req.principal, params, "project_id");
    if (pscope) where.push(pscope);
    const res = await pool.query(
      `SELECT * FROM mcp_server_drafts
       ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY created_at DESC`, params
    );
    return { items: res.rows };
  });

  app.post("/v1/mcp-server-drafts/:id/export", async (req, reply) => {
    const { id } = req.params as { id: string };
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const found = await client.query(
        "SELECT * FROM mcp_server_drafts WHERE id = $1 FOR UPDATE", [id]
      );
      if (!found.rows[0] || !workspaceAllowed(req.principal, found.rows[0].workspace_id)) {
        await client.query("ROLLBACK");
        return reply.code(404).send({ error: "server_draft_not_found" });
      }
      const updated = await client.query(
        `UPDATE mcp_server_drafts SET status='exported', exported_at=now(), updated_at=now()
          WHERE id=$1 RETURNING *`, [id]
      );
      await audit(client, { actor_type: "admin", actor_id: req.principal?.userId ?? undefined,
        action: "mcp_server.draft_exported", resource_type: "mcp_server_draft",
        resource_id: id, result: "success", workspace_id: found.rows[0].workspace_id,
        project_id: found.rows[0].project_id });
      await client.query("COMMIT");
      // Export is an unsigned handoff. The operator reviews and publishes it;
      // this response is not trusted configuration.
      return { draft: updated.rows[0], exported_at: updated.rows[0].exported_at };
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  });

  const discoverServer = async (req: FastifyRequest, reply: FastifyReply) => {
    const { id } = req.params as { id: string };
    const client = await pool.connect();
    try {
      const srv = await client.query("SELECT * FROM mcp_servers WHERE id = $1", [id]);
      if (!srv.rows[0] || !workspaceAllowed(req.principal, srv.rows[0].workspace_id)) {
        return reply.code(404).send({ error: "server_not_found" });
      }
      const server = srv.rows[0];
      if (server.disabled_at) {
        return reply.code(409).send({ error: "server_disabled" });
      }
      // Re-validate at discover time: a name that resolved publicly at
      // registration must not quietly point at a private range now.
      const recheck = await checkUpstreamUrlResolved(server.base_url);
      if (!recheck.ok) {
        return reply.code(400).send({ error: "unsafe_upstream", reason: recheck.reason });
      }
      // Discovery also talks to the upstream, so it uses the same reference
      // resolution as a tool call and fails closed when the credential is
      // unavailable. B1 keeps this read in the API for the existing admin
      // route; the value is never persisted or returned.
      let authSecret: string | null;
      try {
        authSecret = resolveSecretRef(server.secret_ref);
      } catch (err) {
        req.log.error({ err }, "upstream secret reference unavailable");
        return reply.code(503).send({ error: "secret_unavailable" });
      }
      const tools = await discoverTools(server.base_url, authSecret);
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
          const current = await client.query(
            "SELECT quarantined, candidate_pin_id FROM server_tools WHERE server_id = $1 AND tool_name = $2",
            [id, t.name]
          );
          if (current.rows[0]?.candidate_pin_id) {
            await client.query(
              `UPDATE tool_pins SET status = 'superseded'
                WHERE id = $1 AND status IN ('candidate', 'pending_review', 'approved')`,
              [current.rows[0].candidate_pin_id]
            );
          }
          await client.query(
            `UPDATE server_tools SET quarantined=true, quarantine_reason=$3,
               candidate_pin_id=NULL, updated_at=now()
              WHERE server_id=$1 AND tool_name=$2`,
            [id, t.name, issue]
          );
          if (current.rows[0] && !current.rows[0].quarantined) {
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
          `SELECT st.definition_hash, st.active_pin_id, st.candidate_pin_id,
                  cp.definition_hash AS candidate_hash
             FROM server_tools st
             LEFT JOIN tool_pins cp ON cp.id = st.candidate_pin_id
            WHERE st.server_id = $1 AND st.tool_name = $2`,
          [id, t.name]
        );
        if (!existing.rows[0]) {
          await client.query(
            `INSERT INTO server_tools
               (server_id, tool_name, description, input_schema, definition, definition_hash)
             VALUES ($1,$2,$3,$4::jsonb,$5::jsonb,$6)`,
            [id, t.name, t.description ?? "", JSON.stringify(t.inputSchema), JSON.stringify(definition), hash]
          );
          const pin = await client.query(
            `INSERT INTO tool_pins
               (server_id, tool_name, version, definition, definition_hash, status)
             VALUES ($1,$2,1,$3::jsonb,$4,'active')
             RETURNING id, version`,
            [id, t.name, JSON.stringify(definition), hash]
          );
          await client.query(
            "UPDATE server_tools SET active_pin_id = $3 WHERE server_id = $1 AND tool_name = $2",
            [id, t.name, pin.rows[0].id]
          );
          pinned.push(t.name);
          await audit(client, { actor_type: "system", action: "tool.pinned",
            resource_type: "server_tool", resource_id: `${id}/${t.name}`,
            result: "success", workspace_id: server.workspace_id,
            project_id: server.project_id,
            metadata: { definition_hash: hash, pin_id: pin.rows[0].id, pin_version: pin.rows[0].version } });
        } else if (existing.rows[0].definition_hash !== hash) {
          // Upstream changed the tool definition: create a new immutable
          // candidate. The active definition and its signed pin stay untouched
          // until an admin approves the candidate and the publisher activates
          // it in a new signed bundle.
          //
          // Re-running discovery while the same changed definition is still
          // present must not replace the candidate. Otherwise a refresh after
          // "submit for review" would silently supersede the pending pin.
          if (existing.rows[0].candidate_pin_id
              && existing.rows[0].candidate_hash === hash) {
            continue;
          }
          if (existing.rows[0].candidate_pin_id) {
            await client.query(
              `UPDATE tool_pins SET status = 'superseded'
                WHERE id = $1 AND status IN ('candidate', 'pending_review', 'approved')`,
              [existing.rows[0].candidate_pin_id]
            );
          }
          const next = await client.query(
            `SELECT COALESCE(MAX(version), 0) + 1 AS version
               FROM tool_pins WHERE server_id = $1 AND tool_name = $2`,
            [id, t.name]
          );
          const candidate = await client.query(
            `INSERT INTO tool_pins
               (server_id, tool_name, version, definition, definition_hash, status, quarantine_reason)
             VALUES ($1,$2,$3,$4::jsonb,$5,'candidate','definition changed')
             RETURNING id, version`,
            [id, t.name, next.rows[0].version, JSON.stringify(definition), hash]
          );
          await client.query(
            `UPDATE server_tools SET candidate_pin_id=$3, quarantined=true,
               quarantine_reason='definition changed', updated_at=now()
             WHERE server_id=$1 AND tool_name=$2`,
            [id, t.name, candidate.rows[0].id]
          );
          changed.push(t.name);
          await audit(client, { actor_type: "system", action: "tool.definition_changed",
            resource_type: "server_tool", resource_id: `${id}/${t.name}`,
            result: "quarantine", workspace_id: server.workspace_id,
            project_id: server.project_id,
            metadata: { previous_hash: existing.rows[0].definition_hash, definition_hash: hash,
              active_pin_id: existing.rows[0].active_pin_id,
              candidate_pin_id: candidate.rows[0].id, candidate_version: candidate.rows[0].version } });
          await audit(client, { actor_type: "system", action: "tool.quarantined",
            resource_type: "server_tool", resource_id: `${id}/${t.name}`,
            result: "quarantine", workspace_id: server.workspace_id,
            project_id: server.project_id,
            metadata: { reason: "definition changed", candidate_pin_id: candidate.rows[0].id } });
        } else if (existing.rows[0].candidate_pin_id) {
          // The upstream is back on the active definition, so an unreviewed
          // candidate is stale. Keep the quarantine in place until an admin
          // explicitly submits the active pin for a fresh review.
          await client.query(
            `UPDATE tool_pins SET status = 'superseded'
              WHERE id = $1 AND status IN ('candidate', 'pending_review', 'approved')`,
            [existing.rows[0].candidate_pin_id]
          );
          await client.query(
            "UPDATE server_tools SET candidate_pin_id = NULL WHERE server_id = $1 AND tool_name = $2",
            [id, t.name]
          );
        }
      }
      await client.query("COMMIT");
      const listed = await client.query(
        `SELECT st.server_id, st.tool_name, st.description, st.input_schema, st.definition,
                st.previous_definition, st.definition_hash, st.previous_hash,
                st.definition_version, st.quarantined, st.quarantine_reason, st.updated_at,
                st.active_pin_id, ap.version AS active_pin_version,
                st.candidate_pin_id, cp.version AS candidate_pin_version,
                cp.definition AS candidate_definition,
                cp.definition_hash AS candidate_definition_hash,
                cp.status AS candidate_status,
                cp.quarantine_reason AS candidate_reason
           FROM server_tools st
           LEFT JOIN tool_pins ap ON ap.id = st.active_pin_id
           LEFT JOIN tool_pins cp ON cp.id = st.candidate_pin_id
          WHERE st.server_id = $1 ORDER BY st.tool_name`,
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
  };
  app.post("/v1/servers/:id/discover", discoverServer);
  app.post("/v1/mcp-servers/:id/refresh-tools", discoverServer);

  app.get("/v1/mcp-servers/:id/tools", async (req, reply) => {
    const { id } = req.params as { id: string };
    const srv = await pool.query("SELECT * FROM mcp_servers WHERE id = $1", [id]);
    if (!srv.rows[0] || !workspaceAllowed(req.principal, srv.rows[0].workspace_id)) {
      return reply.code(404).send({ error: "server_not_found" });
    }
    const res = await pool.query(
      `SELECT st.tool_name, st.description, st.input_schema, st.quarantined,
              st.quarantine_reason, st.definition_version, st.definition_hash,
              st.active_pin_id, st.candidate_pin_id,
              ap.version AS active_pin_version, ap.status AS active_pin_status,
              cp.version AS candidate_pin_version, cp.status AS candidate_pin_status
         FROM server_tools st
         LEFT JOIN tool_pins ap ON ap.id = st.active_pin_id
         LEFT JOIN tool_pins cp ON cp.id = st.candidate_pin_id
        WHERE st.server_id = $1 ORDER BY st.tool_name`,
      [id]
    );
    return { items: res.rows };
  });

  app.post("/v1/mcp-servers/:id/disable", async (req, reply) => {
    const { id } = req.params as { id: string };
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const found = await client.query(
        "SELECT * FROM mcp_servers WHERE id = $1 FOR UPDATE", [id]
      );
      if (!found.rows[0] || !workspaceAllowed(req.principal, found.rows[0].workspace_id)) {
        await client.query("ROLLBACK");
        return reply.code(404).send({ error: "server_not_found" });
      }
      const server = found.rows[0];
      if (!server.disabled_at) {
        const updated = await client.query(
          `UPDATE mcp_servers SET disabled_at = now() WHERE id = $1
            RETURNING id, workspace_id, project_id, name, gateway_alias, base_url,
                      secret_ref, disabled_at, created_at`,
          [id]
        );
        await audit(client, { actor_type: "admin", actor_id: req.principal?.userId ?? undefined,
          action: "server.disabled", resource_type: "mcp_server", resource_id: id,
          result: "disabled", workspace_id: server.workspace_id,
          project_id: server.project_id, metadata: { name: server.name } });
        await client.query("COMMIT");
        return updated.rows[0];
      }
      await client.query("COMMIT");
      return found.rows[0];
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  });

  app.put("/v1/servers/:sid/tools/:tool/quarantine", async (req, reply) => {
    const { sid, tool } = req.params as { sid: string; tool: string };
    const parsed = z.object({ quarantined: z.boolean() }).safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_body" });
    // Clearing quarantine is not a review: a same-hash re-approval must create
    // a new pin version and a new signed bundle. Reviewers submit the pin and
    // approve it for publication instead.
    if (!parsed.data.quarantined) {
      return reply.code(409).send({ error: "review_required" });
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const current = await client.query(
        "SELECT candidate_pin_id FROM server_tools WHERE server_id = $1 AND tool_name = $2 FOR UPDATE",
        [sid, tool]
      );
      if (!current.rows[0]) {
        await client.query("ROLLBACK");
        return reply.code(404).send({ error: "tool_not_found" });
      }
      if (current.rows[0].candidate_pin_id) {
        await client.query(
          `UPDATE tool_pins SET status = 'superseded'
            WHERE id = $1 AND status IN ('candidate', 'pending_review', 'approved')`,
          [current.rows[0].candidate_pin_id]
        );
      }
      const res = await client.query(
        `UPDATE server_tools SET quarantined=true, quarantine_reason='quarantined by reviewer',
           candidate_pin_id=NULL, updated_at=now()
          WHERE server_id=$1 AND tool_name=$2
          RETURNING tool_name, quarantined, definition_version, definition_hash,
                    active_pin_id, candidate_pin_id`,
        [sid, tool]
      );
      const scope = await client.query(
        "SELECT workspace_id, project_id FROM mcp_servers WHERE id = $1", [sid]
      );
      await audit(client, { actor_type: "admin", actor_id: req.principal?.userId ?? undefined,
        action: "tool.quarantined", resource_type: "server_tool", resource_id: `${sid}/${tool}`,
        result: "success", workspace_id: scope.rows[0]?.workspace_id ?? null,
        project_id: scope.rows[0]?.project_id ?? null,
        metadata: { quarantined: true, reason: "quarantined by reviewer" } });
      await client.query("COMMIT");
      return res.rows[0];
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  });

  app.post("/v1/tool-pins/:id/submit-review", async (req, reply) => {
    const parsedId = z.string().uuid().safeParse((req.params as { id: string }).id);
    if (!parsedId.success) return reply.code(400).send({ error: "invalid_pin" });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const found = await client.query(
        `SELECT p.*, s.workspace_id, s.project_id,
                st.active_pin_id AS current_active_pin_id,
                st.candidate_pin_id AS current_candidate_pin_id
           FROM tool_pins p
           JOIN mcp_servers s ON s.id = p.server_id
           LEFT JOIN server_tools st ON st.server_id = p.server_id AND st.tool_name = p.tool_name
          WHERE p.id = $1
          FOR UPDATE OF p`,
        [parsedId.data]
      );
      if (!found.rows[0]) {
        await client.query("ROLLBACK");
        return reply.code(404).send({ error: "pin_not_found" });
      }
      const pin = found.rows[0];
      if (!workspaceAllowed(req.principal, pin.workspace_id)) {
        await client.query("ROLLBACK");
        return reply.code(403).send({ error: "workspace_forbidden" });
      }
      if (pin.status === "approved" || pin.status === "superseded") {
        await client.query("ROLLBACK");
        return reply.code(409).send({ error: "pin_not_reviewable" });
      }
      if ((pin.status === "candidate" || pin.status === "pending_review")
          && pin.current_candidate_pin_id !== pin.id) {
        await client.query("ROLLBACK");
        return reply.code(409).send({ error: "pin_not_current" });
      }
      await client.query(
        "SELECT 1 FROM server_tools WHERE server_id = $1 AND tool_name = $2 FOR UPDATE",
        [pin.server_id, pin.tool_name]
      );
      let candidateId = pin.id;
      let candidateVersion = pin.version;
      let candidateStatus = pin.status;
      if (pin.status === "active") {
        await client.query(
          "SELECT pg_advisory_xact_lock(hashtext($1))",
          [`tool-pin:${pin.server_id}:${pin.tool_name}`]
        );
        if (pin.current_candidate_pin_id) {
          await client.query(
            `UPDATE tool_pins SET status = 'superseded'
              WHERE id = $1 AND status IN ('candidate', 'pending_review', 'approved')`,
            [pin.current_candidate_pin_id]
          );
        }
        const next = await client.query(
          `SELECT COALESCE(MAX(version), 0) + 1 AS version
             FROM tool_pins WHERE server_id = $1 AND tool_name = $2`,
          [pin.server_id, pin.tool_name]
        );
        const candidate = await client.query(
          `INSERT INTO tool_pins
             (server_id, tool_name, version, definition, definition_hash, status, quarantine_reason)
           VALUES ($1,$2,$3,$4::jsonb,$5,'pending_review','review requested')
           RETURNING id, version, status`,
          [pin.server_id, pin.tool_name, next.rows[0].version, JSON.stringify(pin.definition),
           pin.definition_hash]
        );
        candidateId = candidate.rows[0].id;
        candidateVersion = candidate.rows[0].version;
        candidateStatus = candidate.rows[0].status;
      } else if (pin.status === "candidate") {
        const updated = await client.query(
          `UPDATE tool_pins SET status='pending_review', quarantine_reason='review requested'
            WHERE id=$1 RETURNING id, version, status`,
          [pin.id]
        );
        candidateStatus = updated.rows[0].status;
      }
      await client.query(
        `UPDATE server_tools SET candidate_pin_id=$3, quarantined=true,
           quarantine_reason='review requested', updated_at=now()
          WHERE server_id=$1 AND tool_name=$2`,
        [pin.server_id, pin.tool_name, candidateId]
      );
      await audit(client, { actor_type: "admin", actor_id: req.principal?.userId ?? undefined,
        action: "tool_pin.submitted", resource_type: "tool_pin", resource_id: candidateId,
        result: "pending_review", workspace_id: pin.workspace_id, project_id: pin.project_id,
        metadata: { pin_id: candidateId, pin_version: candidateVersion, status: candidateStatus } });
      await client.query("COMMIT");
      return { id: candidateId, server_id: pin.server_id, tool_name: pin.tool_name,
        version: candidateVersion, status: candidateStatus, definition_hash: pin.definition_hash };
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  });

  app.post("/v1/tool-pin-candidates/:id/approve-for-publication", async (req, reply) => {
    const parsedId = z.string().uuid().safeParse((req.params as { id: string }).id);
    if (!parsedId.success) return reply.code(400).send({ error: "invalid_pin" });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const found = await client.query(
        `SELECT p.*, s.workspace_id, s.project_id, st.candidate_pin_id
           FROM tool_pins p
           JOIN mcp_servers s ON s.id = p.server_id
           LEFT JOIN server_tools st ON st.server_id = p.server_id AND st.tool_name = p.tool_name
          WHERE p.id = $1
          FOR UPDATE OF p`,
        [parsedId.data]
      );
      if (!found.rows[0]) {
        await client.query("ROLLBACK");
        return reply.code(404).send({ error: "pin_not_found" });
      }
      const pin = found.rows[0];
      if (!workspaceAllowed(req.principal, pin.workspace_id)) {
        await client.query("ROLLBACK");
        return reply.code(403).send({ error: "workspace_forbidden" });
      }
      if (pin.status !== "pending_review" || pin.candidate_pin_id !== pin.id) {
        await client.query("ROLLBACK");
        return reply.code(409).send({ error: "pin_not_pending_review" });
      }
      const reviewedBy = req.principal?.userId ?? "admin";
      const updated = await client.query(
        `UPDATE tool_pins SET status='approved', reviewed_at=now(), reviewed_by=$2
          WHERE id=$1 RETURNING id, server_id, tool_name, version, status, definition_hash,
                            reviewed_at, reviewed_by`,
        [pin.id, reviewedBy]
      );
      await audit(client, { actor_type: "admin", actor_id: req.principal?.userId ?? undefined,
        action: "tool.reapproved", resource_type: "tool_pin", resource_id: pin.id,
        result: "approved", workspace_id: pin.workspace_id, project_id: pin.project_id,
        metadata: { pin_id: pin.id, pin_version: pin.version,
          definition_hash: pin.definition_hash } });
      await client.query("COMMIT");
      return updated.rows[0];
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
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

  const createPolicy = async (req: FastifyRequest, reply: FastifyReply) => {
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
      await audit(pool, { actor_type: "admin", action: "policy.draft_created",
        resource_type: "policy", resource_id: res.rows[0].id, result: "success",
        workspace_id: res.rows[0].workspace_id, project_id: res.rows[0].project_id,
        metadata: { name: p.name, effect: p.effect, version: 1 } });
      return reply.code(201).send(res.rows[0]);
    } finally {
      client.release();
    }
  };
  app.post("/v1/policies", createPolicy);
  app.post("/v1/policy-drafts", createPolicy);

  const listPolicies = async (req: FastifyRequest) => {
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
  };
  app.get("/v1/policies", listPolicies);
  app.get("/v1/policy-drafts", listPolicies);

  const updatePolicy = async (req: FastifyRequest, reply: FastifyReply) => {
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
      if (!old.rows[0] || !workspaceAllowed(req.principal, old.rows[0].workspace_id)) {
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
      await audit(pool, { actor_type: "admin", action: "policy.draft_updated",
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
  };
  app.put("/v1/policies/:id", updatePolicy);
  app.patch("/v1/policies/:id", updatePolicy);
  app.put("/v1/policy-drafts/:id", updatePolicy);
  app.patch("/v1/policy-drafts/:id", updatePolicy);

  app.get("/v1/policy-drafts/:id", async (req, reply) => {
    const { id } = req.params as { id: string };
    const res = await pool.query("SELECT * FROM policies WHERE id = $1", [id]);
    if (!res.rows[0] || !workspaceAllowed(req.principal, res.rows[0].workspace_id)) {
      return reply.code(404).send({ error: "policy_not_found" });
    }
    return res.rows[0];
  });

  app.post("/v1/policy-drafts/:id/export", async (req, reply) => {
    const { id } = req.params as { id: string };
    const res = await pool.query("SELECT * FROM policies WHERE id = $1", [id]);
    if (!res.rows[0] || !workspaceAllowed(req.principal, res.rows[0].workspace_id)) {
      return reply.code(404).send({ error: "policy_not_found" });
    }
    const draft = res.rows[0];
    // Unsigned handoff only. The publisher re-reads the live draft and signs
    // the assembled bundle; this response is never trusted configuration.
    return {
      draft,
      exported_at: new Date().toISOString(),
      export_format: "traceguard.policy-draft.v1"
    };
  });

  // §14: provenance is a read-only projection of the gateway's decisions.
  // Control-plane readers get the same rows the gateway records.
  app.get("/v1/policy-decisions", async (req) => {
    const q = req.query as { server_id?: string; tool?: string; limit?: string;
      run_id?: string; span_id?: string; request_id?: string };
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
    if (q.run_id) {
      params.push(q.run_id);
      where.push(`run_id = $${params.length}`);
    }
    if (q.span_id) {
      params.push(q.span_id);
      where.push(`span_id = $${params.length}`);
    }
    if (q.request_id) {
      params.push(q.request_id);
      where.push(`request_id = $${params.length}`);
    }
    const scope = scopeClause(req.principal, params, "workspace_id");
    if (scope) where.push(scope);
    params.push(limit);
    const res = await pool.query(
      `SELECT * FROM policy_decisions ${where.length ? "WHERE " + where.join(" AND ") : ""}
       ORDER BY timestamp DESC LIMIT $${params.length}`, params
    );
    return { items: res.rows };
  });
}
