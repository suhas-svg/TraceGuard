import type { FastifyInstance, FastifyReply } from "fastify";
import { z } from "zod";
import { AGENT_PRINCIPAL_SCOPES, newIngestKey } from "./auth.js";
import type { Principal } from "./auth.js";
import { audit } from "./audit.js";
import { pool } from "./db.js";
import { projectAllowed, projectById, projectClause } from "./project-scope.js";
import { workspaceAllowed } from "./auth.js";

const UUID = z.string().guid();

function isAdmin(principal: Principal | undefined): boolean {
  return !!principal && (principal.projects === "all" || principal.scopes.includes("admin"));
}

function denyAdmin(reply: FastifyReply) {
  return reply.code(403).send({ error: "admin_required" });
}

function actor(principal: Principal | undefined): { actor_type: string; actor_id?: string } {
  if (principal?.userId) return { actor_type: "user", actor_id: principal.userId };
  return { actor_type: principal?.kind === "env" ? "system" : "user" };
}

export function registerProjectRoutes(app: FastifyInstance): void {
  app.get("/v1/projects", async (req) => {
    const params: unknown[] = [];
    const scope = projectClause(req.principal, params, "id");
    const res = await pool.query(
      `SELECT id, workspace_id, name, status, created_at FROM projects
       ${scope ? `WHERE ${scope}` : ""} ORDER BY workspace_id, name`, params
    );
    return { items: res.rows };
  });

  app.post("/v1/projects", async (req, reply) => {
    const parsed = z.object({
      name: z.string().min(1).max(128),
      workspace_id: UUID.optional()
    }).safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_project" });
    const workspaceId = parsed.data.workspace_id ?? (await (async () => {
      const found = await pool.query("SELECT id FROM workspaces WHERE name = 'default'");
      if (found.rows[0]) return found.rows[0].id as string;
      const created = await pool.query(
        "INSERT INTO workspaces (name) VALUES ('default') RETURNING id");
      return created.rows[0].id as string;
    })());
    if (!workspaceAllowed(req.principal, workspaceId)) {
      return reply.code(403).send({ error: "workspace_forbidden", workspace_id: workspaceId });
    }
    try {
      const created = await pool.query(
        `INSERT INTO projects (workspace_id, name) VALUES ($1, $2)
         RETURNING id, workspace_id, name, status, created_at`,
        [workspaceId, parsed.data.name]
      );
      await audit(pool, {
        ...actor(req.principal), action: "project.create", resource_type: "project",
        resource_id: created.rows[0].id, result: "success",
        workspace_id: workspaceId, project_id: created.rows[0].id,
        metadata: { name: parsed.data.name }
      });
      return reply.code(201).send(created.rows[0]);
    } catch (err) {
      if ((err as { code?: string }).code === "23505") {
        return reply.code(409).send({ error: "project_name_taken" });
      }
      throw err;
    }
  });

  app.get("/v1/projects/:id", async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!UUID.safeParse(id).success) return reply.code(400).send({ error: "invalid_project_id" });
    if (!projectAllowed(req.principal, id)) return reply.code(404).send({ error: "project_not_found" });
    const project = await projectById(pool, id);
    if (!project) return reply.code(404).send({ error: "project_not_found" });
    return project;
  });

  app.patch("/v1/projects/:id", async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!UUID.safeParse(id).success) return reply.code(400).send({ error: "invalid_project_id" });
    if (!projectAllowed(req.principal, id)) return reply.code(404).send({ error: "project_not_found" });
    const parsed = z.object({
      name: z.string().min(1).max(128).optional(),
      status: z.enum(["active", "archived"]).optional()
    }).refine((v) => v.name !== undefined || v.status !== undefined,
      { message: "nothing to update" }).safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_project" });
    try {
      const updated = await pool.query(
        `UPDATE projects SET name = COALESCE($2, name), status = COALESCE($3, status)
          WHERE id = $1 RETURNING id, workspace_id, name, status, created_at`,
        [id, parsed.data.name ?? null, parsed.data.status ?? null]
      );
      if (!updated.rows[0]) return reply.code(404).send({ error: "project_not_found" });
      await audit(pool, {
        ...actor(req.principal), action: "project.update", resource_type: "project",
        resource_id: id, result: "success",
        workspace_id: updated.rows[0].workspace_id, project_id: id,
        metadata: { name: parsed.data.name ?? null, status: parsed.data.status ?? null }
      });
      return updated.rows[0];
    } catch (err) {
      if ((err as { code?: string }).code === "23505") {
        return reply.code(409).send({ error: "project_name_taken" });
      }
      throw err;
    }
  });

  app.get("/v1/projects/:id/ingest-keys", async (req, reply) => {
    if (!isAdmin(req.principal)) return denyAdmin(reply);
    const { id } = req.params as { id: string };
    if (!UUID.safeParse(id).success) return reply.code(400).send({ error: "invalid_project_id" });
    if (!projectAllowed(req.principal, id)) return reply.code(404).send({ error: "project_not_found" });
    const res = await pool.query(
      `SELECT id, project_id, name, scopes, expires_at, revoked_at, last_used_at, created_at
         FROM ingest_api_keys WHERE project_id = $1 ORDER BY created_at DESC`, [id]
    );
    return { items: res.rows };
  });

  app.post("/v1/projects/:id/ingest-keys", async (req, reply) => {
    if (!isAdmin(req.principal)) return denyAdmin(reply);
    const { id } = req.params as { id: string };
    if (!UUID.safeParse(id).success) return reply.code(400).send({ error: "invalid_project_id" });
    if (!projectAllowed(req.principal, id)) return reply.code(404).send({ error: "project_not_found" });
    const parsed = z.object({
      name: z.string().min(1).max(128),
      expires_days: z.number().int().min(1).max(365).default(90)
    }).safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_ingest_key" });
    const project = await projectById(pool, id);
    if (!project) return reply.code(404).send({ error: "project_not_found" });
    const { plaintext, hash } = newIngestKey();
    const expires = new Date(Date.now() + parsed.data.expires_days * 86400000);
    const created = await pool.query(
      `INSERT INTO ingest_api_keys
         (project_id, name, key_hash, scopes, created_by_user_id, expires_at)
       VALUES ($1, $2, $3, '["ingest"]'::jsonb, $4, $5)
       RETURNING id, project_id, name, scopes, expires_at, revoked_at, created_at`,
      [id, parsed.data.name, hash, req.principal?.userId ?? null, expires.toISOString()]
    );
    await audit(pool, {
      ...actor(req.principal), action: "ingest_key.create", resource_type: "ingest_api_key",
      resource_id: created.rows[0].id, result: "success",
      workspace_id: project.workspace_id, project_id: id,
      metadata: { name: parsed.data.name }
    });
    // The plaintext leaves the server exactly once, here.
    return reply.code(201).send({ ...created.rows[0], key: plaintext });
  });

  app.post("/v1/ingest-keys/:id/revoke", async (req, reply) => {
    if (!isAdmin(req.principal)) return denyAdmin(reply);
    const { id } = req.params as { id: string };
    if (!UUID.safeParse(id).success) return reply.code(400).send({ error: "invalid_key_id" });
    const key = await pool.query(
      `SELECT k.project_id, p.workspace_id FROM ingest_api_keys k
         JOIN projects p ON p.id = k.project_id WHERE k.id = $1`, [id]
    );
    if (!key.rows[0] || !projectAllowed(req.principal, key.rows[0].project_id)) {
      return reply.code(404).send({ error: "ingest_key_not_found" });
    }
    const revoked = await pool.query(
      `UPDATE ingest_api_keys SET revoked_at = COALESCE(revoked_at, now())
        WHERE id = $1 RETURNING id, revoked_at`, [id]
    );
    await audit(pool, {
      ...actor(req.principal), action: "ingest_key.revoke", resource_type: "ingest_api_key",
      resource_id: id, result: "success",
      workspace_id: key.rows[0].workspace_id, project_id: key.rows[0].project_id
    });
    return { ok: true, revoked_at: revoked.rows[0].revoked_at };
  });

  app.get("/v1/projects/:id/agent-principals", async (req, reply) => {
    if (!isAdmin(req.principal)) return denyAdmin(reply);
    const { id } = req.params as { id: string };
    if (!UUID.safeParse(id).success) return reply.code(400).send({ error: "invalid_project_id" });
    if (!projectAllowed(req.principal, id)) return reply.code(404).send({ error: "project_not_found" });
    const res = await pool.query(
      `SELECT id, project_id, issuer, subject, display_name, allowed_scopes, status, created_at
         FROM agent_principals WHERE project_id = $1 ORDER BY created_at DESC`, [id]
    );
    return { items: res.rows };
  });

  app.post("/v1/projects/:id/agent-principals", async (req, reply) => {
    if (!isAdmin(req.principal)) return denyAdmin(reply);
    const { id } = req.params as { id: string };
    if (!UUID.safeParse(id).success) return reply.code(400).send({ error: "invalid_project_id" });
    if (!projectAllowed(req.principal, id)) return reply.code(404).send({ error: "project_not_found" });
    const parsed = z.object({
      issuer: z.string().url(),
      subject: z.string().min(1).max(512),
      display_name: z.string().max(128).default(""),
      allowed_scopes: z.array(z.enum(AGENT_PRINCIPAL_SCOPES as unknown as [string, ...string[]]))
        .default(["gateway", "read", "ingest"])
    }).safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_agent_principal" });
    try {
      const created = await pool.query(
        `INSERT INTO agent_principals
           (project_id, issuer, subject, display_name, allowed_scopes)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, project_id, issuer, subject, display_name, allowed_scopes, status, created_at`,
        [id, parsed.data.issuer, parsed.data.subject, parsed.data.display_name,
          JSON.stringify(parsed.data.allowed_scopes)]
      );
      const project = await projectById(pool, id);
      await audit(pool, {
        ...actor(req.principal), action: "agent_principal.create",
        resource_type: "agent_principal", resource_id: created.rows[0].id, result: "success",
        workspace_id: project?.workspace_id ?? null, project_id: id,
        metadata: { issuer: parsed.data.issuer, subject: parsed.data.subject }
      });
      return reply.code(201).send(created.rows[0]);
    } catch (err) {
      if ((err as { code?: string }).code === "23505") {
        return reply.code(409).send({ error: "agent_principal_exists" });
      }
      throw err;
    }
  });

  app.patch("/v1/agent-principals/:id", async (req, reply) => {
    if (!isAdmin(req.principal)) return denyAdmin(reply);
    const { id } = req.params as { id: string };
    if (!UUID.safeParse(id).success) return reply.code(400).send({ error: "invalid_principal_id" });
    const row = await pool.query(
      `SELECT a.project_id, p.workspace_id FROM agent_principals a
         JOIN projects p ON p.id = a.project_id WHERE a.id = $1`, [id]
    );
    if (!row.rows[0] || !projectAllowed(req.principal, row.rows[0].project_id)) {
      return reply.code(404).send({ error: "agent_principal_not_found" });
    }
    const parsed = z.object({
      display_name: z.string().max(128).optional(),
      status: z.enum(["active", "disabled"]).optional(),
      allowed_scopes: z.array(z.enum(AGENT_PRINCIPAL_SCOPES as unknown as [string, ...string[]])).optional()
    }).refine((v) => v.display_name !== undefined || v.status !== undefined ||
      v.allowed_scopes !== undefined, { message: "nothing to update" }).safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_agent_principal" });
    const updated = await pool.query(
      `UPDATE agent_principals
          SET display_name = COALESCE($2, display_name),
              status = COALESCE($3, status),
              allowed_scopes = COALESCE($4, allowed_scopes)
        WHERE id = $1
        RETURNING id, project_id, issuer, subject, display_name, allowed_scopes, status, created_at`,
      [id, parsed.data.display_name ?? null, parsed.data.status ?? null,
        parsed.data.allowed_scopes ? JSON.stringify(parsed.data.allowed_scopes) : null]
    );
    await audit(pool, {
      ...actor(req.principal), action: "agent_principal.update",
      resource_type: "agent_principal", resource_id: id, result: "success",
      workspace_id: row.rows[0].workspace_id, project_id: row.rows[0].project_id,
      metadata: { status: parsed.data.status ?? null }
    });
    return updated.rows[0];
  });

  // §14: effective identity and project scope from the trusted issuer.
  app.get("/v1/whoami", async (req, reply) => {
    const principal = req.principal;
    if (!principal) return reply.code(401).send({ error: "unauthorized" });
    let projectRows: unknown[] = [];
    if (principal.projects !== "all" && principal.projects.length > 0) {
      const res = await pool.query(
        `SELECT id, workspace_id, name, status FROM projects
          WHERE id = ANY($1::uuid[]) ORDER BY name`, [principal.projects]
      );
      projectRows = res.rows;
    }
    return {
      kind: principal.kind,
      user_id: principal.userId,
      agent_principal_id: principal.agentPrincipalId ?? null,
      issuer: principal.issuer ?? null,
      scopes: principal.scopes,
      workspaces: principal.workspaces,
      projects: principal.projects,
      project_details: projectRows
    };
  });
}
