import { createHash } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { pool } from "./db.js";
import { audit } from "./audit.js";
import { checkPassword, hashPassword, newKey, ROLE_SCOPES } from "./auth.js";

// User management. Registration stays open only until the first user
// exists; that account becomes admin and everything after needs one.
// Login mints a short-lived bearer key, not a session cookie, so the SDK,
// the dashboard, and scripts all authenticate the same way.
export function registerUserRoutes(app: FastifyInstance) {
  const creds = z.object({
    email: z.string().email().max(256),
    password: z.string().min(12).max(256)
  });

  app.post("/v1/auth/register", async (req, reply) => {
    const parsed = creds.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_credentials" });
    const count = await pool.query("SELECT COUNT(*) AS n FROM users");
    if (Number(count.rows[0].n) > 0) {
      return reply.code(403).send({ error: "registration_closed" });
    }
    const created = await pool.query(
      "INSERT INTO users (email, password_hash, role) VALUES ($1, $2, 'admin') RETURNING id, email, role",
      [parsed.data.email.toLowerCase(), hashPassword(parsed.data.password)]
    );
    await audit(pool, { actor_type: "system", action: "user.bootstrap",
      resource_type: "user", resource_id: created.rows[0].id, result: "success", metadata: {} });
    return reply.code(201).send(created.rows[0]);
  });

  app.post("/v1/auth/login", async (req, reply) => {
    const parsed = creds.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_credentials" });
    const found = await pool.query("SELECT id, password_hash, role FROM users WHERE email = $1",
      [parsed.data.email.toLowerCase()]);
    const user = found.rows[0];
    if (!user || !checkPassword(parsed.data.password, user.password_hash)) {
      return reply.code(401).send({ error: "bad_login" });
    }
    const { plaintext, hash } = newKey();
    const expires = new Date(Date.now() + 24 * 3600000);
    await pool.query(
      `INSERT INTO api_keys (user_id, name, key_hash, scopes, expires_at)
       VALUES ($1, 'login', $2, $3, $4)`,
      [user.id, hash, JSON.stringify(ROLE_SCOPES[user.role] ?? []), expires.toISOString()]
    );
    return { token: plaintext, expires_at: expires.toISOString(), role: user.role };
  });

  app.get("/v1/auth/me", async (req, reply) => {
    const p = req.principal;
    if (!p) return reply.code(401).send({ error: "unauthorized" });
    let email: string | null = null;
    let role: string | null = null;
    if (p.userId) {
      const row = await pool.query("SELECT email, role FROM users WHERE id = $1", [p.userId]);
      email = row.rows[0]?.email ?? null;
      role = row.rows[0]?.role ?? null;
    }
    return {
      kind: p.kind,
      user_id: p.userId ?? null,
      email,
      role,
      scopes: p.scopes,
      workspaces: p.workspaces
    };
  });

  // Login keys are revocable; env keys are not. Logout deletes the presented
  // login key row, so its bearer stops working everywhere at once.
  app.post("/v1/auth/logout", async (req, reply) => {
    const p = req.principal;
    if (!p) return reply.code(401).send({ error: "unauthorized" });
    if (p.kind !== "user") {
      return reply.code(400).send({ error: "env_key_not_revocable" });
    }
    const presented = (req.headers.authorization ?? "").replace(/^Bearer\s+/i, "");
    const keyHash = createHash("sha256").update(presented).digest("hex");
    const deleted = await pool.query("DELETE FROM api_keys WHERE key_hash = $1 RETURNING id", [keyHash]);
    await audit(pool, { actor_type: "user", actor_id: p.userId ?? undefined, action: "key.logout",
      resource_type: "api_key", resource_id: deleted.rows[0]?.id ?? "", result: "success", metadata: {} });
    return { ok: true, revoked: (deleted.rowCount ?? 0) > 0 };
  });

  app.post("/v1/users", async (req, reply) => {
    const parsed = creds.extend({ role: z.enum(["admin", "member", "approver"]).default("member") })
      .safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_user" });
    try {
      const created = await pool.query(
        "INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id, email, role, created_at",
        [parsed.data.email.toLowerCase(), hashPassword(parsed.data.password), parsed.data.role]
      );
      await audit(pool, { actor_type: "user",
        actor_id: req.principal?.userId ?? undefined, action: "user.create",
        resource_type: "user", resource_id: created.rows[0].id, result: "success", metadata: {} });
      return reply.code(201).send(created.rows[0]);
    } catch {
      return reply.code(409).send({ error: "email_taken" });
    }
  });

  app.get("/v1/users", async () => {
    const res = await pool.query(
      `SELECT u.id, u.email, u.role, u.created_at,
              COALESCE(json_agg(json_build_object('id', k.id, 'name', k.name,
                'scopes', k.scopes, 'workspace_id', k.workspace_id,
                'expires_at', k.expires_at, 'last_used_at', k.last_used_at)
                ORDER BY k.created_at) FILTER (WHERE k.id IS NOT NULL), '[]') AS keys,
              COALESCE((SELECT json_agg(workspace_id) FROM memberships m
                WHERE m.user_id = u.id), '[]') AS workspaces
       FROM users u LEFT JOIN api_keys k ON k.user_id = u.id
       GROUP BY u.id ORDER BY u.created_at`);
    return { items: res.rows };
  });

  app.post("/v1/users/:id/keys", async (req, reply) => {
    const parsed = z.object({
      name: z.string().min(1).max(128),
      scopes: z.array(z.enum(["admin", "ingest", "gateway", "approve", "read"])).min(1),
      expires_days: z.number().int().min(1).max(365).default(90),
      workspace_id: z.string().uuid().nullable().optional()
    }).safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_key" });
    const owner = await pool.query("SELECT id, role FROM users WHERE id = $1",
      [(req.params as { id: string }).id]);
    if (!owner.rows[0]) return reply.code(404).send({ error: "no_user" });
    const allowed = ROLE_SCOPES[owner.rows[0].role] ?? [];
    // A key can never exceed its owner's role, and only an admin principal
    // reaches this route, so privilege flows one way only.
    const scopes = parsed.data.scopes.filter((s) => allowed.includes(s));
    if (parsed.data.scopes.includes("admin") && !allowed.includes("admin")) {
      return reply.code(403).send({ error: "beyond_role" });
    }
    if (scopes.length === 0) return reply.code(400).send({ error: "no_allowed_scopes" });
    const pin: string | null = parsed.data.workspace_id ?? null;
    if (pin) {
      const ws = await pool.query("SELECT id FROM workspaces WHERE id = $1", [pin]);
      if (!ws.rows[0]) return reply.code(404).send({ error: "no_workspace" });
      if (owner.rows[0].role !== "admin") {
        const mem = await pool.query(
          "SELECT 1 FROM memberships WHERE user_id = $1 AND workspace_id = $2",
          [owner.rows[0].id, pin]);
        // Pinning outside the owner's memberships would mint a key that can
        // write nowhere, so refuse it loudly instead of silently.
        if (!mem.rows[0]) return reply.code(403).send({ error: "owner_not_member" });
      }
    }
    const { plaintext, hash } = newKey();
    const expires = new Date(Date.now() + parsed.data.expires_days * 86400000);
    const created = await pool.query(
      `INSERT INTO api_keys (user_id, name, key_hash, scopes, workspace_id, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, scopes, workspace_id, expires_at, created_at`,
      [owner.rows[0].id, parsed.data.name, hash,
       JSON.stringify(scopes), pin, expires.toISOString()]
    );
    await audit(pool, { actor_type: "user",
      actor_id: req.principal?.userId ?? undefined, action: "key.create",
      resource_type: "api_key", resource_id: created.rows[0].id,
      result: "success", metadata: { scopes, workspace_id: pin } });
    // The plaintext leaves the server exactly once, here.
    return reply.code(201).send({ ...created.rows[0], key: plaintext });
  });

  app.delete("/v1/users/:id/keys/:keyId", async (req, reply) => {
    const p = req.params as { id: string; keyId: string };
    const del = await pool.query("DELETE FROM api_keys WHERE id = $1 AND user_id = $2",
      [p.keyId, p.id]);
    if (del.rowCount === 0) return reply.code(404).send({ error: "no_key" });
    await audit(pool, { actor_type: "user",
      actor_id: req.principal?.userId ?? undefined, action: "key.revoke",
      resource_type: "api_key", resource_id: p.keyId, result: "success", metadata: {} });
    return { ok: true };
  });

  app.post("/v1/users/:id/memberships", async (req, reply) => {
    const parsed = z.object({ workspace_id: z.string().uuid() }).safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_membership" });
    const p = req.params as { id: string };
    const owner = await pool.query("SELECT id FROM users WHERE id = $1", [p.id]);
    if (!owner.rows[0]) return reply.code(404).send({ error: "no_user" });
    const ws = await pool.query("SELECT id FROM workspaces WHERE id = $1",
      [parsed.data.workspace_id]);
    if (!ws.rows[0]) return reply.code(404).send({ error: "no_workspace" });
    try {
      await pool.query("INSERT INTO memberships (user_id, workspace_id) VALUES ($1, $2)",
        [p.id, parsed.data.workspace_id]);
    } catch {
      return reply.code(409).send({ error: "already_member" });
    }
    await audit(pool, { actor_type: "user",
      actor_id: req.principal?.userId ?? undefined, action: "membership.grant",
      resource_type: "user", resource_id: p.id,
      result: "success", metadata: { workspace_id: parsed.data.workspace_id } });
    return reply.code(201).send({ ok: true });
  });

  app.delete("/v1/users/:id/memberships/:workspaceId", async (req, reply) => {
    const p = req.params as { id: string; workspaceId: string };
    const del = await pool.query(
      "DELETE FROM memberships WHERE user_id = $1 AND workspace_id = $2", [p.id, p.workspaceId]);
    if (del.rowCount === 0) return reply.code(404).send({ error: "no_membership" });
    await audit(pool, { actor_type: "user",
      actor_id: req.principal?.userId ?? undefined, action: "membership.revoke",
      resource_type: "user", resource_id: p.id,
      result: "success", metadata: { workspace_id: p.workspaceId } });
    return { ok: true };
  });

  app.get("/v1/workspaces", async (req) => {
    // Admins list everything; members list only their own.
    if (req.principal?.workspaces === "all") {
      const all = await pool.query("SELECT id, name, created_at FROM workspaces ORDER BY name");
      return { items: all.rows };
    }
    const own = await pool.query(
      "SELECT w.id, w.name, w.created_at FROM workspaces w JOIN memberships m ON m.workspace_id = w.id WHERE m.user_id = $1 ORDER BY w.name",
      [req.principal?.userId ?? null]);
    return { items: own.rows };
  });

  app.post("/v1/workspaces", async (req, reply) => {
    const parsed = z.object({ name: z.string().min(1).max(128) }).safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_workspace" });
    try {
      const created = await pool.query(
        "INSERT INTO workspaces (name) VALUES ($1) RETURNING id, name, created_at",
        [parsed.data.name]);
      await audit(pool, { actor_type: "user",
        actor_id: req.principal?.userId ?? undefined, action: "workspace.create",
        resource_type: "workspace", resource_id: created.rows[0].id,
        result: "success", metadata: {} });
      return reply.code(201).send(created.rows[0]);
    } catch {
      return reply.code(409).send({ error: "workspace_taken" });
    }
  });
}
