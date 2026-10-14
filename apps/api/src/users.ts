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
                'scopes', k.scopes, 'expires_at', k.expires_at,
                'last_used_at', k.last_used_at)
                ORDER BY k.created_at) FILTER (WHERE k.id IS NOT NULL), '[]') AS keys
       FROM users u LEFT JOIN api_keys k ON k.user_id = u.id
       GROUP BY u.id ORDER BY u.created_at`);
    return { items: res.rows };
  });

  app.post("/v1/users/:id/keys", async (req, reply) => {
    const parsed = z.object({
      name: z.string().min(1).max(128),
      scopes: z.array(z.enum(["admin", "ingest", "gateway", "approve", "read"])).min(1),
      expires_days: z.number().int().min(1).max(365).default(90)
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
    const { plaintext, hash } = newKey();
    const expires = new Date(Date.now() + parsed.data.expires_days * 86400000);
    const created = await pool.query(
      `INSERT INTO api_keys (user_id, name, key_hash, scopes, expires_at)
       VALUES ($1, $2, $3, $4, $5) RETURNING id, name, scopes, expires_at, created_at`,
      [owner.rows[0].id, parsed.data.name, hash,
       JSON.stringify(scopes), expires.toISOString()]
    );
    await audit(pool, { actor_type: "user",
      actor_id: req.principal?.userId ?? undefined, action: "key.create",
      resource_type: "api_key", resource_id: created.rows[0].id,
      result: "success", metadata: { scopes } });
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
}
