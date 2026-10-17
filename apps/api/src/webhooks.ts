import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { PoolClient } from "pg";
import { pool } from "./db.js";
import { audit } from "./audit.js";
import { redeliver } from "./notify.js";

async function defaultWorkspaceId(client: PoolClient): Promise<string> {
  const found = await client.query("SELECT id FROM workspaces WHERE name = 'default'");
  if (found.rows[0]) return found.rows[0].id;
  const created = await client.query("INSERT INTO workspaces (name) VALUES ('default') RETURNING id");
  return created.rows[0].id;
}

export function registerWebhookRoutes(app: FastifyInstance) {
  const subSchema = z.object({
    name: z.string().min(1).max(128),
    url: z.string().url().max(512),
    // Required, not optional: an empty secret used to sign with a publicly
    // known key, so the signature header implied an authenticity that did not
    // exist. Unsigned delivery is still possible for legacy rows, and it now
    // sends no header at all.
    secret: z.string().min(1).max(512),
    events: z.array(z.enum(["tool.denied", "approval.requested", "approval.decided", "budget.exceeded", "eval.completed", "*"])).min(1),
    enabled: z.boolean().default(true)
  });

  app.post("/v1/webhooks", async (req, reply) => {
    const parsed = subSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_webhook" });
    if (!parsed.data.url.startsWith("http://") && !parsed.data.url.startsWith("https://")) {
      return reply.code(400).send({ error: "http_only" });
    }
    const client = await pool.connect();
    try {
      const workspaceId = await defaultWorkspaceId(client);
      const s = parsed.data;
      try {
        const res = await client.query(
          `INSERT INTO webhook_subscriptions (workspace_id, name, url, secret, events, enabled)
           VALUES ($1,$2,$3,$4,$5::jsonb,$6) RETURNING id, workspace_id, name, url, events, enabled, created_at`,
          [workspaceId, s.name, s.url, s.secret, JSON.stringify(s.events), s.enabled]
        );
        await audit(pool, { actor_type: "admin", action: "webhook.create",
          resource_type: "webhook", resource_id: res.rows[0].id, result: "success",
          metadata: { name: s.name, events: s.events } });
        return reply.code(201).send(res.rows[0]);
      } catch (err: unknown) {
        if ((err as { code?: string }).code === "23505") {
          return reply.code(409).send({ error: "webhook_name_taken" });
        }
        throw err;
      }
    } finally {
      client.release();
    }
  });

  app.get("/v1/webhooks", async () => {
    // Secrets never leave: the list omits them, rotation is delete plus add.
    const res = await pool.query(
      "SELECT id, workspace_id, name, url, events, enabled, created_at FROM webhook_subscriptions ORDER BY created_at DESC"
    );
    return { items: res.rows };
  });

  app.delete("/v1/webhooks/:id", async (req, reply) => {
    const { id } = req.params as { id: string };
    const res = await pool.query("DELETE FROM webhook_subscriptions WHERE id = $1 RETURNING id", [id]);
    if (!res.rows[0]) return reply.code(404).send({ error: "webhook_not_found" });
    await audit(pool, { actor_type: "admin", action: "webhook.delete",
      resource_type: "webhook", resource_id: id, result: "success" });
    return { ok: true };
  });

  app.get("/v1/webhooks/deliveries", async (req) => {
    const q = req.query as { status?: string; limit?: string };
    const limit = Math.min(Math.max(Number(q.limit ?? 50), 1), 200);
    const params: unknown[] = [];
    const where: string[] = [];
    if (q.status) {
      params.push(q.status);
      where.push(`d.status = $${params.length}`);
    }
    params.push(limit);
    const res = await pool.query(
      `SELECT d.id, d.subscription_id, s.name AS subscription, d.event_type,
              d.status, d.attempts, d.last_error, d.created_at
       FROM webhook_deliveries d JOIN webhook_subscriptions s ON s.id = d.subscription_id
       ${where.length ? "WHERE " + where.join(" AND ") : ""}
       ORDER BY d.created_at DESC LIMIT $${params.length}`, params
    );
    return { items: res.rows };
  });

  app.post("/v1/webhooks/deliveries/:id/retry", async (req, reply) => {
    const { id } = req.params as { id: string };
    try {
      const out = await redeliver(id);
      return out;
    } catch {
      return reply.code(404).send({ error: "delivery_not_found" });
    }
  });
}
