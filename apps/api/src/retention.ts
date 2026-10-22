import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { Pool, PoolClient } from "pg";
import { pool, retentionPool } from "./db.js";
import { audit } from "./audit.js";

// Retention deletes execution and operational data past its age. It never
// touches policies, decisions, approvals, the audit log, or money.
// Like the stale-run finalizer, an operator cron calls the run endpoint;
// the app holds no scheduler.
const targets = ["runs", "webhook_deliveries", "spans"] as const;

async function defaultWorkspaceId(client: PoolClient): Promise<string> {
  const found = await client.query("SELECT id FROM workspaces WHERE name = 'default'");
  if (found.rows[0]) return found.rows[0].id;
  const created = await client.query("INSERT INTO workspaces (name) VALUES ('default') RETURNING id");
  return created.rows[0].id;
}

// §11.4: migration 026 seeded the default trace rule only for workspaces that
// already existed. Every workspace created from now on gets the same 7-day /
// 100,000-span rule at birth, so the retention default is real on a fresh
// install and not just on migrated ones.
export async function ensureDefaultSpanRetention(
  db: Pool | PoolClient,
  workspaceId: string
): Promise<void> {
  await db.query(
    `INSERT INTO retention_rules (workspace_id, name, target, older_than_days, max_rows, enabled)
     VALUES ($1, 'default-span-retention', 'spans', 7, 100000, true)
     ON CONFLICT (workspace_id, name) DO NOTHING`,
    [workspaceId]
  );
}

async function applyRule(
  client: PoolClient,
  rule: {
    id: string;
    workspace_id: string;
    target: string;
    older_than_days: number;
    max_rows?: number | string | null;
  }
): Promise<number> {
  const cutoff = `now() - (${rule.older_than_days} || ' days')::interval`;
  switch (rule.target) {
    case "runs": {
      // Spans go with their runs through the foreign-key cascade.
      const r = await client.query(
        `DELETE FROM runs WHERE workspace_id = $1 AND started_at < ${cutoff}`, [rule.workspace_id]
      );
      return r.rowCount ?? 0;
    }
    case "webhook_deliveries": {
      const r = await client.query(
        `DELETE FROM webhook_deliveries d USING webhook_subscriptions s
         WHERE d.subscription_id = s.id AND s.workspace_id = $1 AND d.created_at < ${cutoff}`,
        [rule.workspace_id]
      );
      return r.rowCount ?? 0;
    }
    case "spans": {
      // Traces leave whole: a run and its spans go together so no graph ever
      // dangles. The age cutoff runs first (§11.4), then the optional row cap
      // takes oldest runs until the workspace fits under it. Both stay far
      // from approvals, decisions, and the audit log.
      const aged = await client.query(
        `DELETE FROM runs WHERE workspace_id = $1 AND started_at < ${cutoff}`, [rule.workspace_id]
      );
      let deleted = aged.rowCount ?? 0;
      const maxRows = rule.max_rows == null ? null : Number(rule.max_rows);
      if (maxRows !== null && Number.isFinite(maxRows) && maxRows > 0) {
        // Bounded sweep: a run usually owns several spans, so a thousand
        // deletions clears a workspace far past the spec's 100k default; a
        // still-over-cap workspace is finished on the next scheduled run.
        for (let i = 0; i < 1000; i++) {
          const counts = await client.query(
            `SELECT count(*)::bigint AS n FROM spans s
             JOIN runs r ON r.id = s.run_id WHERE r.workspace_id = $1`,
            [rule.workspace_id]
          );
          if (BigInt(String(counts.rows[0].n)) <= BigInt(maxRows)) break;
          const oldest = await client.query(
            `SELECT r.id FROM runs r WHERE r.workspace_id = $1
               AND EXISTS (SELECT 1 FROM spans s WHERE s.run_id = r.id)
             ORDER BY r.started_at ASC, r.id ASC LIMIT 1`,
            [rule.workspace_id]
          );
          if (!oldest.rows[0]) break;
          await client.query("DELETE FROM runs WHERE id = $1", [oldest.rows[0].id]);
          deleted++;
        }
      }
      return deleted;
    }
    default:
      return 0;
  }
}

export function registerRetentionRoutes(app: FastifyInstance) {
  const ruleSchema = z.object({
    name: z.string().min(1).max(128),
    target: z.enum(targets),
    older_than_days: z.number().int().min(1).max(3650),
    max_rows: z.number().int().min(1).max(1_000_000_000).nullable().optional(),
    enabled: z.boolean().default(true)
  });

  app.post("/v1/retention/rules", async (req, reply) => {
    const parsed = ruleSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_rule" });
    const client = await pool.connect();
    try {
      const workspaceId = await defaultWorkspaceId(client);
      const r = parsed.data;
      try {
        const res = await client.query(
          `INSERT INTO retention_rules (workspace_id, name, target, older_than_days, max_rows, enabled)
           VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
          [workspaceId, r.name, r.target, r.older_than_days, r.max_rows ?? null, r.enabled]
        );
        await audit(pool, { actor_type: "admin", action: "retention.rule_create",
          resource_type: "retention_rule", resource_id: res.rows[0].id, result: "success",
          metadata: { name: r.name, target: r.target, older_than_days: r.older_than_days,
            max_rows: r.max_rows ?? null } });
        return reply.code(201).send(res.rows[0]);
      } catch (err: unknown) {
        if ((err as { code?: string }).code === "23505") {
          return reply.code(409).send({ error: "rule_name_taken" });
        }
        throw err;
      }
    } finally {
      client.release();
    }
  });

  app.get("/v1/retention/rules", async () => {
    const res = await pool.query("SELECT * FROM retention_rules ORDER BY created_at DESC");
    return { items: res.rows };
  });

  app.put("/v1/retention/rules/:id", async (req, reply) => {
    const { id } = req.params as { id: string };
    const parsed = z.object({
      older_than_days: z.number().int().min(1).max(3650).optional(),
      max_rows: z.number().int().min(1).max(1_000_000_000).nullable().optional(),
      enabled: z.boolean().optional()
    }).safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_rule" });
    const sets: string[] = [];
    const params: unknown[] = [];
    if (parsed.data.older_than_days !== undefined) {
      params.push(parsed.data.older_than_days);
      sets.push(`older_than_days = $${params.length}`);
    }
    if (parsed.data.max_rows !== undefined) {
      params.push(parsed.data.max_rows);
      sets.push(`max_rows = $${params.length}`);
    }
    if (parsed.data.enabled !== undefined) {
      params.push(parsed.data.enabled);
      sets.push(`enabled = $${params.length}`);
    }
    if (!sets.length) return reply.code(400).send({ error: "nothing_to_update" });
    params.push(id);
    const res = await pool.query(
      `UPDATE retention_rules SET ${sets.join(", ")} WHERE id = $${params.length} RETURNING *`, params
    );
    if (!res.rows[0]) return reply.code(404).send({ error: "rule_not_found" });
    return res.rows[0];
  });

  app.delete("/v1/retention/rules/:id", async (req, reply) => {
    const { id } = req.params as { id: string };
    const res = await pool.query("DELETE FROM retention_rules WHERE id = $1 RETURNING id", [id]);
    if (!res.rows[0]) return reply.code(404).send({ error: "rule_not_found" });
    await audit(pool, { actor_type: "admin", action: "retention.rule_delete",
      resource_type: "retention_rule", resource_id: id, result: "success" });
    return { ok: true };
  });

  app.post("/v1/retention/run", async () => {
    const client = await pool.connect();
    try {
      const rules = await client.query(
        "SELECT * FROM retention_rules WHERE enabled = true ORDER BY created_at"
      );
      const run = await client.query(
        "INSERT INTO retention_runs (workspace_id, status) VALUES ($1, 'running') RETURNING id",
        [rules.rows[0]?.workspace_id ?? (await defaultWorkspaceId(client))]
      );
      const counts: Record<string, number> = {};
      // The deletes run on the sweep connection: with DATABASE_URL_RETENTION
      // set, that is the retention_job role, which is the only role granted
      // to prune terminal approvals (§13.4).
      const sweep = await (retentionPool ?? pool).connect();
      try {
        await sweep.query("BEGIN");
        try {
          for (const rule of rules.rows) {
            counts[rule.name] = await applyRule(sweep, rule);
          }
          await sweep.query("COMMIT");
        } catch (err) {
          await sweep.query("ROLLBACK").catch(() => undefined);
          throw err;
        }
      } catch (err) {
        await pool.query("UPDATE retention_runs SET status = 'failed', ended_at = now() WHERE id = $1",
          [run.rows[0].id]);
        throw err;
      } finally {
        sweep.release();
      }
      await pool.query(
        "UPDATE retention_runs SET status = 'success', ended_at = now(), deleted_counts = $2 WHERE id = $1",
        [run.rows[0].id, JSON.stringify(counts)]
      );
      await audit(pool, { actor_type: "admin", action: "retention.run",
        resource_type: "retention_run", resource_id: run.rows[0].id, result: "success",
        metadata: { deleted: counts } });
      return { run_id: run.rows[0].id, deleted: counts };
    } finally {
      client.release();
    }
  });

  app.get("/v1/retention/runs", async (req) => {
    const q = req.query as { limit?: string };
    const limit = Math.min(Math.max(Number(q.limit ?? 20), 1), 100);
    const res = await pool.query("SELECT * FROM retention_runs ORDER BY started_at DESC LIMIT $1", [limit]);
    return { items: res.rows };
  });
}
