import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { PoolClient } from "pg";
import { pool } from "./db.js";
import { audit } from "./audit.js";
import { workspaceAllowed } from "./auth.js";
import { notify } from "./notify.js";

async function defaultWorkspaceId(client: PoolClient): Promise<string> {
  const found = await client.query("SELECT id FROM workspaces WHERE name = 'default'");
  if (found.rows[0]) return found.rows[0].id;
  const created = await client.query("INSERT INTO workspaces (name) VALUES ('default') RETURNING id");
  return created.rows[0].id;
}

export function registerBudgetRoutes(app: FastifyInstance) {
  const pricingSchema = z.object({
    provider: z.string().min(1).max(64),
    model: z.string().min(1).max(128),
    input_price_per_million: z.number().int().min(0),
    output_price_per_million: z.number().int().min(0),
    cached_input_price_per_million: z.number().int().min(0).default(0),
    currency: z.string().max(8).default("USD")
  });

  // New prices append a version; old rows stay so past estimates keep meaning.
  app.post("/v1/pricing", async (req, reply) => {
    const parsed = pricingSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_pricing" });
    const p = parsed.data;
    const res = await pool.query(
      `INSERT INTO pricing
         (provider, model, input_price_per_million, output_price_per_million,
          cached_input_price_per_million, currency)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [p.provider, p.model, p.input_price_per_million, p.output_price_per_million,
       p.cached_input_price_per_million, p.currency]
    );
    await audit(pool, { actor_type: "admin", action: "pricing.create",
      resource_type: "pricing", resource_id: res.rows[0].id, result: "success",
      metadata: { provider: p.provider, model: p.model } });
    return reply.code(201).send(res.rows[0]);
  });

  app.get("/v1/pricing", async (req) => {
    const q = req.query as { provider?: string; model?: string };
    const params: unknown[] = [];
    const where: string[] = [];
    if (q.provider) {
      params.push(q.provider);
      where.push(`provider = $${params.length}`);
    }
    if (q.model) {
      params.push(q.model);
      where.push(`model = $${params.length}`);
    }
    const res = await pool.query(
      `SELECT * FROM pricing ${where.length ? "WHERE " + where.join(" AND ") : ""}
       ORDER BY effective_from DESC LIMIT 100`, params
    );
    return { items: res.rows };
  });

  const budgetSchema = z.object({
    scope: z.enum(["run", "agent"]),
    ref_id: z.string().uuid(),
    limit_micro: z.number().int().min(0),
    effect: z.enum(["block", "warn"]).default("block")
  });

  app.post("/v1/budgets", async (req, reply) => {
    const parsed = budgetSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_budget" });
    const client = await pool.connect();
    try {
      const workspaceId = await defaultWorkspaceId(client);
      const b = parsed.data;
      const res = await client.query(
        `INSERT INTO budgets (workspace_id, scope, ref_id, limit_micro, effect)
         VALUES ($1,$2,$3,$4,$5) RETURNING *`,
        [workspaceId, b.scope, b.ref_id, b.limit_micro, b.effect]
      );
      await audit(pool, { actor_type: "admin", action: "budget.create",
        resource_type: "budget", resource_id: res.rows[0].id, result: "success",
        metadata: { scope: b.scope, limit_micro: b.limit_micro, effect: b.effect } });
      return reply.code(201).send(res.rows[0]);
    } finally {
      client.release();
    }
  });

  app.get("/v1/budgets", async (req) => {
    const q = req.query as { scope?: string; ref_id?: string };
    const params: unknown[] = [];
    const where: string[] = [];
    if (q.scope) {
      params.push(q.scope);
      where.push(`scope = $${params.length}`);
    }
    if (q.ref_id) {
      params.push(q.ref_id);
      where.push(`ref_id = $${params.length}`);
    }
    const res = await pool.query(
      `SELECT *, (limit_micro - spent_micro - reserved_micro) AS remaining_micro
       FROM budgets ${where.length ? "WHERE " + where.join(" AND ") : ""}
       ORDER BY created_at DESC`, params
    );
    return { items: res.rows };
  });

  app.put("/v1/budgets/:id", async (req, reply) => {
    const { id } = req.params as { id: string };
    const parsed = z.object({
      limit_micro: z.number().int().min(0).optional(),
      effect: z.enum(["block", "warn"]).optional()
    }).safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_budget" });
    const sets: string[] = ["updated_at = now()"];
    const params: unknown[] = [];
    if (parsed.data.limit_micro !== undefined) {
      params.push(parsed.data.limit_micro);
      sets.push(`limit_micro = $${params.length}`);
    }
    if (parsed.data.effect !== undefined) {
      params.push(parsed.data.effect);
      sets.push(`effect = $${params.length}`);
    }
    params.push(id);
    const res = await pool.query(
      `UPDATE budgets SET ${sets.join(", ")} WHERE id = $${params.length} RETURNING *`, params
    );
    if (!res.rows[0]) return reply.code(404).send({ error: "budget_not_found" });
    await audit(pool, { actor_type: "admin", action: "budget.update",
      resource_type: "budget", resource_id: id, result: "success",
      metadata: parsed.data as Record<string, unknown> });
    return res.rows[0];
  });

  const checkSchema = z.object({
    budget_id: z.string().uuid(),
    max_cost_micro: z.number().int().min(0),
    ttl_seconds: z.number().int().min(1).default(300)
  });

  // Reserve-before-call. SELECT ... FOR UPDATE holds the budget row for the
  // rest of the check, so concurrent calls serialize and cannot both pass an
  // exhausted budget.
  app.post("/v1/budgets/check", async (req, reply) => {
    const parsed = checkSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_check" });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const b = await client.query("SELECT * FROM budgets WHERE id = $1 FOR UPDATE", [parsed.data.budget_id]);
      if (!b.rows[0]) {
        await client.query("ROLLBACK");
        return reply.code(404).send({ error: "budget_not_found" });
      }
      const budget = b.rows[0];
      if (!workspaceAllowed(req.principal, budget.workspace_id)) {
        await client.query("ROLLBACK");
        return reply.code(403).send({ error: "workspace_forbidden" });
      }
      const used = Number(budget.spent_micro) + Number(budget.reserved_micro);
      const over = used + parsed.data.max_cost_micro > Number(budget.limit_micro);

      if (over && budget.effect === "block") {
        await client.query("ROLLBACK");
        await audit(pool, { actor_type: "agent", action: "budget.exceeded",
          resource_type: "budget", resource_id: budget.id, result: "blocked",
          metadata: { spent_micro: budget.spent_micro, limit_micro: budget.limit_micro } });
        void notify(budget.workspace_id, "budget.exceeded",
          { budget_id: budget.id, scope: budget.scope, spent_micro: Number(budget.spent_micro), limit_micro: Number(budget.limit_micro) });
        return reply.code(409).send({ error: "budget_exceeded",
          spent_micro: Number(budget.spent_micro), limit_micro: Number(budget.limit_micro) });
      }

      const updated = await client.query(
        "UPDATE budgets SET reserved_micro = reserved_micro + $2 WHERE id = $1 RETURNING *",
        [budget.id, parsed.data.max_cost_micro]
      );
      const expiresAt = new Date(Date.now() + parsed.data.ttl_seconds * 1000).toISOString();
      const r = await client.query(
        `INSERT INTO budget_reservations (budget_id, amount_micro, expires_at)
         VALUES ($1,$2,$3) RETURNING id, expires_at`,
        [budget.id, parsed.data.max_cost_micro, expiresAt]
      );
      await client.query("COMMIT");
      return { ok: true, reservation_id: r.rows[0].id, expires_at: r.rows[0].expires_at,
        warning: over ? "budget limit reached, warn-only budget" : undefined,
        remaining_micro: Number(updated.rows[0].limit_micro) - Number(updated.rows[0].spent_micro) - Number(updated.rows[0].reserved_micro) };
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  });

  const settleSchema = z.object({
    reservation_id: z.string().uuid(),
    actual_cost_micro: z.number().int().min(0).nullable().optional()
  });

  // Settle to the measured cost and release the remainder. Missing usage or
  // an expired hold settles at the reserved maximum, never less.
  app.post("/v1/budgets/settle", async (req, reply) => {
    const parsed = settleSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_settle" });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      // Lock the reservation row: two concurrent settles serialize here, so
      // only the first can flip held -> settled; the second reads 'settled'
      // and gets 409 instead of adding the amount to spent_micro twice.
      const r = await client.query("SELECT * FROM budget_reservations WHERE id = $1 FOR UPDATE", [parsed.data.reservation_id]);
      if (!r.rows[0]) {
        await client.query("ROLLBACK");
        return reply.code(404).send({ error: "reservation_not_found" });
      }
      const res = r.rows[0];
      if (res.status !== "held") {
        await client.query("ROLLBACK");
        return reply.code(409).send({ error: "reservation_not_held", status: res.status });
      }
      const bw = await client.query("SELECT workspace_id FROM budgets WHERE id = $1", [res.budget_id]);
      if (!workspaceAllowed(req.principal, bw.rows[0]?.workspace_id ?? "")) {
        await client.query("ROLLBACK");
        return reply.code(403).send({ error: "workspace_forbidden" });
      }
      const actual = parsed.data.actual_cost_micro ?? Number(res.amount_micro);
      await client.query(
        `UPDATE budgets SET reserved_micro = reserved_micro - $2, spent_micro = spent_micro + $3,
           updated_at = now() WHERE id = $1`,
        [res.budget_id, Number(res.amount_micro), actual]
      );
      await client.query(
        "INSERT INTO budget_ledger (budget_id, amount_micro, reservation_id) VALUES ($1,$2,$3)",
        [res.budget_id, actual, res.id]
      );
      await client.query("UPDATE budget_reservations SET status='settled' WHERE id=$1", [res.id]);
      await client.query("COMMIT");
      return { ok: true, actual_cost_micro: actual };
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  });

  app.post("/v1/budgets/release", async (req, reply) => {
    const parsed = z.object({ reservation_id: z.string().uuid() }).safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_release" });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      // Same lock as settle: concurrent releases cannot both subtract the
      // reserved amount, and one that loses the race sees 'released'.
      const r = await client.query("SELECT * FROM budget_reservations WHERE id = $1 FOR UPDATE", [parsed.data.reservation_id]);
      if (!r.rows[0] || r.rows[0].status !== "held") {
        await client.query("ROLLBACK");
        return reply.code(404).send({ error: "reservation_not_found" });
      }
      const rw = await client.query("SELECT workspace_id FROM budgets WHERE id = $1", [r.rows[0].budget_id]);
      if (!workspaceAllowed(req.principal, rw.rows[0]?.workspace_id ?? "")) {
        await client.query("ROLLBACK");
        return reply.code(403).send({ error: "workspace_forbidden" });
      }
      await client.query("UPDATE budgets SET reserved_micro = reserved_micro - $2 WHERE id = $1",
        [r.rows[0].budget_id, Number(r.rows[0].amount_micro)]);
      await client.query("UPDATE budget_reservations SET status='released' WHERE id=$1", [r.rows[0].id]);
      await client.query("COMMIT");
      return { ok: true };
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  });

  // Token and cost breakdown for one run. Costs resolve against the pricing
  // version in force when each span ran. Spans with no matching price report
  // NULL cost and appear in missing_pricing, never as zero.
  app.get("/v1/runs/:id/usage", async (req, reply) => {
    const { id } = req.params as { id: string };
    const run = await pool.query("SELECT * FROM runs WHERE id = $1", [id]);
    if (!run.rows[0] || !workspaceAllowed(req.principal, run.rows[0].workspace_id)) {
      return reply.code(404).send({ error: "run_not_found" });
    }
    const spans = await pool.query(
      `SELECT s.id, s.operation_type, s.provider, s.model, s.input_tokens, s.output_tokens,
              s.started_at, s.cached_tokens, p.id AS pricing_id,
              CASE WHEN s.input_tokens IS NULL AND s.output_tokens IS NULL THEN NULL
                   WHEN p.id IS NULL THEN NULL
                   ELSE ((GREATEST(COALESCE(s.input_tokens,0) - COALESCE(s.cached_tokens,0), 0) * p.input_price_per_million
                        + COALESCE(s.cached_tokens,0) * p.cached_input_price_per_million
                        + COALESCE(s.output_tokens,0) * p.output_price_per_million) / 1000000)::BIGINT
              END AS cost_micro
       FROM spans s LEFT JOIN LATERAL (
         SELECT * FROM pricing
         WHERE provider = s.provider AND model = s.model AND effective_from <= s.started_at
         ORDER BY effective_from DESC LIMIT 1
       ) p ON true
       WHERE s.run_id = $1 ORDER BY s.started_at ASC`,
      [id]
    );
    let input = 0;
    let output = 0;
    let cost = 0;
    let costUnknown = false;
    const missing: string[] = [];
    for (const s of spans.rows) {
      input += s.input_tokens ?? 0;
      output += s.output_tokens ?? 0;
      if (s.input_tokens != null || s.output_tokens != null) {
        if (s.cost_micro == null) {
          costUnknown = true;
          missing.push(`${s.provider ?? "?"}:${s.model ?? "?"}`);
        } else {
          cost += Number(s.cost_micro);
        }
      }
    }
    return {
      run_id: id, input_tokens: input, output_tokens: output,
      estimated_cost_micro: cost, cost_partial: costUnknown,
      missing_pricing: [...new Set(missing)], spans: spans.rows
    };
  });
}
