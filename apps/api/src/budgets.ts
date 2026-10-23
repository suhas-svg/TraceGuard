import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { Pool, PoolClient } from "pg";
import { pool } from "./db.js";
import { audit } from "./audit.js";
import { scopeClause, workspaceAllowed } from "./auth.js";
import { ensureDefaultProject, projectAllowed } from "./project-scope.js";
import { notify } from "./notify.js";

async function defaultWorkspaceId(client: PoolClient): Promise<string> {
  const found = await client.query("SELECT id FROM workspaces WHERE name = 'default'");
  if (found.rows[0]) return found.rows[0].id;
  const created = await client.query("INSERT INTO workspaces (name) VALUES ('default') RETURNING id");
  return created.rows[0].id;
}

// Releases every hold whose TTL has passed and returns the micro-dollars
// freed. One statement, so the reservation flip and the counter decrement
// cannot be split by a crash, and re-running it finds nothing left to do.
// Without this, an abandoned hold (a caller that died between reserve and
// settle) keeps its worst case reserved forever: the budget then 409s with
// spent_micro at zero and nothing on the API can recover it.
async function sweepExpiredHolds(
  client: Pool | PoolClient, budgetId: string
): Promise<number> {
  const r = await client.query(
    `WITH expired AS (
       UPDATE budget_reservations SET status='released', released_at=now(), settle_reason='timeout'
        WHERE budget_id=$1 AND status='held' AND expires_at < now()
        RETURNING amount_micro
     )
     UPDATE budgets
        SET reserved_micro = GREATEST(0, reserved_micro - COALESCE((SELECT SUM(amount_micro) FROM expired),0))
      WHERE id=$1
      RETURNING COALESCE((SELECT SUM(amount_micro) FROM expired),0)::bigint AS freed`,
    [budgetId]
  );
  return Number(r.rows[0]?.freed ?? 0);
}

// §12.3: the per-budget reclaim above runs lazily, only when that budget is
// touched again. A crashed caller's hold on an otherwise idle budget would
// sit there forever; this sweep recovers every budget with an expired hold.
export async function sweepAllExpiredHolds(
  db: Pool | PoolClient
): Promise<{ freed_micro: number; budgets: number }> {
  const ids = await db.query(
    "SELECT DISTINCT budget_id FROM budget_reservations WHERE status='held' AND expires_at < now()"
  );
  let freed = 0;
  let budgets = 0;
  for (const row of ids.rows) {
    const got = await sweepExpiredHolds(db, String(row.budget_id));
    if (got > 0) budgets += 1;
    freed += got;
  }
  return { freed_micro: freed, budgets };
}

// Spend inside the budget's reporting period. Returns null for 'lifetime',
// where the cached spent_micro counter is already the answer; windowed periods
// sum the append-only ledger instead of resetting that counter on a schedule.
async function periodSpentMicro(
  client: PoolClient, budgetId: string, period: string
): Promise<number | null> {
  if (period === "lifetime") return null;
  const r = await client.query(
    `SELECT COALESCE(SUM(amount_micro),0)::bigint AS spent FROM budget_ledger
      WHERE budget_id=$1 AND created_at >= date_trunc($2, now()::timestamptz)`,
    [budgetId, period]
  );
  return Number(r.rows[0].spent);
}

// A project budget caps what the whole project spent, so it is measured from the
// spans that actually incurred cost rather than from the budget's own ledger.
// The ledger only accumulates for calls that checked that specific budget, which
// for a project cap would mean counting a fraction of the spend and reporting
// headroom that is not there. Unpriced spans contribute nothing, the same as
// everywhere else cost is estimated.
async function projectSpentMicro(
  client: Pool | PoolClient, projectId: string, period: string
): Promise<number> {
  const params: unknown[] = [projectId];
  let windowSql = "TRUE";
  if (period !== "lifetime") {
    params.push(period);
    windowSql = `s.started_at >= date_trunc($${params.length}, now()::timestamptz)`;
  }
  const r = await client.query(
    `SELECT COALESCE(SUM(
              CASE WHEN s.input_tokens IS NULL AND s.output_tokens IS NULL THEN 0
                   WHEN p.id IS NULL THEN 0
                   ELSE ((GREATEST(COALESCE(s.input_tokens,0) - COALESCE(s.cached_tokens,0), 0) * p.input_price_per_million
                        + COALESCE(s.cached_tokens,0) * p.cached_input_price_per_million
                        + COALESCE(s.output_tokens,0) * p.output_price_per_million) / 1000000)::BIGINT
              END), 0)::bigint AS spent
       FROM spans s
       JOIN runs r ON r.id = s.run_id
       LEFT JOIN LATERAL (
         SELECT * FROM pricing
         WHERE provider = s.provider AND model = s.model AND effective_from <= s.started_at
         ORDER BY effective_from DESC LIMIT 1
       ) p ON true
      WHERE r.project_id = $1 AND ${windowSql}`,
    params
  );
  return Number(r.rows[0].spent);
}

export function registerBudgetRoutes(app: FastifyInstance) {
  const pricingSchema = z.object({
    provider: z.string().min(1).max(64),
    model: z.string().min(1).max(128),
    // §12.2: prices are NUMERIC — sub-micro rates are representable.
    input_price_per_million: z.number().min(0),
    output_price_per_million: z.number().min(0),
    cached_input_price_per_million: z.number().min(0).default(0),
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
    // §12.2: NUMERIC columns travel as strings; the API reports numbers.
    return { items: res.rows.map((r) => ({ ...r,
      input_price_per_million: Number(r.input_price_per_million),
      output_price_per_million: Number(r.output_price_per_million),
      cached_input_price_per_million: Number(r.cached_input_price_per_million) })) };
  });

  const budgetSchema = z.object({
    // A project budget's ref_id is a project id. A workspace id is still
    // accepted as the legacy spelling and maps to that workspace's default
    // project, so existing callers keep working after the identity split.
    scope: z.enum(["run", "agent", "project"]),
    ref_id: z.string().uuid(),
    limit_micro: z.number().int().min(0),
    effect: z.enum(["block", "warn"]).default("block"),
    // 'lifetime' is the original behaviour: one limit for the row's whole life.
    period: z.enum(["lifetime", "day", "week", "month"]).default("lifetime")
  });

  app.post("/v1/budgets", async (req, reply) => {
    const parsed = budgetSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_budget" });
    const client = await pool.connect();
    try {
      const workspaceId = await defaultWorkspaceId(client);
      const b = parsed.data;
      let budgetWorkspace = workspaceId;
      let projectId: string;
      // A project budget names a project. The old spelling named the
      // workspace, so accept that too and map it to the default project.
      if (b.scope === "project") {
        const project = await client.query(
          "SELECT id, workspace_id FROM projects WHERE id = $1", [b.ref_id]);
        if (project.rows[0]) {
          projectId = project.rows[0].id;
          budgetWorkspace = project.rows[0].workspace_id;
        } else {
          const ws = await client.query("SELECT id FROM workspaces WHERE id = $1", [b.ref_id]);
          if (!ws.rows[0]) return reply.code(400).send({ error: "unknown_workspace" });
          budgetWorkspace = b.ref_id;
          projectId = await ensureDefaultProject(client, b.ref_id);
        }
        if (!workspaceAllowed(req.principal, budgetWorkspace) ||
            !projectAllowed(req.principal, projectId)) {
          return reply.code(403).send({ error: "project_forbidden" });
        }
      } else {
        projectId = await ensureDefaultProject(client, workspaceId);
      }
      const res = await client.query(
        `INSERT INTO budgets (workspace_id, project_id, scope, ref_id, limit_micro, effect, period)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
        [budgetWorkspace, projectId, b.scope, b.ref_id, b.limit_micro, b.effect, b.period]
      );
      await audit(pool, { actor_type: "admin", action: "budget.create",
        resource_type: "budget", resource_id: res.rows[0].id, result: "success",
        workspace_id: res.rows[0].workspace_id, project_id: res.rows[0].project_id,
        metadata: { scope: b.scope, limit_micro: b.limit_micro, effect: b.effect, period: b.period } });
      return reply.code(201).send(res.rows[0]);
    } finally {
      client.release();
    }
  });

  app.get("/v1/budgets", async (req) => {
    const q = req.query as { scope?: string; ref_id?: string; limit?: string };
    const limit = Math.min(Math.max(Number(q.limit ?? 100), 1), 500);
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
    // Money rows are workspace-confined like every other read. Members hold
    // the read scope for this path, so without this they see every team's
    // limits, spend, and remaining headroom.
    const scope = scopeClause(req.principal, params, "workspace_id");
    if (scope) where.push(scope);
    params.push(limit);
    const res = await pool.query(
      `SELECT *, (limit_micro - spent_micro - reserved_micro) AS remaining_micro
       FROM budgets ${where.length ? "WHERE " + where.join(" AND ") : ""}
       ORDER BY created_at DESC LIMIT $${params.length}`, params
    );
    // A project budget's spend is measured from the project's spans rather than
    // from a counter, so the cached column reads zero and the dashboard would
    // show headroom that is not there. One extra query per distinct project and
    // window on the page, not one per row.
    const projects = res.rows.filter((b) => b.scope === "project");
    if (projects.length > 0) {
      const spent = new Map<string, number>();
      for (const b of projects) {
        const key = `${b.project_id}\0${b.period ?? "lifetime"}`;
        if (!spent.has(key)) {
          spent.set(key, await projectSpentMicro(pool, b.project_id, b.period ?? "lifetime"));
        }
      }
      for (const b of projects) {
        b.spent_micro = spent.get(`${b.project_id}\0${b.period ?? "lifetime"}`) ?? 0;
        b.remaining_micro = Number(b.limit_micro) - b.spent_micro - Number(b.reserved_micro);
      }
    }
    return { items: res.rows };
  });

  app.put("/v1/budgets/:id", async (req, reply) => {
    const { id } = req.params as { id: string };
    const parsed = z.object({
      limit_micro: z.number().int().min(0).optional(),
      effect: z.enum(["block", "warn"]).optional(),
      period: z.enum(["lifetime", "day", "week", "month"]).optional()
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
    if (parsed.data.period !== undefined) {
      params.push(parsed.data.period);
      sets.push(`period = $${params.length}`);
    }
    params.push(id);
    const res = await pool.query(
      `UPDATE budgets SET ${sets.join(", ")} WHERE id = $${params.length} RETURNING *`, params
    );
    if (!res.rows[0]) return reply.code(404).send({ error: "budget_not_found" });
    await audit(pool, { actor_type: "admin", action: "budget.update",
      resource_type: "budget", resource_id: id, result: "success",
      workspace_id: res.rows[0].workspace_id, project_id: res.rows[0].project_id,
      metadata: parsed.data as Record<string, unknown> });
    return res.rows[0];
  });

  const checkSchema = z.object({
    budget_id: z.string().uuid(),
    max_cost_micro: z.number().int().min(0),
    ttl_seconds: z.number().int().min(1).default(300)
  });

  // Reserve-before-call. The block-budget check is a single conditional
  // UPDATE: the limit test and the counter increment happen under the row
  // lock, so concurrent checks cannot both pass an exhausted budget. A zero
  // row count is the denial (no read-then-write window).
  app.post("/v1/budgets/check", async (req, reply) => {
    const parsed = checkSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_check" });
    // Reclaim abandoned holds before measuring, on its own connection so the
    // 409 path below cannot roll the recovery back. This is what stops an
    // abandoned reservation from wedging the budget permanently.
    const freed = await sweepExpiredHolds(pool, parsed.data.budget_id);
    if (freed > 0) {
      await audit(pool, { actor_type: "system", action: "budget.reservation_expired",
        resource_type: "budget", resource_id: parsed.data.budget_id, result: "released",
        metadata: { freed_micro: freed } });
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const b = await client.query("SELECT * FROM budgets WHERE id = $1", [parsed.data.budget_id]);
      if (!b.rows[0]) {
        await client.query("ROLLBACK");
        return reply.code(404).send({ error: "budget_not_found" });
      }
      const budget = b.rows[0];
      // The row's workspace_id is the authoritative boundary for both legacy
      // workspace-named project budgets and real project ids.
      if (!workspaceAllowed(req.principal, budget.workspace_id)) {
        await client.query("ROLLBACK");
        return reply.code(403).send({ error: "workspace_forbidden" });
      }
      const spent = budget.scope === "project"
        ? await projectSpentMicro(client, budget.project_id, budget.period ?? "lifetime")
        : (await periodSpentMicro(client, budget.id, budget.period ?? "lifetime")) ??
          Number(budget.spent_micro);

      // Block budgets reserve only when the current spend plus every live
      // hold plus this request still fits. Warn budgets deliberately reserve
      // past the limit so the call can proceed and the warning is surfaced.
      const updated = budget.effect === "block"
        ? await client.query(
          `UPDATE budgets
              SET reserved_micro = reserved_micro + $2, updated_at = now()
            WHERE id = $1
              AND ($3::bigint + reserved_micro + $2) <= limit_micro
            RETURNING *`,
          [budget.id, parsed.data.max_cost_micro, spent]
        )
        : await client.query(
          `UPDATE budgets
              SET reserved_micro = reserved_micro + $2, updated_at = now()
            WHERE id = $1
            RETURNING *`,
          [budget.id, parsed.data.max_cost_micro]
        );

      if (updated.rowCount === 0) {
        await client.query("ROLLBACK");
        await audit(pool, { actor_type: "agent", action: "budget.exceeded",
          resource_type: "budget", resource_id: budget.id, result: "blocked",
          workspace_id: budget.workspace_id, project_id: budget.project_id,
          metadata: { spent_micro: spent, limit_micro: budget.limit_micro,
            requested_micro: parsed.data.max_cost_micro, period: budget.period ?? "lifetime" } });
        void notify(budget.workspace_id, "budget.exceeded",
          { budget_id: budget.id, scope: budget.scope, spent_micro: spent, limit_micro: Number(budget.limit_micro) });
        return reply.code(409).send({ error: "budget_exceeded",
          spent_micro: spent, limit_micro: Number(budget.limit_micro) });
      }

      const reserved = updated.rows[0];
      const over = spent + Number(reserved.reserved_micro) > Number(reserved.limit_micro);
      const expiresAt = new Date(Date.now() + parsed.data.ttl_seconds * 1000).toISOString();
      const r = await client.query(
        `INSERT INTO budget_reservations (budget_id, amount_micro, expires_at)
         VALUES ($1,$2,$3) RETURNING id, expires_at`,
        [budget.id, parsed.data.max_cost_micro, expiresAt]
      );
      await client.query("COMMIT");
      // §10.3: the reservation is a money-moving event; the chain gets it.
      await audit(pool, { actor_type: "agent", action: "budget.reserved",
        resource_type: "budget", resource_id: budget.id, result: "reserved",
        workspace_id: budget.workspace_id, project_id: budget.project_id,
        metadata: { reservation_id: r.rows[0].id, amount_micro: parsed.data.max_cost_micro,
          expires_at: r.rows[0].expires_at } });
      return { ok: true, reservation_id: r.rows[0].id, expires_at: r.rows[0].expires_at,
        warning: over ? "budget limit reached, warn-only budget" : undefined,
        remaining_micro: Number(reserved.limit_micro) - spent - Number(reserved.reserved_micro) };
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
      const bw = await client.query(
        "SELECT workspace_id, project_id FROM budgets WHERE id = $1", [res.budget_id]
      );
      if (!workspaceAllowed(req.principal, bw.rows[0]?.workspace_id ?? "")) {
        await client.query("ROLLBACK");
        return reply.code(403).send({ error: "workspace_forbidden" });
      }
      // A reservation is the authorized maximum. A caller that reports more
      // usage than it reserved cannot move more money than the budget check
      // approved; the excess is capped here and remains visible in the audit.
      const reservedAmount = Number(res.amount_micro);
      const actual = parsed.data.actual_cost_micro == null
        ? reservedAmount
        : Math.min(parsed.data.actual_cost_micro, reservedAmount);
      await client.query(
        `UPDATE budgets SET reserved_micro = reserved_micro - $2, spent_micro = spent_micro + $3,
           updated_at = now() WHERE id = $1`,
        [res.budget_id, Number(res.amount_micro), actual]
      );
      await client.query(
        "INSERT INTO budget_ledger (budget_id, amount_micro, reservation_id) VALUES ($1,$2,$3)",
        [res.budget_id, actual, res.id]
      );
      await client.query(
        "UPDATE budget_reservations SET status='settled', settle_reason=$2 WHERE id=$1",
        [res.id, parsed.data.actual_cost_micro == null ? "usage_unavailable" : "usage_known"]
      );
      await client.query("COMMIT");
      // §10.3: settlement closes the money loop; record what it settled at.
      await audit(pool, { actor_type: "agent", action: "budget.settled",
        resource_type: "budget", resource_id: res.budget_id, result: "settled",
        workspace_id: bw.rows[0]?.workspace_id ?? null,
        project_id: bw.rows[0]?.project_id ?? null,
        metadata: { reservation_id: res.id, settled_micro: actual,
          requested_micro: parsed.data.actual_cost_micro ?? reservedAmount,
          capped: parsed.data.actual_cost_micro != null && parsed.data.actual_cost_micro > reservedAmount,
          basis: parsed.data.actual_cost_micro == null ? "reserved_max" : "measured",
          settle_reason: parsed.data.actual_cost_micro == null ? "usage_unavailable" : "usage_known" } });
      return { ok: true, actual_cost_micro: actual,
        settle_reason: parsed.data.actual_cost_micro == null ? "usage_unavailable" : "usage_known" };
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
