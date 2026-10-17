import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { PoolClient } from "pg";
import { pool } from "./db.js";
import { audit } from "./audit.js";
import { scopeClause, workspaceAllowed } from "./auth.js";

// Reconciliation answers one question: do our estimates match what the
// provider says we spent? Actuals are imported operator records. Estimates
// price each span at the pricing version in force when it ran, so the two
// sides stay comparable even after price changes.
export interface CompareRow {
  provider: string;
  model: string;
  input_tokens: number;
  output_tokens: number;
  estimated_micro: number;
  actual_micro: number | null;
  variance_micro: number | null;
  variance_pct: number | null;
}

export function variance(
  estimated: number,
  actual: number | null
): { variance_micro: number | null; variance_pct: number | null } {
  if (actual === null) return { variance_micro: null, variance_pct: null };
  const diff = estimated - actual;
  return { variance_micro: diff, variance_pct: actual === 0 ? null : diff / actual };
}

async function defaultWorkspaceId(client: PoolClient): Promise<string> {
  const found = await client.query("SELECT id FROM workspaces WHERE name = 'default'");
  if (found.rows[0]) return found.rows[0].id;
  const created = await client.query("INSERT INTO workspaces (name) VALUES ('default') RETURNING id");
  return created.rows[0].id;
}

export function registerReconciliationRoutes(app: FastifyInstance) {
  const actualSchema = z.object({
    provider: z.string().min(1).max(64),
    model: z.string().min(1).max(128),
    period_start: z.string().datetime(),
    period_end: z.string().datetime(),
    input_tokens: z.number().int().min(0).default(0),
    output_tokens: z.number().int().min(0).default(0),
    actual_cost_micro: z.number().int().min(0),
    source: z.string().max(256).default("")
  });

  app.post("/v1/reconciliation/actuals", async (req, reply) => {
    const parsed = z.object({ rows: actualSchema.array().min(1).max(500) }).safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_actuals" });
    for (const r of parsed.data.rows) {
      if (new Date(r.period_end).getTime() <= new Date(r.period_start).getTime()) {
        return reply.code(400).send({ error: "period_end_must_follow_start" });
      }
    }
    const client = await pool.connect();
    try {
      const workspaceId = await defaultWorkspaceId(client);
      await client.query("BEGIN");
      let accepted = 0;
      let duplicates = 0;
      for (const r of parsed.data.rows) {
        // Idempotent on the invoice line's natural key: replaying a batch
        // stores nothing twice and says how many rows it skipped.
        const ins = await client.query(
          `INSERT INTO actuals
             (workspace_id, provider, model, period_start, period_end,
              input_tokens, output_tokens, actual_cost_micro, source)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
           ON CONFLICT (workspace_id, provider, model, period_start, period_end, source)
           DO NOTHING`,
          [workspaceId, r.provider, r.model, r.period_start, r.period_end,
           r.input_tokens, r.output_tokens, r.actual_cost_micro, r.source]
        );
        if (ins.rowCount === 0) duplicates++;
        else accepted++;
      }
      await client.query("COMMIT");
      await audit(pool, { actor_type: "admin", action: "reconciliation.import",
        resource_type: "actuals", result: "success",
        metadata: { rows: accepted, duplicates } });
      return reply.code(201).send({ accepted, duplicates });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  });

  app.get("/v1/reconciliation/compare", async (req, reply) => {
    const q = req.query as { provider?: string; model?: string; period_start?: string;
      period_end?: string; group_by?: string; bucket?: string };
    if (!q.period_start || !q.period_end) {
      return reply.code(400).send({ error: "period_required" });
    }
    // Section 12.1 asks for costs grouped by run, agent, model, project, and
    // reporting period. One endpoint serves all of them: the grouping swaps the
    // SELECT and GROUP BY, and the row shape stays the same so every caller and
    // the dashboard table keep working.
    const groupBy = q.group_by ?? "model";
    if (!["model", "agent", "project", "period"].includes(groupBy)) {
      return reply.code(400).send({ error: "invalid_group_by" });
    }
    // Interpolated into date_trunc below, so it is a whitelist, never the raw
    // parameter.
    const bucket = ["day", "week", "month"].includes(q.bucket ?? "") ? q.bucket! : "day";
    const client = await pool.connect();
    try {
      const workspaceId = await defaultWorkspaceId(client);
      // The comparison covers the default workspace, except when grouping by
      // project, where the point is to compare them. Members outside it get a
      // denial, not another team's numbers; the project grouping narrows to the
      // workspaces the caller may see instead.
      if (groupBy !== "project" && !workspaceAllowed(req.principal, workspaceId)) {
        // No release here: the finally below owns it. Releasing twice logs a
        // pool error on every denial and makes a routine 403 look like a fault.
        return reply.code(403).send({ error: "workspace_forbidden" });
      }
      const startMs = new Date(q.period_start).getTime();
      const endMs = new Date(q.period_end).getTime();
      if (!Number.isFinite(startMs) || !Number.isFinite(endMs)) {
        return reply.code(400).send({ error: "invalid_period" });
      }
      if (endMs <= startMs) {
        return reply.code(400).send({ error: "period_end_must_follow_start" });
      }
      const params: unknown[] = [];
      const joins: string[] = [];
      let groupSql: string;
      let labelSql: string;
      // The model grouping keeps its own columns so the dashboard's existing
      // key and badge keep working; every other grouping reports through label.
      let extraCols = "";
      if (groupBy === "agent") {
        joins.push("JOIN agents a ON a.id = r.agent_id");
        groupSql = "a.name";
        labelSql = "a.name";
        params.push(workspaceId);
      } else if (groupBy === "project") {
        joins.push("JOIN workspaces w ON w.id = r.workspace_id");
        groupSql = "w.id, w.name";
        labelSql = "w.name";
      } else if (groupBy === "period") {
        groupSql = `date_trunc('${bucket}', s.started_at)`;
        labelSql = `to_char(${groupSql}, 'YYYY-MM-DD')`;
        params.push(workspaceId);
      } else {
        groupSql = "s.provider, s.model";
        labelSql = "s.provider || '/' || s.model";
        extraCols = "s.provider, s.model, ";
        params.push(workspaceId);
      }
      const scopeWhere = groupBy === "project"
        ? scopeClause(req.principal, params, "r.workspace_id") ?? "TRUE"
        : `r.workspace_id = $${params.length}`;
      params.push(q.period_start);
      const startParam = params.length;
      params.push(q.period_end);
      const endParam = params.length;
      const filter: string[] = [];
      if (q.provider) {
        params.push(q.provider);
        filter.push(`s.provider = $${params.length}`);
      }
      if (q.model) {
        params.push(q.model);
        filter.push(`s.model = $${params.length}`);
      }
      const est = await client.query(
        `SELECT ${extraCols}${labelSql} AS label,
                COALESCE(SUM(s.input_tokens), 0) AS input_tokens,
                COALESCE(SUM(s.output_tokens), 0) AS output_tokens,
                COALESCE(SUM(
                  CASE WHEN s.input_tokens IS NULL AND s.output_tokens IS NULL THEN 0
                       WHEN p.id IS NULL THEN 0
                       ELSE ((GREATEST(COALESCE(s.input_tokens,0) - COALESCE(s.cached_tokens,0), 0) * p.input_price_per_million
                            + COALESCE(s.cached_tokens,0) * p.cached_input_price_per_million
                            + COALESCE(s.output_tokens,0) * p.output_price_per_million) / 1000000)::BIGINT
                  END), 0) AS estimated_micro,
                BOOL_OR(p.id IS NULL AND (s.input_tokens IS NOT NULL OR s.output_tokens IS NOT NULL)) AS missing_pricing
         FROM spans s JOIN runs r ON r.id = s.run_id
         ${joins.join("\n         ")}
         LEFT JOIN LATERAL (
           SELECT * FROM pricing
           WHERE provider = s.provider AND model = s.model AND effective_from <= s.started_at
           ORDER BY effective_from DESC LIMIT 1
         ) p ON true
         WHERE ${scopeWhere} AND s.started_at >= $${startParam} AND s.started_at < $${endParam}
         ${filter.length ? "AND " + filter.join(" AND ") : ""}
         GROUP BY ${groupSql}`,
        params
      );
      // Actuals are recorded per provider and model, so they can only be
      // attributed to a model grouping. Every other dimension reports a null
      // actual rather than a number that would be a guess.
      let actRows: { provider: string; model: string; actual_micro: unknown }[] = [];
      if (groupBy === "model") {
        const actParams: unknown[] = [workspaceId, q.period_start, q.period_end];
        const actFilter: string[] = [];
        if (q.provider) {
          actParams.push(q.provider);
          actFilter.push(`provider = $${actParams.length}`);
        }
        if (q.model) {
          actParams.push(q.model);
          actFilter.push(`model = $${actParams.length}`);
        }
        const act = await client.query(
          `SELECT provider, model, COALESCE(SUM(actual_cost_micro), 0) AS actual_micro
           FROM actuals
           WHERE workspace_id = $1 AND period_start >= $2 AND period_end <= $3
           ${actFilter.length ? "AND " + actFilter.join(" AND ") : ""}
           GROUP BY provider, model`,
          actParams
        );
        actRows = act.rows;
      }
      const actualByKey = new Map(
        actRows.map((r) => [`${r.provider}\0${r.model}`, Number(r.actual_micro)])
      );
      const keyOf = (r: { provider?: string | null; model?: string | null; label: string }) =>
        r.provider == null ? `${groupBy}\0${r.label}` : `${r.provider}\0${r.model}`;
      const rows: (CompareRow & { missing_pricing: boolean })[] = est.rows.map((r) => {
        const actual = actualByKey.get(keyOf(r)) ?? null;
        const v = variance(Number(r.estimated_micro), actual);
        actualByKey.delete(keyOf(r));
        return {
          provider: r.provider ?? groupBy, model: r.model ?? r.label,
          input_tokens: Number(r.input_tokens), output_tokens: Number(r.output_tokens),
          estimated_micro: Number(r.estimated_micro),
          actual_micro: actual, variance_micro: v.variance_micro, variance_pct: v.variance_pct,
          missing_pricing: r.missing_pricing
        };
      });
      for (const [k, actual] of actualByKey) {
        const [provider, model] = k.split("\0");
        rows.push({ provider, model, input_tokens: 0, output_tokens: 0,
          estimated_micro: 0, actual_micro: actual,
          ...variance(0, actual), missing_pricing: false });
      }
      rows.sort((a, b) => (a.provider + a.model < b.provider + b.model ? -1 : 1));
      return { period_start: q.period_start, period_end: q.period_end, group_by: groupBy, rows };
    } finally {
      client.release();
    }
  });
}
