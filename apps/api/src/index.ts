import Fastify from "fastify";
import { randomUUID } from "node:crypto";
import { pool, isDbReady } from "./db.js";
import { ingestBodySchema } from "@traceguard/schemas";
import { registerBudgetRoutes, sweepAllExpiredHolds } from "./budgets.js";
import { registerEvalRoutes } from "./evals.js";
import { registerWebhookRoutes } from "./webhooks.js";
import { ensureDefaultSpanRetention, registerRetentionRoutes } from "./retention.js";
import { registerReconciliationRoutes } from "./reconciliation.js";
import { attrsToObject, mapOtlpSpan, otlpLimits, otlpRateLimited, type OtlpSpan } from "./otlp.js";
import { decodeTraceRequest, encodeTraceResponse } from "./otlp_proto.js";
import { authHook, scopeClause, workspaceAllowed } from "./auth.js";
import { assertProductionAuth } from "./oauth.js";
import { projectAllowed, projectClause, resolveProject } from "./project-scope.js";
import { audit } from "./audit.js";
import { registerUserRoutes } from "./users.js";
import { registerSessionRoutes } from "./sessions.js";
import { registerAdminRoutes } from "./admin.js";
import { registerProjectRoutes } from "./projects.js";
import { captureRawEnabled, redactDeep } from "./redact.js";
import { computeWarnings, thresholdsFromEnv } from "./diagnostics.js";

const PORT = Number(process.env.PORT ?? 8080);
// The browser dashboard fetches cross-origin, so the API answers CORS.
// Single trusted origin, configured per deploy. The gateway gets the same
// treatment when its UI screens land.
const DASHBOARD_ORIGIN = process.env.DASHBOARD_ORIGIN ?? "http://localhost:5173";

export function buildApp() {
  const app = Fastify({ logger: true, genReqId: () => randomUUID() });

  // §7.3: a production deployment authenticates people and agents through
  // the configured OAuth issuer, not through static bearer keys.
  assertProductionAuth();

  // Privacy default check. Raw-capture mode is opt-in and loud: it weakens
  // the "no raw prompt/response/args unless asked" guarantee on every
  // persistence path (ingest, OTLP, evals, approvals).
  if (captureRawEnabled()) {
    app.log.warn("CAPTURE_RAW_ATTRIBUTES=true: raw prompt/response/tool-argument content may be persisted. See docs/security.md.");
  }

  // OTLP exporters speak binary protobuf by default. This parser hands the
  // raw bytes to the protobuf decoder instead of the JSON parser.
  for (const type of ["application/x-protobuf", "application/protobuf"]) {
    app.addContentTypeParser(type, { parseAs: "buffer" }, (_req, body, done) => {
      done(null, body);
    });
  }

  app.get("/healthz", async () => ({ ok: true }));

  app.get("/readyz", async (req, reply) => {
    const ready = await isDbReady();
    if (!ready) return reply.code(503).send({ ok: false });
    return { ok: true };
  });

  // CORS first, then the central scoped-auth hook. The old single key still
  // works with full access; user keys carry role scopes instead.
  app.addHook("onRequest", async (req, reply) => {
    reply.header("Access-Control-Allow-Origin", DASHBOARD_ORIGIN);
    reply.header("Access-Control-Allow-Credentials", "true");
    reply.header("Access-Control-Allow-Headers", "authorization, content-type, x-csrf-token");
    // Browsers reject PUT/DELETE preflights without an explicit method list.
    reply.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    if (req.method === "OPTIONS") return reply.code(204).send();
    await authHook(req, reply);
  });

  app.post("/v1/ingest/events", async (req, reply) => {
    const parsed = ingestBodySchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_events", details: parsed.error.flatten() });
    }
    if (parsed.data.events.length > 500) {
      return reply.code(413).send({ error: "too_many_events" });
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      let accepted = 0;
      let duplicates = 0;

      for (const e of parsed.data.events) {
        // Resolve workspace: explicit id wins, else named lookup. Admins and
        // env keys auto-create unknown names; member keys only write where
        // they belong, so unknown or foreign names stop here, not later.
        let workspaceId = e.workspace_id;
        if (!workspaceId) {
          const name = e.workspace_name ?? "default";
          const found = await client.query("SELECT id FROM workspaces WHERE name = $1", [name]);
          workspaceId = found.rows[0]?.id;
          if (!workspaceId) {
            if (req.principal?.workspaces !== "all") {
              await client.query("ROLLBACK");
              return reply.code(403).send({ error: "workspace_forbidden", workspace: name });
            }
            const created = await client.query(
              "INSERT INTO workspaces (name) VALUES ($1) RETURNING id",
              [name]
            );
            const newWorkspaceId = created.rows[0].id as string;
            workspaceId = newWorkspaceId;
            await ensureDefaultSpanRetention(client, newWorkspaceId);
          }
        }
        if (typeof workspaceId !== "string") {
          await client.query("ROLLBACK");
          return reply.code(400).send({ error: "workspace_unresolved" });
        }
        if (!workspaceAllowed(req.principal, workspaceId)) {
          await client.query("ROLLBACK");
          return reply.code(403).send({ error: "workspace_forbidden", workspace_id: workspaceId });
        }
        // §7.1/§13.1: every run belongs to a project. An ingestion key is
        // pinned to one; humans default to their allowed project inside the
        // workspace and may name another project they are allowed to use.
        const projectContext = await resolveProject(client, req.principal, {
          workspaceId,
          projectId: e.project_id ?? null,
          projectName: e.project_name ?? null
        });
        if (!projectContext) {
          await client.query("ROLLBACK");
          return reply.code(403).send({ error: "project_forbidden" });
        }
        const projectId = projectContext.project.id;

        // Resolve agent: explicit id wins, else per-workspace named agent.
        let agentId = e.agent_id;
        if (!agentId) {
          const name = e.agent_name ?? "demo-agent";
          const found = await client.query(
            "SELECT id FROM agents WHERE workspace_id = $1 AND name = $2",
            [workspaceId, name]
          );
          agentId = found.rows[0]?.id;
          if (!agentId) {
            const created = await client.query(
              "INSERT INTO agents (workspace_id, name) VALUES ($1, $2) RETURNING id",
              [workspaceId, name]
            );
            agentId = created.rows[0].id;
          }
        }

        // Run upsert is idempotent on run_id: first event creates, later events update status.
        await client.query(
          `INSERT INTO runs (id, workspace_id, project_id, agent_id, status, started_at)
           VALUES ($1, $2, $3, $4, 'running', $5)
           ON CONFLICT (id) DO NOTHING`,
          [e.run_id, workspaceId, projectId, agentId, e.timestamp]
        );

        if (e.event_type === "run.completed" || e.event_type === "run.failed") {
          const target = e.event_type === "run.completed" ? "success" : "failed";
          // §11.4: a finalized run is never rewritten by a late event. A
          // replay of the same outcome stays silent; a conflicting late
          // event is recorded as an explicit correction instead.
          const applied = await client.query(
            `UPDATE runs SET status = $2, ended_at = $3,
               error_type = CASE WHEN $2 = 'failed' THEN $4 ELSE error_type END
             WHERE id = $1 AND status = 'running'`,
            [e.run_id, target, e.timestamp, e.error_type ?? "unknown"]
          );
          if (applied.rowCount === 0) {
            const current = await client.query("SELECT status FROM runs WHERE id = $1", [e.run_id]);
            const previous = current.rows[0]?.status as string | undefined;
            if (previous && previous !== target) {
              await audit(client, {
                actor_type: "system", action: "run.status_correction",
                resource_type: "run", resource_id: e.run_id, result: "rejected",
                metadata: { event_type: e.event_type, previous_status: previous, attempted_status: target }
              });
            }
          }
        }

        // Span upsert is idempotent on event_id: retries never duplicate.
        const endedAt =
          e.duration_ms != null
            ? new Date(new Date(e.timestamp).getTime() + e.duration_ms).toISOString()
            : null;
        const res = await client.query(
          `INSERT INTO spans
             (id, run_id, parent_span_id, event_id, operation_type, name, started_at, ended_at,
              duration_ms, status, provider, model, input_tokens, output_tokens, cached_tokens,
              usage_source, error_type, attributes)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
           ON CONFLICT (event_id) DO NOTHING`,
          [
            e.span_id,
            e.run_id,
            e.parent_span_id ?? null,
            e.event_id,
            e.event_type,
            e.event_type,
            e.timestamp,
            endedAt,
            e.duration_ms ?? null,
            e.status,
            e.provider ?? null,
            e.model ?? null,
            e.input_tokens ?? null,
            e.output_tokens ?? null,
            e.cached_tokens ?? null,
            e.input_tokens == null && e.output_tokens == null
              ? "unavailable"
              : (e.usage_source ?? "provider_reported"),
            e.error_type ?? null,
            JSON.stringify(redactDeep(e.attributes ?? {}, { captureRaw: captureRawEnabled() }))
          ]
        );
        if (res.rowCount === 0) duplicates++;
        else accepted++;
      }

      await client.query("COMMIT");
      return { accepted, duplicates };
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  });

  app.get("/v1/runs", async (req) => {
    const q = req.query as {
      agent_id?: string; status?: string; limit?: string; cursor?: string;
      since?: string; until?: string; provider?: string; model?: string; eval_run_id?: string;
    };
    const limit = Math.min(Math.max(Number(q.limit ?? 50), 1), 200);
    const params: unknown[] = [];
    const where: string[] = [];
    if (q.agent_id) {
      params.push(q.agent_id);
      where.push(`r.agent_id = $${params.length}`);
    }
    if (q.status) {
      params.push(q.status);
      where.push(`r.status = $${params.length}`);
    }
    // Date range filters use the run's start time, which the cursor also
    // orders by. Unparseable timestamps are ignored rather than guessed at.
    if (q.since && !Number.isNaN(Date.parse(q.since))) {
      params.push(q.since);
      where.push(`r.started_at >= $${params.length}`);
    }
    if (q.until && !Number.isNaN(Date.parse(q.until))) {
      params.push(q.until);
      where.push(`r.started_at <= $${params.length}`);
    }
    // Provider/model/eval-run filters narrow by what the run actually used:
    // a span with that provider or model, or an eval result linking the run
    // to the named evaluation run.
    if (q.provider) {
      params.push(q.provider);
      where.push(`EXISTS (SELECT 1 FROM spans s WHERE s.run_id = r.id AND s.provider = $${params.length})`);
    }
    if (q.model) {
      params.push(q.model);
      where.push(`EXISTS (SELECT 1 FROM spans s WHERE s.run_id = r.id AND s.model = $${params.length})`);
    }
    if (q.eval_run_id && /^[0-9a-fA-F-]{36}$/.test(q.eval_run_id)) {
      params.push(q.eval_run_id);
      where.push(`EXISTS (SELECT 1 FROM eval_results er WHERE er.agent_run_id = r.id AND er.eval_run_id = $${params.length})`);
    }
    if (q.cursor) {
      params.push(q.cursor);
      where.push(`r.started_at < (SELECT started_at FROM runs WHERE id = $${params.length})`);
    }
    // Members list only their own workspaces and projects. Workspace scope
    // alone would expose every project in a shared workspace.
    const scope = scopeClause(req.principal, params, "r.workspace_id");
    if (scope) where.push(scope);
    const projectScope = projectClause(req.principal, params, "r.project_id");
    if (projectScope) where.push(projectScope);
    params.push(limit + 1);
    const rows = await pool.query(
      `SELECT r.*, a.name AS agent_name,
              COALESCE((SELECT SUM(input_tokens) FROM spans s WHERE s.run_id = r.id), 0) AS input_tokens,
              COALESCE((SELECT SUM(output_tokens) FROM spans s WHERE s.run_id = r.id), 0) AS output_tokens,
              (SELECT COUNT(*) FROM spans s WHERE s.run_id = r.id) AS span_count
       FROM runs r JOIN agents a ON a.id = r.agent_id
       ${where.length ? "WHERE " + where.join(" AND ") : ""}
       ORDER BY r.started_at DESC LIMIT $${params.length}`,
      params
    );
    const hasMore = rows.rows.length > limit;
    const items = hasMore ? rows.rows.slice(0, limit) : rows.rows;
    return {
      items,
      next_cursor: hasMore ? items[items.length - 1].id : null
    };
  });

  // Dashboard tiles read global totals from here, so a filtered list cannot
  // re-count itself. Same workspace scoping as the list.
  app.get("/v1/runs/counts", async (req) => {
    const params: unknown[] = [];
    const where: string[] = [];
    const scope = scopeClause(req.principal, params, "r.workspace_id");
    if (scope) where.push(scope);
    const projectScope = projectClause(req.principal, params, "r.project_id");
    if (projectScope) where.push(projectScope);
    const runFilter = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const byStatus = await pool.query(
      `SELECT r.status, COUNT(*)::int AS count
         FROM runs r
        ${runFilter}
        GROUP BY r.status`,
      params
    );
    // `params` now holds both scopes. Reusing it here keeps the workspace and
    // project predicates identical rather than accidentally widening the
    // denied count back to the whole workspace.
    const denied = await pool.query(
      `SELECT COUNT(*)::int AS count
         FROM spans s JOIN runs r ON r.id = s.run_id
        WHERE s.status = 'denied' ${where.length ? "AND " + where.join(" AND ") : ""}`,
      params
    );
    const counts: Record<string, number> = {};
    for (const row of byStatus.rows as { status: string; count: number }[]) {
      counts[row.status] = row.count;
    }
    return {
      counts,
      total: Object.values(counts).reduce((sum, n) => sum + n, 0),
      denied_spans: (denied.rows[0] as { count: number }).count
    };
  });

  // Dashboard overview: one workspace-scoped read for the KPI row — run
  // totals, token usage, estimated spend with an explicit partial flag,
  // median/p95 run latency, denial count, and the live approval queue.
  app.get("/v1/overview", async (req) => {
    const q = req.query as { since?: string };
    const since = q.since && !Number.isNaN(Date.parse(q.since)) ? q.since : null;
    // Every run-scoped aggregate shares the same workspace + date filter.
    const base = (extra: string[] = []) => {
      const params: unknown[] = [];
      const where: string[] = [];
      const scope = scopeClause(req.principal, params, "r.workspace_id");
      if (scope) where.push(scope);
      const projectScope = projectClause(req.principal, params, "r.project_id");
      if (projectScope) where.push(projectScope);
      if (since) {
        params.push(since);
        where.push(`r.started_at >= $${params.length}`);
      }
      where.push(...extra);
      return { params, sql: where.length ? "WHERE " + where.join(" AND ") : "" };
    };

    const runsBase = base();
    const statuses = await pool.query(
      `SELECT r.status, COUNT(*)::int AS count FROM runs r ${runsBase.sql} GROUP BY r.status`,
      runsBase.params
    );
    const byStatus: Record<string, number> = {};
    for (const row of statuses.rows as { status: string; count: number }[]) {
      byStatus[row.status] = row.count;
    }

    const usage = await pool.query(
      `SELECT COALESCE(SUM(s.input_tokens), 0)::bigint AS input_tokens,
              COALESCE(SUM(s.output_tokens), 0)::bigint AS output_tokens,
              COUNT(*) FILTER (WHERE s.input_tokens IS NOT NULL OR s.output_tokens IS NOT NULL)::int AS spans_with_usage,
              COUNT(*) FILTER (WHERE s.input_tokens IS NULL AND s.output_tokens IS NULL)::int AS spans_without_usage
         FROM spans s JOIN runs r ON r.id = s.run_id ${runsBase.sql}`,
      runsBase.params
    );

    // Spend uses the price in force at each span's start. Spans with usage
    // but no matching price are counted, never billed as zero.
    const cost = await pool.query(
      `SELECT COALESCE(SUM(t.cost_micro), 0)::bigint AS estimated_cost_micro,
              COUNT(*) FILTER (WHERE t.cost_micro IS NULL AND (t.input_tokens IS NOT NULL OR t.output_tokens IS NOT NULL))::int AS missing_pricing_spans
         FROM (
           SELECT s.input_tokens, s.output_tokens, s.cached_tokens,
                  CASE WHEN s.input_tokens IS NULL AND s.output_tokens IS NULL THEN NULL
                       WHEN p.id IS NULL THEN NULL
                       ELSE ((GREATEST(COALESCE(s.input_tokens, 0) - COALESCE(s.cached_tokens, 0), 0)::bigint * p.input_price_per_million
                            + COALESCE(s.cached_tokens, 0)::bigint * p.cached_input_price_per_million
                            + COALESCE(s.output_tokens, 0)::bigint * p.output_price_per_million) / 1000000)::bigint
                  END AS cost_micro
             FROM spans s JOIN runs r ON r.id = s.run_id
             LEFT JOIN LATERAL (
               SELECT pr.id, pr.input_price_per_million, pr.output_price_per_million,
                      pr.cached_input_price_per_million
                 FROM pricing pr
                WHERE pr.provider = s.provider AND pr.model = s.model AND pr.effective_from <= s.started_at
                ORDER BY pr.effective_from DESC LIMIT 1
             ) p ON true
             ${runsBase.sql}
         ) t`,
      runsBase.params
    );

    const latency = await pool.query(
      `SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (r.ended_at - r.started_at)) * 1000) AS median_ms,
              percentile_cont(0.95) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (r.ended_at - r.started_at)) * 1000) AS p95_ms
         FROM runs r ${base(["r.ended_at IS NOT NULL"]).sql}`,
      base(["r.ended_at IS NOT NULL"]).params
    );

    const denied = await pool.query(
      `SELECT COUNT(*)::int AS count FROM spans s JOIN runs r ON r.id = s.run_id
        ${base(["s.status = 'denied'"]).sql}`,
      base(["s.status = 'denied'"]).params
    );

    // Pending approvals live on the gateway but share this database. Expired
    // rows are excluded even before any sweeper touches them.
    const apParams: unknown[] = [];
    const apWhere = ["a.status = 'pending'", "a.expires_at > now()"];
    const apScope = scopeClause(req.principal, apParams, "a.workspace_id");
    if (apScope) apWhere.push(apScope);
    const apProjectScope = projectClause(req.principal, apParams, "a.project_id");
    if (apProjectScope) apWhere.push(apProjectScope);
    const pending = await pool.query(
      `SELECT COUNT(*)::int AS count FROM approvals a
        WHERE ${apWhere.join(" AND ")}`,
      apParams
    );

    const round1 = (v: unknown): number | null => (v == null ? null : Math.round(Number(v) * 10) / 10);
    const usageRow = usage.rows[0];
    const costRow = cost.rows[0];
    const latRow = latency.rows[0] as { median_ms: unknown; p95_ms: unknown };
    return {
      since,
      runs: { total: Object.values(byStatus).reduce((sum, n) => sum + n, 0), by_status: byStatus },
      tokens: {
        input_tokens: Number(usageRow.input_tokens),
        output_tokens: Number(usageRow.output_tokens),
        spans_with_usage: usageRow.spans_with_usage,
        spans_without_usage: usageRow.spans_without_usage
      },
      cost: {
        estimated_cost_micro: Number(costRow.estimated_cost_micro),
        cost_partial: costRow.missing_pricing_spans > 0,
        missing_pricing_spans: costRow.missing_pricing_spans
      },
      latency_ms: { median: round1(latRow.median_ms), p95: round1(latRow.p95_ms) },
      denied_spans: (denied.rows[0] as { count: number }).count,
      pending_approvals: (pending.rows[0] as { count: number }).count
    };
  });

  // Agent directory for dashboard filters. Workspace-scoped like everything
  // else; names repeat across workspaces, so ids are the filter key.
  app.get("/v1/agents", async (req) => {
    const params: unknown[] = [];
    const where: string[] = [];
    const scope = scopeClause(req.principal, params, "workspace_id");
    if (scope) where.push(scope);
    // Agents are workspace-level rows, but a project-restricted principal
    // must not enumerate agents that only ever acted in another project.
    const projectScope = projectClause(req.principal, params, "r.project_id");
    if (projectScope) {
      where.push(
        `EXISTS (SELECT 1 FROM runs r WHERE r.agent_id = agents.id AND ${projectScope})`
      );
    }
    const rows = await pool.query(
      `SELECT id, name, adapter_type, created_at FROM agents
        ${where.length ? "WHERE " + where.join(" AND ") : ""}
        ORDER BY name ASC LIMIT 500`,
      params
    );
    return { items: rows.rows };
  });

  app.get("/v1/runs/:id", async (req, reply) => {
    const { id } = req.params as { id: string };
    const res = await pool.query("SELECT * FROM runs WHERE id = $1", [id]);
    // Foreign runs read as missing, so ids cannot probe other workspaces.
    if (!res.rows[0] || !workspaceAllowed(req.principal, res.rows[0].workspace_id) ||
        !projectAllowed(req.principal, res.rows[0].project_id)) {
      return reply.code(404).send({ error: "run_not_found" });
    }
    return res.rows[0];
  });

  app.get("/v1/runs/:id/trace", async (req, reply) => {
    const { id } = req.params as { id: string };
    // Join the agent so the trace header can name it, matching the list view.
    const run = await pool.query(
      `SELECT r.*, a.name AS agent_name FROM runs r
       LEFT JOIN agents a ON a.id = r.agent_id
       WHERE r.id = $1`,
      [id]
    );
    if (!run.rows[0] || !workspaceAllowed(req.principal, run.rows[0].workspace_id) ||
        !projectAllowed(req.principal, run.rows[0].project_id)) {
      return reply.code(404).send({ error: "run_not_found" });
    }
    const spans = await pool.query("SELECT * FROM spans WHERE run_id = $1 ORDER BY started_at ASC", [
      id
    ]);
    return { run: run.rows[0], spans: spans.rows };
  });

  app.get("/v1/runs/:id/spans", async (req, reply) => {
    const { id } = req.params as { id: string };
    const run = await pool.query("SELECT * FROM runs WHERE id = $1", [id]);
    if (!run.rows[0] || !workspaceAllowed(req.principal, run.rows[0].workspace_id) ||
        !projectAllowed(req.principal, run.rows[0].project_id)) {
      return reply.code(404).send({ error: "run_not_found" });
    }
    const spans = await pool.query(
      "SELECT * FROM spans WHERE run_id = $1 ORDER BY started_at ASC", [id]
    );
    return { items: spans.rows };
  });

  // §14: redacted approval summaries for the dashboard. This endpoint cannot
  // decrypt arguments or transition state; decisions remain on the gateway's
  // dedicated control listener.
  app.get("/v1/approvals", async (req, reply) => {
    reply.header("Cache-Control", "no-store");
    const q = req.query as { status?: string; limit?: string };
    const limit = Math.min(Math.max(Number(q.limit ?? 50), 1), 200);
    const params: unknown[] = [];
    const where: string[] = [];
    if (q.status) {
      params.push(q.status);
      where.push(`a.status = $${params.length}`);
    }
    const scope = scopeClause(req.principal, params, "a.workspace_id");
    if (scope) where.push(scope);
    const projectScope = projectClause(req.principal, params, "a.project_id");
    if (projectScope) where.push(projectScope);
    params.push(limit);
    const res = await pool.query(
      `SELECT a.id, a.workspace_id, a.project_id, a.server_id, a.tool_name, a.status,
              a.requested_by, a.requested_at, a.expires_at, a.decided_at, a.terminal_at,
              a.args_summary, a.outcome_summary, a.execution_started_at,
              d.run_id, d.span_id, d.request_id
         FROM approvals a
         LEFT JOIN LATERAL (
           SELECT run_id, span_id, request_id FROM policy_decisions
            WHERE approval_id = a.id
            ORDER BY timestamp DESC LIMIT 1
         ) d ON true
        ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
        ORDER BY a.requested_at DESC LIMIT $${params.length}`,
      params
    );
    return { items: res.rows };
  });

  // FR-010 loop and usage diagnostics. Advisory heuristics over the run's
  // recorded spans; recomputed per request so it always reflects current
  // data and never blocks or mutates anything.
  app.get("/v1/runs/:id/diagnostics", async (req, reply) => {
    const { id } = req.params as { id: string };
    const run = await pool.query("SELECT * FROM runs WHERE id = $1", [id]);
    if (!run.rows[0] || !workspaceAllowed(req.principal, run.rows[0].workspace_id) ||
        !projectAllowed(req.principal, run.rows[0].project_id)) {
      return reply.code(404).send({ error: "run_not_found" });
    }
    const spans = await pool.query(
      `SELECT operation_type, name, status, error_type, started_at, ended_at,
              input_tokens, output_tokens, attributes
         FROM spans WHERE run_id = $1`,
      [id]
    );
    const thresholds = thresholdsFromEnv();
    return {
      run_id: id,
      warnings: computeWarnings(run.rows[0], spans.rows, thresholds),
      thresholds
    };
  });

  registerAdminRoutes(app);
  registerProjectRoutes(app);
  registerBudgetRoutes(app);
  registerEvalRoutes(app);
  registerWebhookRoutes(app);
  registerRetentionRoutes(app);
  registerReconciliationRoutes(app);
  registerUserRoutes(app);
  registerSessionRoutes(app);

  // OTLP/HTTP receiver in both encodings. Exporters default to binary
  // protobuf; http/json also works. Spans in one trace share a run; ids map
  // deterministically so retries upsert instead of duplicating. The reply is
  // a collector-spec ExportTraceServiceResponse: partialSuccess reports what
  // was refused, and an empty/absent one means the batch was fully accepted.
  const otlpBodyLimit = otlpLimits().maxBodyBytes;
  app.post("/v1/traces", { bodyLimit: otlpBodyLimit }, async (req, reply) => {
    const limits = otlpLimits();
    const contentType = String(req.headers["content-type"] ?? "");
    const isProtobuf = contentType.includes("protobuf");
    let resourceSpans: {
      resource?: { attributes?: { key: string; value?: Record<string, unknown> }[] };
      scopeSpans?: { spans?: OtlpSpan[] }[];
    }[] | undefined;
    if (isProtobuf) {
      try {
        resourceSpans = decodeTraceRequest(req.body as Buffer).resourceSpans as typeof resourceSpans;
      } catch {
        return reply.code(400).send({ error: "invalid_protobuf" });
      }
    } else {
      const body = req.body as { resourceSpans?: typeof resourceSpans };
      resourceSpans = body?.resourceSpans;
    }
    if (!Array.isArray(resourceSpans) || resourceSpans.length > 50) {
      return reply.code(400).send({ error: "invalid_traces" });
    }
    // Rate before any database work: a runaway exporter is turned away
    // cheaply (§11.1). In-process fixed window, keyed per authenticated
    // caller and project. The project comes from the resource attributes (or
    // the caller's single project for an ingest key), so one project cannot
    // spend another project's budget. See otlp.ts for the single-process
    // caveat.
    const rateGroups = new Map<string, number>();
    const principalProject = req.principal?.projects !== "all"
      ? req.principal?.projects?.[0] : undefined;
    for (const rs of resourceSpans) {
      const resource = attrsToObject(rs.resource?.attributes ?? []);
      const workspace = String(resource["traceguard.workspace"] ?? "unscoped");
      const project = String(
        resource["traceguard.project_id"] ?? resource["traceguard.project"]
          ?? principalProject ?? "unscoped"
      );
      const key = `${req.principal?.userId ?? req.principal?.agentPrincipalId ?? "static-key"}:${workspace}:${project}`;
      const spans = (rs.scopeSpans ?? []).reduce((m, ss) => m + (ss.spans ?? []).length, 0);
      rateGroups.set(key, (rateGroups.get(key) ?? 0) + spans);
    }
    for (const [key, spans] of rateGroups) {
      if (otlpRateLimited(key, spans, limits.rateSpansPerMinute)) {
        return reply.code(429).header("retry-after", "60").send({ error: "rate_limited" });
      }
    }

    const receivedAtMs = Date.now();
    const insertedIds: string[] = [];
    let rejected = 0;
    // Rejections are counted by reason so the partialSuccess message is
    // actionable instead of a bare number.
    const reasons = new Map<string, number>();
    const reject = (reason: string) => {
      rejected++;
      reasons.set(reason, (reasons.get(reason) ?? 0) + 1);
    };
    // Past the span cap spans are refused and reported, never silently cut.
    let budget = limits.maxSpans;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      for (const rs of resourceSpans) {
        const resource = attrsToObject(
          (rs.resource?.attributes ?? []) as Parameters<typeof attrsToObject>[0]
        );
        const spans = (rs.scopeSpans ?? []).flatMap((s) => s.spans ?? []);
        for (const span of spans) {
          if (budget <= 0) {
            reject("span cap exceeded");
            continue;
          }
          budget--;
          const m = mapOtlpSpan(span, resource, {
            receivedAtMs,
            maxAttributes: limits.maxAttributes,
            maxAttrString: limits.maxAttrString,
            skewThresholdMs: limits.skewThresholdMs
          });
          if (!m) {
            reject("missing or unparseable start time");
            continue;
          }
          // The 24h late window bounds backfill: an exporter replaying the
          // distant past is refused rather than rewriting old windows.
          if (Date.parse(m.startedAt) < receivedAtMs - limits.lateWindowMs) {
            reject("start time older than the 24h late window");
            continue;
          }
          let workspace = await client.query("SELECT id FROM workspaces WHERE name = $1", [m.workspaceName]);
          if (!workspace.rows[0]) {
            if (req.principal?.workspaces !== "all") {
              await client.query("ROLLBACK");
              return reply.code(403).send({ error: "workspace_forbidden", workspace: m.workspaceName });
            }
            workspace = await client.query("INSERT INTO workspaces (name) VALUES ($1) RETURNING id", [m.workspaceName]);
            await ensureDefaultSpanRetention(client, workspace.rows[0].id);
          }
          if (!workspaceAllowed(req.principal, workspace.rows[0].id)) {
            await client.query("ROLLBACK");
            return reply.code(403).send({ error: "workspace_forbidden", workspace: m.workspaceName });
          }
          const projectContext = await resolveProject(client, req.principal, {
            workspaceId: workspace.rows[0].id,
            projectId: m.projectId,
            projectName: m.projectName
          });
          if (!projectContext) {
            await client.query("ROLLBACK");
            return reply.code(403).send({ error: "project_forbidden", project: m.projectName });
          }
          let agent = await client.query(
            "SELECT id FROM agents WHERE workspace_id = $1 AND name = $2",
            [workspace.rows[0].id, m.agentName]
          );
          if (!agent.rows[0]) {
            agent = await client.query(
              "INSERT INTO agents (workspace_id, name, adapter_type) VALUES ($1, $2, 'otlp') RETURNING id",
              [workspace.rows[0].id, m.agentName]
            );
          }
          await client.query(
            `INSERT INTO runs (id, workspace_id, project_id, agent_id, status, started_at)
             VALUES ($1, $2, $3, $4, 'running', $5) ON CONFLICT (id) DO NOTHING`,
            [m.runId, workspace.rows[0].id, projectContext.project.id, agent.rows[0].id, m.startedAt]
          );
          const endedAt =
            m.durationMs != null
              ? new Date(new Date(m.startedAt).getTime() + m.durationMs).toISOString()
              : null;
          // §11.4 parent ordering: resolved means the parent row is already
          // stored. A child arriving first waits as unresolved — the
          // end-of-batch link below settles it, or the orphan sweep does.
          let parentState = "resolved";
          if (m.parentSpanId) {
            const parent = await client.query("SELECT 1 FROM spans WHERE id = $1", [m.parentSpanId]);
            parentState = parent.rows[0] ? "resolved" : "unresolved";
          }
          const res = await client.query(
            `INSERT INTO spans
               (id, run_id, parent_span_id, event_id, operation_type, name, started_at, ended_at,
                duration_ms, status, provider, model, input_tokens, output_tokens, cached_tokens,
                usage_source, error_type, attributes, received_at, ingestion_source, schema_version,
                clock_skew, parent_state)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,
                     'otlp', 'otlp-traces/1', $20, $21)
             ON CONFLICT (event_id) DO NOTHING`,
            [m.spanId, m.runId, m.parentSpanId, m.eventId, m.operationType, m.name,
             m.startedAt, endedAt, m.durationMs, m.status, m.provider, m.model,
             m.inputTokens, m.outputTokens, m.cachedTokens, m.usageSource, m.errorType,
             JSON.stringify(m.attributes), new Date(receivedAtMs).toISOString(), m.clockSkew,
             parentState]
          );
          // Duplicates land silently: the partial-success reply counts only
          // rejections, the way the collector contract specifies.
          if (res.rowCount !== 0) {
            insertedIds.push(m.spanId);
          }
        }
      }
      // Child-before-parent: spans stored earlier that name a span from this
      // batch as their parent are linked now. Linking flips only the state
      // flag; a late arrival never rewrites a run's or span's outcome. An
      // orphaned child is revived too — a parent inside the 24h late window
      // disproves the orphan verdict rather than being ignored.
      if (insertedIds.length > 0) {
        await client.query(
          `UPDATE spans SET parent_state = 'resolved'
           WHERE parent_span_id = ANY($1::uuid[]) AND parent_state IN ('unresolved', 'orphaned')`,
          [insertedIds]
        );
      }
      await client.query("COMMIT");
      const errorMessage = rejected > 0
        ? `${rejected} span(s) rejected: ${[...reasons.entries()]
            .map(([reason, n]) => `${n} ${reason}`)
            .join("; ")}`.slice(0, 512)
        : undefined;
      if (isProtobuf) {
        return reply.type("application/x-protobuf")
          .send(encodeTraceResponse({ rejectedSpans: rejected, errorMessage }));
      }
      // A rejected span is reported, not silently dropped: an exporter that
      // gets no signal retries the same bad batch forever while its valid
      // siblings never land. Full acceptance answers with an empty document —
      // a zero-valued partialSuccess is not part of the collector contract.
      if (rejected === 0) return {};
      return { partialSuccess: { rejectedSpans: rejected, errorMessage } };
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  });

  // Runs orphaned by crashed SDKs never send a completion event. §11.3 gives
  // the window: a run that never finalizes within 15 minutes is ORPHANED —
  // not failed, because failure is a claim about the work that nobody made.
  // Call this periodically (cron, not a scheduler in the app).
  app.post("/v1/admin/finalize-stale-runs", async (req) => {
    const q = req.query as { older_than_seconds?: string };
    const seconds = Math.min(Math.max(Number(q.older_than_seconds ?? 900), 60), 86400);
    const res = await pool.query(
      `UPDATE runs SET status = 'orphaned', ended_at = now(), error_type = 'stale_timeout'
       WHERE status = 'running' AND started_at < now() - ($1 || ' seconds')::interval
       RETURNING id`,
      [String(seconds)]
    );
    // A bulk status mutation belongs in the same trail as every other admin
    // outcome; it is not exempt because it is a sweep.
    await audit(pool, { actor_type: "admin", action: "run.finalize_stale",
      resource_type: "run", result: "success",
      metadata: { older_than_seconds: seconds, finalized: res.rows.length } });
    return { finalized: res.rows.length, ids: res.rows.map((r) => r.id) };
  });

  // Unresolved parents that never arrived are marked ORPHANED, not left
  // half-linked forever (§11.3). Cron-invoked like the run finalizer, with
  // the spec's 15 minute default.
  // §12.3: abandoned reservations must not wedge a budget forever. The
  // per-budget reclaims run lazily on that budget's next touch; this
  // endpoint sweeps every hold past its TTL in one pass for the cron.
  app.post("/v1/admin/sweep-budget-holds", async () => {
    const totals = await sweepAllExpiredHolds(pool);
    if (totals.settled_micro > 0 || totals.budgets > 0) {
      await audit(pool, { actor_type: "system", action: "budget.holds_swept",
        resource_type: "budget", result: "success",
        metadata: { settled_micro: totals.settled_micro, budgets: totals.budgets } });
    }
    return totals;
  });

  app.post("/v1/admin/finalize-orphan-spans", async (req) => {
    const q = req.query as { older_than_seconds?: string };
    const seconds = Math.min(Math.max(Number(q.older_than_seconds ?? 900), 60), 86400);
    const res = await pool.query(
      `UPDATE spans SET parent_state = 'orphaned'
       WHERE parent_state = 'unresolved' AND received_at < now() - ($1 || ' seconds')::interval
       RETURNING id`,
      [String(seconds)]
    );
    await audit(pool, { actor_type: "admin", action: "span.finalize_orphans",
      resource_type: "span", result: "success",
      metadata: { older_than_seconds: seconds, orphaned: res.rows.length } });
    return { orphaned: res.rows.length, ids: res.rows.map((r) => r.id) };
  });

  return app;
}

const isMain = process.argv[1]?.endsWith("index.js") || process.argv[1]?.endsWith("index.ts");
if (isMain) {
  buildApp().listen({ port: PORT, host: "0.0.0.0" });
}
