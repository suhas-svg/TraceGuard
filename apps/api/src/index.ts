import Fastify from "fastify";
import { randomUUID } from "node:crypto";
import { pool, isDbReady } from "./db.js";
import { ingestBodySchema } from "@traceguard/schemas";

const API_KEY = process.env.API_KEY ?? "";
const PORT = Number(process.env.PORT ?? 8080);

export function buildApp() {
  const app = Fastify({ logger: true, genReqId: () => randomUUID() });

  app.get("/healthz", async () => ({ ok: true }));

  app.get("/readyz", async (req, reply) => {
    const ready = await isDbReady();
    if (!ready) return reply.code(503).send({ ok: false });
    return { ok: true };
  });

  // shortcut: single API key for all /v1 routes. Upgrade to scoped
  // ingest/gateway/admin keys plus login before multi-user use.
  app.addHook("onRequest", async (req, reply) => {
    if (!req.url.startsWith("/v1/")) return;
    const auth = req.headers.authorization ?? "";
    if (auth !== `Bearer ${API_KEY}`) {
      return reply.code(401).send({ error: "unauthorized" });
    }
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
        // Resolve workspace: explicit id wins, else named default, else shared default.
        let workspaceId = e.workspace_id;
        if (!workspaceId) {
          const name = e.workspace_name ?? "default";
          const found = await client.query("SELECT id FROM workspaces WHERE name = $1", [name]);
          workspaceId = found.rows[0]?.id;
          if (!workspaceId) {
            const created = await client.query(
              "INSERT INTO workspaces (name) VALUES ($1) RETURNING id",
              [name]
            );
            workspaceId = created.rows[0].id;
          }
        }

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
          `INSERT INTO runs (id, workspace_id, agent_id, status, started_at)
           VALUES ($1, $2, $3, 'running', $4)
           ON CONFLICT (id) DO NOTHING`,
          [e.run_id, workspaceId, agentId, e.timestamp]
        );

        if (e.event_type === "run.completed") {
          await client.query(
            "UPDATE runs SET status = 'success', ended_at = $2 WHERE id = $1",
            [e.run_id, e.timestamp]
          );
        } else if (e.event_type === "run.failed") {
          await client.query(
            "UPDATE runs SET status = 'failed', ended_at = $2, error_type = $3 WHERE id = $1",
            [e.run_id, e.timestamp, e.error_type ?? "unknown"]
          );
        }

        // Span upsert is idempotent on event_id: retries never duplicate.
        const endedAt =
          e.duration_ms != null
            ? new Date(new Date(e.timestamp).getTime() + e.duration_ms).toISOString()
            : null;
        const res = await client.query(
          `INSERT INTO spans
             (id, run_id, parent_span_id, event_id, operation_type, name, started_at, ended_at,
              duration_ms, status, provider, model, input_tokens, output_tokens,
              usage_source, error_type, attributes)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
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
            e.input_tokens == null && e.output_tokens == null
              ? "unavailable"
              : (e.usage_source ?? "provider_reported"),
            e.error_type ?? null,
            JSON.stringify(e.attributes ?? {})
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
    const q = req.query as { agent_id?: string; status?: string; limit?: string; cursor?: string };
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
    if (q.cursor) {
      params.push(q.cursor);
      where.push(`r.started_at < (SELECT started_at FROM runs WHERE id = $${params.length})`);
    }
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

  app.get("/v1/runs/:id", async (req, reply) => {
    const { id } = req.params as { id: string };
    const res = await pool.query("SELECT * FROM runs WHERE id = $1", [id]);
    if (!res.rows[0]) return reply.code(404).send({ error: "run_not_found" });
    return res.rows[0];
  });

  app.get("/v1/runs/:id/trace", async (req, reply) => {
    const { id } = req.params as { id: string };
    const run = await pool.query("SELECT * FROM runs WHERE id = $1", [id]);
    if (!run.rows[0]) return reply.code(404).send({ error: "run_not_found" });
    const spans = await pool.query("SELECT * FROM spans WHERE run_id = $1 ORDER BY started_at ASC", [
      id
    ]);
    return { run: run.rows[0], spans: spans.rows };
  });

  return app;
}

const isMain = process.argv[1]?.endsWith("index.js") || process.argv[1]?.endsWith("index.ts");
if (isMain) {
  buildApp().listen({ port: PORT, host: "0.0.0.0" });
}
