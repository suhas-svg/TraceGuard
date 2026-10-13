import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { PoolClient } from "pg";
import { pool } from "./db.js";
import { audit } from "./audit.js";
import { estimateCostMicro } from "./cost.js";
import { runAssertion } from "./assertions.js";

async function defaultWorkspaceId(client: PoolClient): Promise<string> {
  const found = await client.query("SELECT id FROM workspaces WHERE name = 'default'");
  if (found.rows[0]) return found.rows[0].id;
  const created = await client.query("INSERT INTO workspaces (name) VALUES ('default') RETURNING id");
  return created.rows[0].id;
}

interface ExecConfig {
  output?: string;
  model?: string;
  provider?: string;
  input_tokens?: number;
  output_tokens?: number;
  latency_ms?: number;
  tools?: { tool: string; args?: Record<string, unknown>; status?: string; error_type?: string }[];
  fail?: string;
}

// Scripted reference adapter. It replays the case's declared behavior against
// the mock tool surface and records a real run, so evaluation tests the
// platform's record and compare path deterministically. Live model adapters
// arrive later behind the same run-writing contract.
async function executeCase(
  client: PoolClient,
  workspaceId: string,
  agentId: string,
  agentName: string,
  exec: ExecConfig,
  model: string
): Promise<{ runId: string; output: string; tools: string[]; status: string; latencyMs: number; costMicro: number }> {
  const started = Date.now();
  const runId = randomUUID();
  const rootId = randomUUID();
  const now = new Date().toISOString();
  await client.query(
    "INSERT INTO runs (id, workspace_id, agent_id, status, started_at) VALUES ($1,$2,$3,'running',$4)",
    [runId, workspaceId, agentId, now]
  );
  const addSpan = (id: string, parent: string | null, op: string, extra: Record<string, unknown>) =>
    client.query(
      `INSERT INTO spans
         (id, run_id, parent_span_id, event_id, operation_type, name, started_at,
          duration_ms, status, provider, model, input_tokens, output_tokens,
          usage_source, error_type, attributes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb)`,
      [id, runId, parent, `evt-${randomUUID()}`, op, op, now,
       extra.duration_ms ?? null, (extra.status as string) ?? "success",
       extra.provider ?? null, extra.model ?? null,
       extra.input_tokens ?? null, extra.output_tokens ?? null,
       extra.input_tokens == null && extra.output_tokens == null ? "unavailable" : "provider_reported",
       extra.error_type ?? null, JSON.stringify(extra.attributes ?? {})]
    );

  await addSpan(rootId, null, "run.started", {});
  // Bounded pretend work so latency is measured, not asserted.
  await new Promise((r) => setTimeout(r, Math.min(Math.max(exec.latency_ms ?? 0, 0), 2000)));
  const tools = exec.tools ?? [];
  await addSpan(randomUUID(), rootId, "model.request", {
    duration_ms: Date.now() - started, provider: exec.provider ?? "scripted",
    model: exec.model ?? model, input_tokens: exec.input_tokens ?? 0,
    output_tokens: exec.output_tokens ?? 0
  });
  const toolNames: string[] = [];
  for (const t of tools) {
    toolNames.push(t.tool);
    await addSpan(randomUUID(), rootId, "tool.invocation", {
      duration_ms: 5, status: t.status ?? "success", error_type: t.error_type ?? null,
      attributes: { tool: t.tool, args: t.args ?? {} }
    });
  }
  const failedTool = tools.find((t) => (t.status ?? "success") === "failed");
  const status = exec.fail || failedTool ? "failed" : "success";
  await client.query("UPDATE runs SET status=$2, ended_at=now(), error_type=$3 WHERE id=$1",
    [runId, status, exec.fail ?? failedTool?.error_type ?? null]);

  const price = await client.query(
    "SELECT * FROM pricing WHERE provider=$1 AND model=$2 ORDER BY effective_from DESC LIMIT 1",
    [exec.provider ?? "scripted", exec.model ?? model]
  );
  const cost = price.rows[0]
    ? estimateCostMicro(exec.input_tokens ?? 0, exec.output_tokens ?? 0, 0, {
        input_price_per_million: Number(price.rows[0].input_price_per_million),
        output_price_per_million: Number(price.rows[0].output_price_per_million),
        cached_input_price_per_million: Number(price.rows[0].cached_input_price_per_million)
      })
    : 0;
  return { runId, output: exec.output ?? "", tools: toolNames, status,
    latencyMs: Date.now() - started, costMicro: cost };
}

export function registerEvalRoutes(app: FastifyInstance) {
  app.post("/v1/evaluations/suites", async (req, reply) => {
    const parsed = z.object({
      name: z.string().min(1).max(128),
      description: z.string().max(1024).default("")
    }).safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_suite" });
    const existing = await pool.query(
      "SELECT MAX(version) AS v FROM eval_suites WHERE name = $1", [parsed.data.name]
    );
    const version = Number(existing.rows[0]?.v ?? 0) + 1;
    const res = await pool.query(
      "INSERT INTO eval_suites (name, version, description) VALUES ($1,$2,$3) RETURNING *",
      [parsed.data.name, version, parsed.data.description]
    );
    await audit(pool, { actor_type: "admin", action: "eval.suite_create",
      resource_type: "eval_suite", resource_id: res.rows[0].id, result: "success",
      metadata: { name: parsed.data.name, version } });
    return reply.code(201).send(res.rows[0]);
  });

  app.get("/v1/evaluations/suites", async () => {
    const res = await pool.query(
      `SELECT s.*, (SELECT COUNT(*) FROM eval_cases c WHERE c.suite_id = s.id) AS case_count,
              (SELECT COUNT(*) FROM eval_runs r WHERE r.suite_id = s.id) AS run_count
       FROM eval_suites s ORDER BY s.created_at DESC`
    );
    return { items: res.rows };
  });

  const caseSchema = z.object({
    name: z.string().min(1).max(128),
    input_payload: z.record(z.unknown()).default({}),
    expected: z.record(z.unknown()).default({}),
    assertions: z.array(z.record(z.unknown())).default([]),
    exec_config: z.record(z.unknown()).default({})
  });

  app.post("/v1/evaluations/suites/:id/cases", async (req, reply) => {
    const { id } = req.params as { id: string };
    const parsed = caseSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_case" });
    const suite = await pool.query("SELECT * FROM eval_suites WHERE id = $1", [id]);
    if (!suite.rows[0]) return reply.code(404).send({ error: "suite_not_found" });
    if (suite.rows[0].locked) return reply.code(409).send({ error: "suite_locked" });
    try {
      const c = parsed.data;
      const res = await pool.query(
        `INSERT INTO eval_cases (suite_id, name, input_payload, expected, assertions, exec_config)
         VALUES ($1,$2,$3::jsonb,$4::jsonb,$5::jsonb,$6::jsonb) RETURNING *`,
        [id, c.name, JSON.stringify(c.input_payload), JSON.stringify(c.expected),
         JSON.stringify(c.assertions), JSON.stringify(c.exec_config)]
      );
      return reply.code(201).send(res.rows[0]);
    } catch (err: unknown) {
      if ((err as { code?: string }).code === "23505") {
        return reply.code(409).send({ error: "case_name_taken" });
      }
      throw err;
    }
  });

  app.get("/v1/evaluations/suites/:id/cases", async (req, reply) => {
    const { id } = req.params as { id: string };
    const res = await pool.query("SELECT * FROM eval_cases WHERE suite_id = $1 ORDER BY name", [id]);
    if (!res.rows.length) {
      const suite = await pool.query("SELECT id FROM eval_suites WHERE id = $1", [id]);
      if (!suite.rows[0]) return reply.code(404).send({ error: "suite_not_found" });
    }
    return { items: res.rows };
  });

  const runSchema = z.object({
    agent_name: z.string().min(1).max(128).default("eval-agent"),
    config_fingerprint: z.string().max(256).default(""),
    model: z.string().max(128).default("scripted-1"),
    trials: z.number().int().min(1).max(5).default(1),
    cost_cap_micro: z.number().int().min(0).default(0),
    // Per-run behavior overrides keyed by case name. This is what makes two
    // versions comparable on one locked dataset: same cases, different code.
    exec_overrides: z.record(z.record(z.unknown())).default({})
  });

  app.post("/v1/evaluations/suites/:id/runs", async (req, reply) => {
    const { id } = req.params as { id: string };
    const parsed = runSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_eval_run" });
    const client = await pool.connect();
    try {
      const suite = await client.query("SELECT * FROM eval_suites WHERE id = $1", [id]);
      if (!suite.rows[0]) return reply.code(404).send({ error: "suite_not_found" });
      const cases = await client.query("SELECT * FROM eval_cases WHERE suite_id = $1 ORDER BY name", [id]);
      if (!cases.rows.length) return reply.code(400).send({ error: "suite_empty" });

      await client.query("UPDATE eval_suites SET locked = true WHERE id = $1", [id]);
      const workspaceId = await defaultWorkspaceId(client);
      const cfg = parsed.data;
      let agent = await client.query(
        "SELECT id FROM agents WHERE workspace_id = $1 AND name = $2", [workspaceId, cfg.agent_name]
      );
      if (!agent.rows[0]) {
        agent = await client.query(
          "INSERT INTO agents (workspace_id, name, adapter_type, config_fingerprint) VALUES ($1,$2,'scripted',$3) RETURNING id",
          [workspaceId, cfg.agent_name, cfg.config_fingerprint]
        );
      } else if (cfg.config_fingerprint) {
        await client.query("UPDATE agents SET config_fingerprint = $2 WHERE id = $1",
          [agent.rows[0].id, cfg.config_fingerprint]);
      }
      const er = await client.query(
        `INSERT INTO eval_runs (suite_id, suite_version, agent_id, agent_name,
          config_fingerprint, model, trials, cost_cap_micro)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
        [id, suite.rows[0].version, agent.rows[0].id, cfg.agent_name,
         cfg.config_fingerprint, cfg.model, cfg.trials, cfg.cost_cap_micro]
      );
      const evalRun = er.rows[0];

      let spent = 0;
      let stopped = "";
      const results = [];
      for (let trial = 1; trial <= cfg.trials && !stopped; trial++) {
        for (const c of cases.rows) {
          if (cfg.cost_cap_micro > 0 && spent >= cfg.cost_cap_micro) {
            stopped = "cost cap reached";
            break;
          }
          const exec = { ...((c.exec_config ?? {}) as ExecConfig),
            ...((cfg.exec_overrides[c.name] ?? {}) as Partial<ExecConfig>) };
          const out = await executeCase(client, workspaceId, agent.rows[0].id,
            cfg.agent_name, exec, cfg.model);
          spent += out.costMicro;
          const ctx = { output: out.output, tools: out.tools, status: out.status };
          const assertionResults = ((c.assertions ?? []) as Record<string, unknown>[])
            .map((a) => ({ type: String(a.type ?? "?"), ...runAssertion(a, ctx) }));
          const passed = assertionResults.every((r) => r.passed);
          const rr = await client.query(
            `INSERT INTO eval_results
               (eval_run_id, case_id, trial, agent_run_id, passed,
                assertion_results, latency_ms, cost_micro, error_summary)
             VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9) RETURNING *`,
            [evalRun.id, c.id, trial, out.runId, passed,
             JSON.stringify(assertionResults), out.latencyMs, out.costMicro,
             passed ? null : assertionResults.find((r) => !r.passed)?.message ?? out.status]
          );
          results.push(rr.rows[0]);
        }
      }
      const status = stopped ? "cancelled" : "success";
      await client.query("UPDATE eval_runs SET status = $2, ended_at = now() WHERE id = $1",
        [evalRun.id, status]);
      await audit(pool, { actor_type: "admin", action: "eval.run",
        resource_type: "eval_run", resource_id: evalRun.id, result: status,
        metadata: { suite: suite.rows[0].name, trials: cfg.trials, stopped } });
      return reply.code(201).send({ eval_run: { ...evalRun, status }, results, stopped });
    } finally {
      client.release();
    }
  });

  app.get("/v1/evaluations/runs/:id", async (req, reply) => {
    const { id } = req.params as { id: string };
    const run = await pool.query("SELECT * FROM eval_runs WHERE id = $1", [id]);
    if (!run.rows[0]) return reply.code(404).send({ error: "eval_run_not_found" });
    const results = await pool.query(
      `SELECT r.*, c.name AS case_name FROM eval_results r
       JOIN eval_cases c ON c.id = r.case_id
       WHERE r.eval_run_id = $1 ORDER BY c.name, r.trial`, [id]
    );
    return { eval_run: run.rows[0], results: results.rows };
  });

  // Compare explicit run ids on pass rate, latency, cost, and violations.
  // Missing data stays missing: absent costs do not count as zero.
  app.get("/v1/evaluations/runs/compare", async (req, reply) => {
    const q = req.query as { ids?: string };
    const ids = (q.ids ?? "").split(",").map((s) => s.trim()).filter(Boolean).slice(0, 5);
    if (ids.length < 2) return reply.code(400).send({ error: "need_two_ids" });
    const runs = await pool.query("SELECT * FROM eval_runs WHERE id = ANY($1)", [ids]);
    if (runs.rows.length !== ids.length) return reply.code(404).send({ error: "eval_run_not_found" });
    const out = [];
    for (const r of runs.rows) {
      const res = await pool.query("SELECT * FROM eval_results WHERE eval_run_id = $1", [r.id]);
      const lat = res.rows.map((x) => Number(x.latency_ms));
      const denied = await pool.query(
        `SELECT COUNT(*) AS n FROM spans s JOIN eval_results e ON e.agent_run_id = s.run_id
         WHERE e.eval_run_id = $1 AND s.status = 'denied'`, [r.id]
      );
      const passed = res.rows.filter((x) => x.passed).length;
      out.push({
        eval_run_id: r.id, agent_name: r.agent_name, config_fingerprint: r.config_fingerprint,
        model: r.model, trials: r.trials, cases: res.rows.length, passed,
        pass_rate: res.rows.length ? passed / res.rows.length : null,
        latency_ms: lat.length
          ? { mean: Math.round(lat.reduce((a, b) => a + b, 0) / lat.length), min: Math.min(...lat), max: Math.max(...lat) }
          : null,
        cost_micro: res.rows.reduce((a, x) => a + Number(x.cost_micro), 0),
        violations: Number(denied.rows[0]?.n ?? 0)
      });
    }
    return { runs: out };
  });
}
