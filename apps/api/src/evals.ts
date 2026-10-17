import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { PoolClient } from "pg";
import { pool } from "./db.js";
import { audit } from "./audit.js";
import { workspaceAllowed } from "./auth.js";
import { estimateCostMicro } from "./cost.js";
import { runAssertion } from "./assertions.js";
import { notify } from "./notify.js";
import { captureRawEnabled, redactDeep } from "./redact.js";

async function defaultWorkspaceId(client: PoolClient): Promise<string> {
  const found = await client.query("SELECT id FROM workspaces WHERE name = 'default'");
  if (found.rows[0]) return found.rows[0].id;
  const created = await client.query("INSERT INTO workspaces (name) VALUES ('default') RETURNING id");
  return created.rows[0].id;
}

interface ExecConfig {
  output?: string;
  input?: string;
  model?: string;
  provider?: string;
  input_tokens?: number;
  output_tokens?: number;
  cached_tokens?: number;
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
): Promise<{ runId: string; output: string; tools: string[]; status: string; latencyMs: number; costMicro: number | null }> {
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
          duration_ms, status, provider, model, input_tokens, output_tokens, cached_tokens,
          usage_source, error_type, attributes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17::jsonb)`,
      [id, runId, parent, `evt-${randomUUID()}`, op, op, now,
       extra.duration_ms ?? null, (extra.status as string) ?? "success",
       extra.provider ?? null, extra.model ?? null,
       extra.input_tokens ?? null, extra.output_tokens ?? null, extra.cached_tokens ?? null,
       extra.input_tokens == null && extra.output_tokens == null ? "unavailable" : "provider_reported",
       extra.error_type ?? null, JSON.stringify(extra.attributes ?? {})]
    );

  // Dataset-authored input rides the run's first span for provenance; it is
  // dataset content, not a runtime prompt, and passes the same redaction
  // pass as every other span attribute.
  await addSpan(rootId, null, "run.started",
    exec.input === undefined ? {} : { attributes: { input: exec.input } });
  // Bounded pretend work so latency is measured, not asserted.
  await new Promise((r) => setTimeout(r, Math.min(Math.max(exec.latency_ms ?? 0, 0), 2000)));
  const tools = exec.tools ?? [];
  await addSpan(randomUUID(), rootId, "model.request", {
    duration_ms: Date.now() - started, provider: exec.provider ?? "scripted",
    model: exec.model ?? model, input_tokens: exec.input_tokens ?? null,
    output_tokens: exec.output_tokens ?? null, cached_tokens: exec.cached_tokens ?? null
  });
  const toolNames: string[] = [];
  for (const t of tools) {
    toolNames.push(t.tool);
    await addSpan(randomUUID(), rootId, "tool.invocation", {
      duration_ms: 5, status: t.status ?? "success", error_type: t.error_type ?? null,
      attributes: redactDeep({ tool: t.tool, args: t.args ?? {} }, { captureRaw: captureRawEnabled() })
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
  // Unknown price or unknown usage stays NULL, never zero (same rule as the
  // usage endpoint; comparisons must not read "no price" as "$0.00").
  const priced = price.rows[0] != null && (exec.input_tokens != null || exec.output_tokens != null);
  const cost = priced
    ? estimateCostMicro(exec.input_tokens ?? 0, exec.output_tokens ?? 0, Number(exec.cached_tokens ?? 0), {
        input_price_per_million: Number(price.rows[0].input_price_per_million),
        output_price_per_million: Number(price.rows[0].output_price_per_million),
        cached_input_price_per_million: Number(price.rows[0].cached_input_price_per_million)
      })
    : null;
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
    // Allocate the version inside the insert. Read-then-insert lets two
    // concurrent creates compute the same next version, and the loser dies on
    // the unique index with a 500 instead of a usable answer.
    try {
      const res = await pool.query(
        `INSERT INTO eval_suites (name, version, description)
         SELECT $1, COALESCE(MAX(version), 0) + 1, $2 FROM eval_suites WHERE name = $1
         RETURNING *`,
        [parsed.data.name, parsed.data.description]
      );
      await audit(pool, { actor_type: "admin", action: "eval.suite_create",
        resource_type: "eval_suite", resource_id: res.rows[0].id, result: "success",
        metadata: { name: parsed.data.name, version: res.rows[0].version } });
      return reply.code(201).send(res.rows[0]);
    } catch (err: unknown) {
      if ((err as { code?: string }).code === "23505") {
        return reply.code(409).send({ error: "suite_version_race" });
      }
      throw err;
    }
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
    // Any JSON, not just an object: the replay below turns a string expected
    // value into the scripted output, and a record-only schema made that
    // documented path unreachable through the API.
    expected: z.unknown().default({}),
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
      // The locked flag is re-checked inside the insert, so a case cannot slip
      // into a suite that a run locked between the read above and this write.
      const res = await pool.query(
        `INSERT INTO eval_cases (suite_id, name, input_payload, expected, assertions, exec_config)
         SELECT $1,$2,$3::jsonb,$4::jsonb,$5::jsonb,$6::jsonb
          WHERE EXISTS (SELECT 1 FROM eval_suites WHERE id = $1 AND NOT locked)
         RETURNING *`,
        [id, c.name, JSON.stringify(c.input_payload), JSON.stringify(c.expected),
         JSON.stringify(c.assertions), JSON.stringify(c.exec_config)]
      );
      if (!res.rows[0]) return reply.code(409).send({ error: "suite_locked" });
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
      // Lock the suite row while snapshotting its cases, so the dataset this
      // run executes is exactly the one it locked.
      await client.query("BEGIN");
      const suite = await client.query("SELECT * FROM eval_suites WHERE id = $1 FOR UPDATE", [id]);
      if (!suite.rows[0]) {
        await client.query("ROLLBACK");
        return reply.code(404).send({ error: "suite_not_found" });
      }
      const cases = await client.query("SELECT * FROM eval_cases WHERE suite_id = $1 ORDER BY name", [id]);
      if (!cases.rows.length) {
        await client.query("ROLLBACK");
        return reply.code(400).send({ error: "suite_empty" });
      }

      await client.query("UPDATE eval_suites SET locked = true WHERE id = $1", [id]);
      await client.query("COMMIT");
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
          // Cases authored with input_payload/expected and no explicit exec
          // config still replay deterministically: a string expected value
          // becomes the scripted output, and the input rides the run spans.
          if (exec.output === undefined && typeof c.expected === "string") exec.output = c.expected;
          if (exec.input === undefined) exec.input = c.input_payload as string | undefined;
          const out = await executeCase(client, workspaceId, agent.rows[0].id,
            cfg.agent_name, exec, cfg.model);
          // Unknown costs cannot count against the cap, which turns the cap
          // into a no-op exactly when spend is unknown. Stop and name the
          // reason instead of running the whole locked dataset unguarded while
          // reporting a cap that never fired.
          spent += out.costMicro ?? 0;
          if (out.costMicro == null && cfg.cost_cap_micro > 0) {
            stopped = `cost unknown for ${cfg.model}; cost cap not enforceable`;
            break;
          }
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
      const passed = results.filter((r) => r.passed).length;
      await audit(pool, { actor_type: "admin", action: "eval.run",
        resource_type: "eval_run", resource_id: evalRun.id, result: status,
        metadata: { suite: suite.rows[0].name, trials: cfg.trials, stopped } });
      void notify(workspaceId, "eval.completed",
        { eval_run_id: evalRun.id, suite: suite.rows[0].name, status,
          passed, total: results.length });
      return reply.code(201).send({ eval_run: { ...evalRun, status }, results, stopped });
    } finally {
      client.release();
    }
  });

  app.get("/v1/evaluations/runs/:id", async (req, reply) => {
    const { id } = req.params as { id: string };
    const run = await pool.query(
      `SELECT er.*, a.workspace_id FROM eval_runs er
       LEFT JOIN agents a ON a.id = er.agent_id WHERE er.id = $1`, [id]);
    // Runs whose agent lives elsewhere read as missing. Suites and cases
    // stay shared templates with no workspace of their own.
    if (!run.rows[0] || !workspaceAllowed(req.principal, run.rows[0].workspace_id ?? "")) {
      return reply.code(404).send({ error: "eval_run_not_found" });
    }
    const results = await pool.query(
      `SELECT r.*, c.name AS case_name FROM eval_results r
       JOIN eval_cases c ON c.id = r.case_id
       WHERE r.eval_run_id = $1 ORDER BY c.name, r.trial`, [id]
    );
    return { eval_run: run.rows[0], results: results.rows };
  });

  // Compare explicit run ids on pass rate, latency, cost, token usage, and
  // violations. Missing data stays missing: absent costs and tokens do not
  // count as zero.
  app.get("/v1/evaluations/runs/compare", async (req, reply) => {
    const q = req.query as { ids?: string };
    const ids = (q.ids ?? "").split(",").map((s) => s.trim()).filter(Boolean).slice(0, 5);
    if (ids.length < 2) return reply.code(400).send({ error: "need_two_ids" });
    const runs = await pool.query(
      `SELECT er.* FROM eval_runs er LEFT JOIN agents a ON a.id = er.agent_id
       WHERE er.id = ANY($1)${req.principal?.workspaces === "all" ? "" : " AND a.workspace_id = ANY($2)"}`,
      req.principal?.workspaces === "all" ? [ids] : [ids, req.principal?.workspaces ?? []]);
    // Anything outside the caller's workspaces reads as missing, so a
    // compare cannot launder another team's numbers.
    if (runs.rows.length !== ids.length) return reply.code(404).send({ error: "eval_run_not_found" });
    const out = [];
    for (const r of runs.rows) {
      const res = await pool.query("SELECT * FROM eval_results WHERE eval_run_id = $1", [r.id]);
      const lat = res.rows.map((x) => Number(x.latency_ms));
      const denied = await pool.query(
        `SELECT COUNT(*) AS n,
                COUNT(*) FILTER (WHERE s.status = 'denied') AS denied,
                COUNT(*) FILTER (WHERE s.input_tokens IS NOT NULL OR s.output_tokens IS NOT NULL) AS with_usage
           FROM spans s JOIN eval_results e ON e.agent_run_id = s.run_id
          WHERE e.eval_run_id = $1`, [r.id]
      );
      const passed = res.rows.filter((x) => x.passed).length;
      const costs = res.rows.map((x) => (x.cost_micro == null ? null : Number(x.cost_micro)))
        .filter((c): c is number => c !== null);
      const tokens = await pool.query(
        `SELECT SUM(s.input_tokens) AS input_tokens, SUM(s.output_tokens) AS output_tokens
           FROM spans s JOIN eval_results e ON e.agent_run_id = s.run_id
          WHERE e.eval_run_id = $1`, [r.id]
      );
      const num = (v: unknown) => (v == null ? null : Number(v));
      // A partial SUM silently understates. Flag it, so two runs are never
      // compared on numbers that do not cover the same data.
      const spanCount = Number(denied.rows[0]?.n ?? 0);
      const spansWithUsage = Number(denied.rows[0]?.with_usage ?? 0);
      out.push({
        eval_run_id: r.id, agent_name: r.agent_name, config_fingerprint: r.config_fingerprint,
        model: r.model, trials: r.trials, cases: res.rows.length, passed,
        pass_rate: res.rows.length ? passed / res.rows.length : null,
        latency_ms: lat.length
          ? { mean: Math.round(lat.reduce((a, b) => a + b, 0) / lat.length), min: Math.min(...lat), max: Math.max(...lat) }
          : null,
        cost_micro: costs.length ? costs.reduce((a, b) => a + b, 0) : null,
        cost_partial: costs.length > 0 && costs.length !== res.rows.length,
        input_tokens: num(tokens.rows[0].input_tokens),
        output_tokens: num(tokens.rows[0].output_tokens),
        tokens_partial: spanCount > 0 && spansWithUsage > 0 && spansWithUsage !== spanCount,
        // A run whose spans are gone counts as unknown, not as zero.
        violations: spanCount > 0 ? Number(denied.rows[0].denied) : null
      });
    }
    return { runs: out };
  });
}
