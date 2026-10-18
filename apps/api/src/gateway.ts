import Fastify from "fastify";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { PoolClient } from "pg";
import { pool } from "./db.js";
import { audit } from "./audit.js";
import { verifyAuditChain } from "@traceguard/audit-chain";
import {
  argsHash,
  evaluate,
  requestHash,
  sha256Hex,
  stableStringify
} from "./policy.js";
import { loadActivePolicy, rulesFromBundle } from "./policy-bundle.js";
import { callUpstreamTool, checkUpstreamUrlResolved, definitionHash, definitionIssue, discoverTools, pinnedDefinition } from "./upstream.js";
import { hashesEqual, parseKey, seal, tryOpen } from "./seal.js";
import { authHook, scopeClause, workspaceAllowed } from "./auth.js";
import { gatewayAlias, registerMcpRoutes } from "./mcp.js";
import { notify } from "./notify.js";
import { captureRawEnabled, redactDeep, summarizeArgs } from "./redact.js";

const API_KEY = process.env.API_KEY ?? "";
const APPROVER_KEY = process.env.APPROVER_KEY ?? "";
const PORT = Number(process.env.GATEWAY_PORT ?? 8091);
// §9.4: default 15 minutes, hard maximum 60 minutes. Deployments may lower the
// default; nothing may raise the cap without a spec change.
const APPROVAL_TTL_SECONDS = Math.min(Math.max(Number(process.env.APPROVAL_TTL_SECONDS ?? 900), 60), 3600);
// Queue protections, read per request so a deployment (or a test) can tighten
// them without a restart. Defaults are the spec's numbers: 10 pending per
// caller, 100 per project, 5 new requests per caller per minute.
const approvalEnv = (name: string, fallback: number): number => {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n > 0 ? n : fallback;
};
// Same single-origin CORS as the API, for the policy screens.
const DASHBOARD_ORIGIN = process.env.DASHBOARD_ORIGIN ?? "http://localhost:5173";
if (!API_KEY) throw new Error("API_KEY is required");
if (!APPROVER_KEY) throw new Error("APPROVER_KEY is required");
// Pending approval arguments are sealed at rest. The gateway cannot start
// without the key, so there is no silent plaintext mode. Rotation sets the
// previous key alongside: old rows still open, new rows seal with primary.
const ARGS_KEY = parseKey(process.env.APPROVAL_ARGS_KEY ?? "");
const ARGS_KEYS = [
  ARGS_KEY,
  ...((process.env.APPROVAL_ARGS_KEY_PREVIOUS ?? "").trim()
    ? [parseKey(process.env.APPROVAL_ARGS_KEY_PREVIOUS ?? "")]
    : [])
];

// Reads one approval's arguments. New rows unseal with the request id as
// associated data; rows written before sealing stay readable as plaintext.
function storedArgs(row: {
  args_enc: boolean; args: unknown; request_id: string;
}): Record<string, unknown> {
  if (!row.args_enc) return row.args as Record<string, unknown>;
  const envelope = row.args as { sealed?: string };
  if (!envelope || typeof envelope.sealed !== "string") throw new Error("bad sealed envelope");
  return tryOpen(ARGS_KEYS, envelope.sealed, row.request_id);
}

async function defaultWorkspaceId(client: PoolClient): Promise<string> {
  const found = await client.query("SELECT id FROM workspaces WHERE name = 'default'");
  if (found.rows[0]) return found.rows[0].id;
  const created = await client.query("INSERT INTO workspaces (name) VALUES ('default') RETURNING id");
  return created.rows[0].id;
}

// What remains after pending arguments are dropped on a terminal
// transition: a redacted summary, alongside the args hash column.
function safeSummary(row: { args_enc: boolean; args: unknown; request_id: string }): string {
  try {
    return summarizeArgs(storedArgs(row), { captureRaw: captureRawEnabled() });
  } catch {
    return "[unreadable]";
  }
}

// A bounded, redacted summary of an upstream result for the approval record:
// the response may outlive the payload, so cap it and never store unredacted
// content.
function boundedSummary(result: unknown): string {
  const text = stableStringify(redactDeep({ result }));
  return text.length > 512 ? `${text.slice(0, 512)}...` : text;
}

// §11.3 step 3: hard budget limits gate managed operations. Returns the first
// exhausted block budget covering this run or agent, or null. Tool calls do
// not spend the budget themselves; the gate stops work once it is gone.
async function enforceBudget(
  client: PoolClient,
  ctx: { workspace_id: string; run_id: string | null; agent_id: string | null }
): Promise<{ id: string; scope: string; spent_micro: string | number; reserved_micro: string | number; limit_micro: string | number } | null> {
  if (!ctx.run_id && !ctx.agent_id) return null;
  const res = await client.query(
    `SELECT id, scope, spent_micro, reserved_micro, limit_micro FROM budgets
      WHERE workspace_id = $1 AND effect = 'block'
        AND ((scope = 'run' AND ref_id = $2::uuid) OR (scope = 'agent' AND ref_id = $3::uuid))
        AND spent_micro + reserved_micro >= limit_micro
      LIMIT 1`,
    [ctx.workspace_id, ctx.run_id, ctx.agent_id]
  );
  return res.rows[0] ?? null;
}

async function recordDecision(client: PoolClient, d: {
  workspace_id: string; caller: string; server_id: string | null; tool_name: string;
  args_hash: string; decision: string; policy_id?: string | null; policy_version?: number | null;
  // The exact signed policy version this decision evaluated (§8.5).
  policy_version_id?: string | null;
  matched?: unknown[]; reason?: string; approval_id?: string | null;
  // Section 14's policy-decision budget, measured from the start of handling
  // the call to the moment the decision is recorded. The upstream round trip
  // it excludes is excluded by construction: the value is read before
  // forwarding, not after.
  overhead_ms?: number | null;
}): Promise<void> {
  await client.query(
    `INSERT INTO policy_decisions
       (workspace_id, caller, server_id, tool_name, args_hash, decision,
        policy_id, policy_version, policy_version_id, matched_rules, reason, approval_id, overhead_ms)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13)`,
    [d.workspace_id, d.caller, d.server_id, d.tool_name, d.args_hash, d.decision,
     d.policy_id ?? null, d.policy_version ?? null, d.policy_version_id ?? null,
     JSON.stringify(d.matched ?? []), d.reason ?? "", d.approval_id ?? null,
     d.overhead_ms ?? null]
  );
}

export function buildGateway() {
  const app = Fastify({ logger: true, genReqId: () => randomUUID() });

  app.get("/healthz", async () => ({ ok: true }));

  app.addHook("onRequest", async (req, reply) => {
    reply.header("Access-Control-Allow-Origin", DASHBOARD_ORIGIN);
    reply.header("Access-Control-Allow-Headers", "authorization, content-type");
    // Browsers reject PUT/DELETE preflights without an explicit method list.
    reply.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    if (req.method === "OPTIONS") return reply.code(204).send();
    // One scoped-auth table for every route. Agent keys carry gateway scope
    // only, so they can never reach the approval decision endpoint no
    // matter how the call is framed; it needs approve scope.
    await authHook(req, reply);
  });

  const serverSchema = z.object({
    name: z.string().min(1).max(128),
    base_url: z.string().url(),
    auth_secret: z.string().max(1024).nullable().optional()
  });

  app.post("/v1/servers", async (req, reply) => {
    const parsed = serverSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_server" });
    const urlCheck = await checkUpstreamUrlResolved(parsed.data.base_url);
    if (!urlCheck.ok) return reply.code(400).send({ error: "unsafe_upstream", reason: urlCheck.reason });
    const client = await pool.connect();
    try {
      const workspaceId = await defaultWorkspaceId(client);
      // The stable alias namespaces every exposed tool (§7.5) and is part of
      // the signed server manifest once bundles land.
      const alias = gatewayAlias(parsed.data.name);
      const res = await client.query(
        `INSERT INTO mcp_servers (workspace_id, name, gateway_alias, base_url, auth_secret)
         VALUES ($1,$2,$3,$4,$5) RETURNING id, workspace_id, name, gateway_alias, base_url, created_at`,
        [workspaceId, parsed.data.name, alias, parsed.data.base_url, parsed.data.auth_secret ?? null]
      );
      await audit(pool, { actor_type: "admin", action: "server.register",
        resource_type: "mcp_server", resource_id: res.rows[0].id,
        result: "success", metadata: { name: parsed.data.name } });
      return reply.code(201).send(res.rows[0]);
    } catch (err: unknown) {
      if ((err as { code?: string }).code === "23505") {
        return reply.code(409).send({ error: "server_name_taken" });
      }
      throw err;
    } finally {
      client.release();
    }
  });

  app.get("/v1/servers", async (req) => {
    // auth_secret is never selected here, so reads cannot leak it.
    const params: unknown[] = [];
    const scope = scopeClause(req.principal, params, "workspace_id");
    const res = await pool.query(
      `SELECT id, workspace_id, name, gateway_alias, base_url, created_at FROM mcp_servers
       ${scope ? `WHERE ${scope}` : ""} ORDER BY created_at DESC`, params
    );
    return { items: res.rows };
  });

  app.post("/v1/servers/:id/discover", async (req, reply) => {
    const { id } = req.params as { id: string };
    const client = await pool.connect();
    try {
      const srv = await client.query("SELECT * FROM mcp_servers WHERE id = $1", [id]);
      if (!srv.rows[0]) return reply.code(404).send({ error: "server_not_found" });
      const server = srv.rows[0];
      // Re-validate at discover time: a name that resolved publicly at
      // registration must not quietly point at a private range now.
      const recheck = await checkUpstreamUrlResolved(server.base_url);
      if (!recheck.ok) {
        return reply.code(400).send({ error: "unsafe_upstream", reason: recheck.reason });
      }
      const tools = await discoverTools(server.base_url, server.auth_secret);
      const rejected: { name: string; reason: string }[] = [];
      const pinned: string[] = [];
      const changed: string[] = [];
      await client.query("BEGIN");
      for (const t of tools) {
        const issue = definitionIssue(t);
        if (issue) {
          // §7.5: an unsafe or oversized definition is never pinned. If one
          // was pinned before, quarantine it — the upstream no longer serves
          // what was reviewed, so the old pin must not stay callable.
          rejected.push({ name: t.name, reason: issue });
          const prior = await client.query(
            `UPDATE server_tools SET quarantined=true, quarantine_reason=$3, updated_at=now()
              WHERE server_id=$1 AND tool_name=$2 AND quarantined=false
              RETURNING tool_name`,
            [id, t.name, issue]
          );
          if (prior.rows[0]) {
            await audit(client, { actor_type: "system", action: "tool.quarantined",
              resource_type: "server_tool", resource_id: `${id}/${t.name}`,
              result: "quarantine", metadata: { reason: issue } });
          }
          await audit(client, { actor_type: "system", action: "tool.definition_rejected",
            resource_type: "server_tool", resource_id: `${id}/${t.name}`,
            result: "rejected", metadata: { reason: issue } });
          continue;
        }
        const hash = definitionHash(t);
        const definition = pinnedDefinition(t);
        const existing = await client.query(
          "SELECT definition_hash FROM server_tools WHERE server_id = $1 AND tool_name = $2",
          [id, t.name]
        );
        if (!existing.rows[0]) {
          await client.query(
            `INSERT INTO server_tools
               (server_id, tool_name, description, input_schema, definition, definition_hash)
             VALUES ($1,$2,$3,$4::jsonb,$5::jsonb,$6)`,
            [id, t.name, t.description ?? "", JSON.stringify(t.inputSchema), JSON.stringify(definition), hash]
          );
          pinned.push(t.name);
          await audit(client, { actor_type: "system", action: "tool.pinned",
            resource_type: "server_tool", resource_id: `${id}/${t.name}`,
            result: "success", metadata: { definition_hash: hash } });
        } else if (existing.rows[0].definition_hash !== hash) {
          // Upstream changed the tool definition: quarantine until reviewed.
          // The old definition is kept so the UI can show the field-level
          // diff; re-approval records a new version instead of rewriting it.
          await client.query(
            `UPDATE server_tools SET description=$3, input_schema=$4::jsonb,
               previous_definition=definition, previous_hash=definition_hash,
               definition=$5::jsonb, definition_hash=$6, definition_version=definition_version+1,
               quarantined=true, quarantine_reason='definition changed', updated_at=now()
             WHERE server_id=$1 AND tool_name=$2`,
            [id, t.name, t.description ?? "", JSON.stringify(t.inputSchema),
             JSON.stringify(definition), hash]
          );
          changed.push(t.name);
          await audit(client, { actor_type: "system", action: "tool.definition_changed",
            resource_type: "server_tool", resource_id: `${id}/${t.name}`,
            result: "quarantine",
            metadata: { previous_hash: existing.rows[0].definition_hash, definition_hash: hash } });
          await audit(client, { actor_type: "system", action: "tool.quarantined",
            resource_type: "server_tool", resource_id: `${id}/${t.name}`,
            result: "quarantine", metadata: { reason: "definition changed" } });
        }
      }
      await client.query("COMMIT");
      const listed = await client.query(
        `SELECT server_id, tool_name, description, input_schema, definition, previous_definition,
                definition_hash, previous_hash, definition_version, quarantined, quarantine_reason, updated_at
           FROM server_tools WHERE server_id = $1 ORDER BY tool_name`,
        [id]
      );
      await audit(pool, { actor_type: "admin", action: "server.discover",
        resource_type: "mcp_server", resource_id: id, result: "success",
        metadata: { tool_count: tools.length, pinned, changed, rejected: rejected.map((r) => r.name) } });
      return { tools: listed.rows, pinned, changed, rejected };
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      // Never swallow the cause: the caller gets a stable code, the operator
      // gets the reason in the log.
      req.log.error({ err }, "tool discovery failed");
      return reply.code(502).send({ error: "upstream_unreachable" });
    } finally {
      client.release();
    }
  });

  app.put("/v1/servers/:sid/tools/:tool/quarantine", async (req, reply) => {
    const { sid, tool } = req.params as { sid: string; tool: string };
    const parsed = z.object({ quarantined: z.boolean() }).safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_body" });
    // Un-quarantining is the human review step: the definition is marked as
    // reviewed, but it still executes only once a signed bundle activates
    // its pin (run policy-publisher publish). Clearing the reason is what
    // tells the publisher this pin carries a current review.
    const res = await pool.query(
      `UPDATE server_tools SET quarantined=$3, quarantine_reason=$4, updated_at=now()
        WHERE server_id=$1 AND tool_name=$2
        RETURNING tool_name, quarantined, definition_version, definition_hash`,
      [sid, tool, parsed.data.quarantined, parsed.data.quarantined ? "quarantined by reviewer" : null]
    );
    if (!res.rows[0]) return reply.code(404).send({ error: "tool_not_found" });
    await audit(pool, { actor_type: "admin", action: "tool.reapprove",
      resource_type: "server_tool", resource_id: `${sid}/${tool}`,
      result: "success", metadata: { quarantined: parsed.data.quarantined } });
    return res.rows[0];
  });

  const policySchema = z.object({
    name: z.string().min(1).max(128),
    enabled: z.boolean().default(true),
    priority: z.number().int().default(0),
    agent_id: z.string().uuid().nullable().optional(),
    server_id: z.string().uuid().nullable().optional(),
    tool_name: z.string().max(128).nullable().optional(),
    effect: z.enum(["allow", "deny", "require_approval"]),
    conditions: z.record(z.unknown()).default({})
  });

  app.post("/v1/policies", async (req, reply) => {
    const parsed = policySchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_policy" });
    const client = await pool.connect();
    try {
      const workspaceId = await defaultWorkspaceId(client);
      const p = parsed.data;
      const res = await client.query(
        `INSERT INTO policies
           (workspace_id, name, enabled, priority, agent_id, server_id, tool_name, effect, conditions)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb) RETURNING *`,
        [workspaceId, p.name, p.enabled, p.priority, p.agent_id ?? null,
         p.server_id ?? null, p.tool_name ?? null, p.effect, JSON.stringify(p.conditions)]
      );
      await audit(pool, { actor_type: "admin", action: "policy.create",
        resource_type: "policy", resource_id: res.rows[0].id, result: "success",
        metadata: { name: p.name, effect: p.effect, version: 1 } });
      return reply.code(201).send(res.rows[0]);
    } finally {
      client.release();
    }
  });

  app.get("/v1/policies", async (req) => {
    const q = req.query as { server_id?: string; all?: string };
    const params: unknown[] = [];
    const where = ["superseded_by IS NULL"];
    if (q.server_id) {
      params.push(q.server_id);
      where.push(`server_id = $${params.length}`);
    }
    if (q.all === "true") where.shift();
    const scope = scopeClause(req.principal, params, "workspace_id");
    if (scope) where.push(scope);
    const res = await pool.query(
      `SELECT * FROM policies ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY priority DESC, created_at DESC`,
      params
    );
    return { items: res.rows };
  });

  app.put("/v1/policies/:id", async (req, reply) => {
    const { id } = req.params as { id: string };
    const parsed = policySchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_policy" });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      // Locked so the "is this rule still live" check and the version insert
      // are one unit. Read outside the transaction, two concurrent updates
      // both find a live row and both insert a new version, leaving the rule
      // with two live heads and a version an operator believes was retired.
      const old = await client.query("SELECT * FROM policies WHERE id = $1 FOR UPDATE", [id]);
      if (!old.rows[0]) {
        await client.query("ROLLBACK");
        return reply.code(404).send({ error: "policy_not_found" });
      }
      if (old.rows[0].superseded_by) {
        await client.query("ROLLBACK");
        return reply.code(409).send({ error: "policy_superseded" });
      }
      const p = parsed.data;
      const next = await client.query(
        `INSERT INTO policies
           (workspace_id, name, enabled, priority, agent_id, server_id, tool_name,
            effect, conditions, version, previous_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11) RETURNING *`,
        [old.rows[0].workspace_id, p.name, p.enabled, p.priority, p.agent_id ?? null,
         p.server_id ?? null, p.tool_name ?? null, p.effect,
         JSON.stringify(p.conditions), old.rows[0].version + 1, id]
      );
      await client.query("UPDATE policies SET superseded_by = $2 WHERE id = $1",
        [id, next.rows[0].id]);
      await client.query("COMMIT");
      await audit(pool, { actor_type: "admin", action: "policy.update",
        resource_type: "policy", resource_id: next.rows[0].id, result: "success",
        metadata: { previous_id: id, version: next.rows[0].version } });
      return next.rows[0];
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  });

  const callSchema = z.object({
    server_id: z.string().uuid(),
    tool: z.string().min(1).max(128),
    arguments: z.record(z.unknown()).default({}),
    agent_name: z.string().max(128).optional(),
    caller: z.string().max(128).optional(),
    request_id: z.string().max(128).optional(),
    approval_id: z.string().uuid().optional(),
    // Attribution the caller supplies, like `caller` itself; see
    // docs/security.md for what that does and does not prove.
    agent_id: z.string().uuid().optional(),
    // When a run is named, the gateway writes its own denials into that run's
    // trace, so denied calls show up next to failed ones (FR-005).
    run_id: z.string().uuid().optional(),
    span_id: z.string().uuid().optional()
  });

  // A blocked call still belongs in the run trace: one span with the denied
  // status the trace view and the eval violations counter look for.
  async function recordDeniedSpan(
    client: PoolClient,
    ctx: { run_id?: string; span_id?: string },
    serverId: string,
    tool: string,
    reason: string
  ): Promise<void> {
    if (!ctx.run_id) return;
    try {
      await client.query(
        `INSERT INTO spans
           (id, run_id, event_id, operation_type, name, started_at, status, error_type, attributes)
         VALUES ($1,$2,$3,'tool.invocation',$4,$5,'denied','policy_denied',$6::jsonb)
         ON CONFLICT (id) DO NOTHING`,
        [ctx.span_id ?? randomUUID(), ctx.run_id, `gw-${randomUUID()}`, tool,
         new Date().toISOString(), JSON.stringify(redactDeep({ server_id: serverId, tool, reason }, { captureRaw: true }))]
      );
    } catch {
      // The denial stands even when the trace write cannot land.
    }
  }

  async function forward(
    client: PoolClient,
    server: { id: string; base_url: string; auth_secret: string | null; workspace_id: string },
    tool: string,
    args: Record<string, unknown>,
    caller: string,
    decisionMeta: { approval_id?: string | null; policy_id?: string | null; policy_version?: number | null;
      policy_version_id?: string | null; matched?: unknown[]; overheadMs?: number }
  ): Promise<unknown> {
    // Gateway fails closed: any upstream or policy error denies, never allows.
    // Re-validate before every forward; a failure surfaces through the
    // caller's catch as 502 so the call fails closed instead of reaching a
    // rebinding host.
    const urlRecheck = await checkUpstreamUrlResolved(server.base_url);
    if (!urlRecheck.ok) {
      // The call never leaves, and the decision trail records why so the
      // console can explain the failure next to the allow rules.
      await recordDecision(client, {
        workspace_id: server.workspace_id, caller, server_id: server.id, tool_name: tool,
        args_hash: sha256Hex(stableStringify(args)), decision: "error",
        policy_id: decisionMeta.policy_id, policy_version: decisionMeta.policy_version,
        policy_version_id: decisionMeta.policy_version_id,
        matched: decisionMeta.matched, reason: `upstream fails validation: ${urlRecheck.reason}`,
        approval_id: decisionMeta.approval_id ?? null, overhead_ms: decisionMeta.overheadMs ?? null
      });
      await audit(pool, { actor_type: "agent", actor_id: caller, action: "tool.execute",
        resource_type: "mcp_server", resource_id: server.id, result: "failed",
        metadata: { tool, error: urlRecheck.reason } });
      throw new Error(`upstream fails validation: ${urlRecheck.reason}`);
    }
    let result: unknown;
    try {
      result = await callUpstreamTool(server.base_url, server.auth_secret, tool, args);
    } catch (err) {
      // Allow-shaped decision, failed call: the trail keeps both the intent
      // and the failure so the console can explain the eventual 502.
      const detail = err instanceof Error ? err.message : String(err);
      await recordDecision(client, {
        workspace_id: server.workspace_id, caller, server_id: server.id, tool_name: tool,
        args_hash: sha256Hex(stableStringify(args)), decision: "error",
        policy_id: decisionMeta.policy_id, policy_version: decisionMeta.policy_version,
        policy_version_id: decisionMeta.policy_version_id,
        matched: decisionMeta.matched, reason: `upstream error: ${detail}`,
        approval_id: decisionMeta.approval_id ?? null, overhead_ms: decisionMeta.overheadMs ?? null
      });
      await audit(pool, { actor_type: "agent", actor_id: caller, action: "tool.execute",
        resource_type: "mcp_server", resource_id: server.id, result: "failed",
        metadata: { tool, error: detail } });
      throw err;
    }
    await recordDecision(client, {
      workspace_id: server.workspace_id, caller, server_id: server.id, tool_name: tool,
      args_hash: sha256Hex(stableStringify(args)), decision: decisionMeta.approval_id ? "approved_retry" : "allow",
      policy_id: decisionMeta.policy_id, policy_version: decisionMeta.policy_version,
      policy_version_id: decisionMeta.policy_version_id,
      matched: decisionMeta.matched, reason: decisionMeta.approval_id ? "approved" : "allowed",
      approval_id: decisionMeta.approval_id ?? null, overhead_ms: decisionMeta.overheadMs ?? null
    });
    await audit(pool, { actor_type: "agent", actor_id: caller, action: "tool.execute",
      resource_type: "server_tool", resource_id: `${server.id}/${tool}`, result: "allowed" });
    return result;
  }

  app.post("/v1/gateway/tools/call", async (req, reply) => {
    // Section 14's budget covers what the gateway itself adds to a tool call,
    // so the clock starts when the request arrives and is read before anything
    // is forwarded. The upstream round trip is excluded by construction.
    const t0 = performance.now();
    const overheadMs = () => Math.round(performance.now() - t0);
    const parsed = callSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_call" });
    const { server_id, tool, arguments: args } = parsed.data;
    const caller = parsed.data.caller ?? parsed.data.agent_name ?? "agent";
    const client = await pool.connect();
    try {
      const srv = await client.query("SELECT * FROM mcp_servers WHERE id = $1", [server_id]);
      if (!srv.rows[0]) {
        await audit(pool, { actor_type: "agent", actor_id: caller, action: "tool.execute",
          resource_type: "server_tool", resource_id: `${server_id}/${tool}`, result: "unknown_server" });
        return reply.code(404).send({ error: "server_not_found" });
      }
      const server = srv.rows[0];

      if (!workspaceAllowed(req.principal, server.workspace_id)) {
        return reply.code(403).send({ error: "workspace_forbidden", workspace_id: server.workspace_id });
      }

      // §13.3 fails closed: no verified signed policy version, no protected
      // call. The gate runs before anything else measures the request, and
      // its denial is recorded like any other.
      const policyLoad = await loadActivePolicy(client, server.workspace_id);
      if (!policyLoad.ok) {
        const reason = `policy unavailable: ${policyLoad.reason}`;
        await recordDecision(client, { workspace_id: server.workspace_id, caller,
          server_id, tool_name: tool, args_hash: argsHash(args as Record<string, unknown>),
          decision: "deny", reason, overhead_ms: overheadMs() });
        await audit(pool, { actor_type: "agent", actor_id: caller, action: "tool.execute",
          resource_type: "server_tool", resource_id: `${server_id}/${tool}`, result: "denied",
          metadata: { reason: "policy_unavailable", detail: policyLoad.reason } });
        await recordDeniedSpan(client, parsed.data, server.id, tool, reason);
        return reply.code(503).send({ error: "policy_unavailable", reason: policyLoad.reason });
      }
      const policy = policyLoad.policy;

      // The server itself must be in the signed manifest: a registered row is
      // a draft, only the manifest makes it connectable (§7.4).
      const manifestServer = policy.bundle.servers.find((s) => s.server_id === server.id);
      if (!manifestServer || manifestServer.base_url !== server.base_url) {
        const reason = "server is not in the active signed policy";
        await recordDecision(client, { workspace_id: server.workspace_id, caller, server_id,
          tool_name: tool, args_hash: argsHash(args as Record<string, unknown>), decision: "deny", reason,
          policy_version_id: policy.policy_version_id, overhead_ms: overheadMs() });
        await audit(pool, { actor_type: "agent", actor_id: caller, action: "tool.execute",
          resource_type: "server_tool", resource_id: `${server_id}/${tool}`, result: "denied",
          metadata: { reason: "server_not_in_policy" } });
        await recordDeniedSpan(client, parsed.data, server.id, tool, reason);
        return reply.code(403).send({ error: "tool_blocked", reason });
      }

      const toolRow = await client.query(
        "SELECT * FROM server_tools WHERE server_id = $1 AND tool_name = $2", [server_id, tool]
      );
      if (!toolRow.rows[0] || toolRow.rows[0].quarantined) {
        const reason = toolRow.rows[0] ? "tool quarantined" : "unknown tool";
        await recordDecision(client, { workspace_id: server.workspace_id, caller,
          server_id, tool_name: tool, args_hash: argsHash(args as Record<string, unknown>),
          decision: "deny", reason, policy_version_id: policy.policy_version_id,
          overhead_ms: overheadMs() });
        await audit(pool, { actor_type: "agent", actor_id: caller, action: "tool.execute",
          resource_type: "server_tool", resource_id: `${server_id}/${tool}`, result: "denied" });
        // Alerts never block the denial they report.
        void notify(server.workspace_id, "tool.denied",
          { caller, server_id, tool, reason: toolRow.rows[0] ? "quarantined" : "unknown" });
        await recordDeniedSpan(client, parsed.data, server.id, tool, reason);
        // A held approval for a tool that has since been quarantined dies
        // with the tool: no execution, no return to the queue.
        if (parsed.data.approval_id && toolRow.rows[0]?.quarantined) {
          const prior = await client.query(
            "SELECT * FROM approvals WHERE id = $1 AND status = 'approved'",
            [parsed.data.approval_id]
          );
          if (prior.rows[0]) {
            await client.query(
              `UPDATE approvals SET status='tool_quarantined', terminal_at=now(), args='{}'::jsonb,
                 args_enc=false, args_summary=$2 WHERE id=$1 AND status='approved'`,
              [prior.rows[0].id, safeSummary(prior.rows[0])]
            );
            await audit(pool, { actor_type: "agent", actor_id: caller, action: "approval.tool_quarantined",
              resource_type: "approval", resource_id: prior.rows[0].id, result: "deny" });
          }
        }
        return reply.code(403).send({ error: "tool_blocked", reason: "unknown or quarantined tool" });
      }

      // The pin manifest: a tool executes only when the definition the signed
      // policy activated is the one the upstream serves now. A definition
      // that changed after publication, or was never published, blocks the
      // call (§7.5, §13.3).
      const pin = policy.bundle.pins.find((p) => p.server_id === server.id && p.tool_name === tool);
      const pinIssue = !pin
        ? "tool is not in the active signed policy"
        : pin.definition_hash !== toolRow.rows[0].definition_hash
          ? "tool definition changed since it was published"
          : null;
      if (pinIssue) {
        await recordDecision(client, { workspace_id: server.workspace_id, caller, server_id,
          tool_name: tool, args_hash: argsHash(args as Record<string, unknown>), decision: "deny",
          reason: pinIssue, policy_version_id: policy.policy_version_id, overhead_ms: overheadMs() });
        await audit(pool, { actor_type: "agent", actor_id: caller, action: "tool.execute",
          resource_type: "server_tool", resource_id: `${server_id}/${tool}`, result: "denied",
          metadata: { reason: "pin_not_active" } });
        void notify(server.workspace_id, "tool.denied",
          { caller, server_id, tool, reason: pinIssue });
        await recordDeniedSpan(client, parsed.data, server.id, tool, pinIssue);
        // A held approval for a pin that is no longer active is dead with it.
        if (parsed.data.approval_id) {
          const prior = await client.query(
            "SELECT * FROM approvals WHERE id = $1 AND status = 'approved'",
            [parsed.data.approval_id]
          );
          if (prior.rows[0]) {
            await client.query(
              `UPDATE approvals SET status='policy_invalidated', terminal_at=now(), decision_reason=$2,
                 args='{}'::jsonb, args_enc=false, args_summary=$3 WHERE id=$1 AND status='approved'`,
              [prior.rows[0].id, `invalidated: ${pinIssue}`, safeSummary(prior.rows[0])]
            );
            await audit(pool, { actor_type: "agent", actor_id: caller, action: "approval.policy_invalidated",
              resource_type: "approval", resource_id: prior.rows[0].id, result: "deny",
              metadata: { reason: pinIssue } });
          }
        }
        return reply.code(403).send({ error: "tool_blocked", reason: pinIssue });
      }

      // Policy evaluation runs before any approval handling: an approval
      // issued earlier must never override a deny rule added since (§11.3,
      // "approval must not override an unconditional deny"). Retries are
      // re-evaluated against the current policy set, not the set that
      // existed when the approval was issued.
      const rules = rulesFromBundle(policy.bundle);
      const verdict = evaluate(rules, {
        caller, agent_id: parsed.data.agent_id ?? null, server_id, tool_name: tool,
        args: args as Record<string, unknown>
      });
      const callArgsHash = argsHash(args as Record<string, unknown>);

      if (verdict.decision === "deny") {
        await recordDecision(client, { workspace_id: server.workspace_id, caller, server_id,
          tool_name: tool, args_hash: callArgsHash, decision: "deny",
          policy_id: verdict.rule?.id ?? null, policy_version: verdict.rule?.version ?? null,
          policy_version_id: policy.policy_version_id,
          matched: verdict.matched, reason: verdict.reason,
          approval_id: parsed.data.approval_id ?? null, overhead_ms: overheadMs() });
        await audit(pool, { actor_type: "agent", actor_id: caller, action: "tool.execute",
          resource_type: "server_tool", resource_id: `${server_id}/${tool}`, result: "denied",
          metadata: { rule: verdict.rule?.name ?? null } });
        // An approval held for this call is dead on arrival: a newly
        // applicable deny invalidates it instead of letting it wait for TTL.
        if (parsed.data.approval_id) {
          const prior = await client.query(
            "SELECT * FROM approvals WHERE id = $1 AND status = 'approved'",
            [parsed.data.approval_id]
          );
          if (prior.rows[0]) {
            await client.query(
              `UPDATE approvals SET status='policy_invalidated', terminal_at=now(), decision_reason=$2,
                 args='{}'::jsonb, args_enc=false, args_summary=$3 WHERE id=$1 AND status='approved'`,
              [prior.rows[0].id, `invalidated: ${verdict.reason}`, safeSummary(prior.rows[0])]
            );
            await audit(pool, { actor_type: "agent", actor_id: caller, action: "approval.policy_invalidated",
              resource_type: "approval", resource_id: prior.rows[0].id, result: "deny",
              metadata: { rule: verdict.rule?.name ?? null } });
          }
        }
        void notify(server.workspace_id, "tool.denied",
          { caller, server_id, tool, rule: verdict.rule?.name ?? null, reason: verdict.reason });
        await recordDeniedSpan(client, parsed.data, server.id, tool, verdict.reason);
        return reply.code(403).send({ error: "tool_blocked", reason: verdict.reason });
      }

      // §11.3 step 3: hard budget limits gate managed operations. Tool calls
      // do not spend the budget themselves, but once a block budget covering
      // this run or agent is fully exhausted, the gateway stops forwarding
      // and records which budget stopped the call.
      const exhausted = await enforceBudget(client, {
        workspace_id: server.workspace_id,
        run_id: parsed.data.run_id ?? null,
        agent_id: parsed.data.agent_id ?? null
      });
      if (exhausted) {
        const reason = `budget exhausted (${exhausted.scope} ${exhausted.id})`;
        await recordDecision(client, { workspace_id: server.workspace_id, caller, server_id,
          tool_name: tool, args_hash: callArgsHash, decision: "deny",
          policy_version_id: policy.policy_version_id, matched: verdict.matched, reason,
          approval_id: parsed.data.approval_id ?? null, overhead_ms: overheadMs() });
        await audit(pool, { actor_type: "agent", actor_id: caller, action: "tool.execute",
          resource_type: "server_tool", resource_id: `${server_id}/${tool}`, result: "denied",
          metadata: { budget_id: exhausted.id, scope: exhausted.scope } });
        void notify(server.workspace_id, "budget.exceeded",
          { budget_id: exhausted.id, scope: exhausted.scope,
            spent_micro: Number(exhausted.spent_micro) + Number(exhausted.reserved_micro),
            limit_micro: Number(exhausted.limit_micro) });
        await recordDeniedSpan(client, parsed.data, server.id, tool, reason);
        return reply.code(403).send({ error: "budget_exceeded", budget_id: exhausted.id,
          scope: exhausted.scope, limit_micro: Number(exhausted.limit_micro) });
      }

      // Approval retry: the client presents the durable approval for this
      // exact call. Everything up to the committed EXECUTING transition runs
      // in one transaction — DB-time expiry, binding, consume-time
      // re-evaluation, the claim and the execution-intent audit event.
      if (parsed.data.approval_id) {
        await client.query("BEGIN");
        const ap = await client.query(
          "SELECT *, (expires_at < now()) AS ttl_expired FROM approvals WHERE id = $1 FOR UPDATE",
          [parsed.data.approval_id]
        );
        if (!ap.rows[0]) {
          await client.query("ROLLBACK");
          return reply.code(404).send({ error: "approval_not_found" });
        }
        const approval = ap.rows[0];
        if (approval.status === "claimed" || approval.status === "executing") {
          await client.query("ROLLBACK");
          return reply.code(409).send({ error: "approval_in_progress", status: approval.status });
        }
        if (approval.status === "pending") {
          if (!approval.ttl_expired) {
            await client.query("ROLLBACK");
            return reply.code(202).send({ approval_id: approval.id, status: "pending",
              expires_at: approval.expires_at });
          }
          await client.query(
            `UPDATE approvals SET status='expired', terminal_at=now(), args='{}'::jsonb,
               args_enc=false, args_summary=$2 WHERE id=$1 AND status='pending'`,
            [approval.id, safeSummary(approval)]
          );
          await recordDecision(client, { workspace_id: server.workspace_id, caller,
            server_id, tool_name: tool, args_hash: callArgsHash,
            policy_version_id: policy.policy_version_id,
            decision: "deny", reason: "approval expired", approval_id: approval.id,
            overhead_ms: overheadMs() });
          await audit(client, { actor_type: "agent", actor_id: caller, action: "approval.expired",
            resource_type: "approval", resource_id: approval.id, result: "deny" });
          await client.query("COMMIT");
          return reply.code(410).send({ error: "approval_expired" });
        }
        if (approval.status !== "approved") {
          // Terminal state: report it, never dispatch again.
          await client.query("ROLLBACK");
          const http = ["rejected", "policy_invalidated", "tool_quarantined"].includes(approval.status) ? 403 : 410;
          const note = approval.status === "outcome_unknown"
            ? { note: "The upstream action may have executed." } : {};
          return reply.code(http).send({ error: `approval_${approval.status}`,
            status: approval.status, ...note });
        }
        if (approval.ttl_expired) {
          await client.query(
            `UPDATE approvals SET status='expired', terminal_at=now(), args='{}'::jsonb,
               args_enc=false, args_summary=$2 WHERE id=$1 AND status='approved'`,
            [approval.id, safeSummary(approval)]
          );
          await recordDecision(client, { workspace_id: server.workspace_id, caller,
            server_id, tool_name: tool, args_hash: callArgsHash,
            policy_version_id: policy.policy_version_id,
            decision: "deny", reason: "approval expired", approval_id: approval.id,
            overhead_ms: overheadMs() });
          await audit(client, { actor_type: "agent", actor_id: caller, action: "approval.expired",
            resource_type: "approval", resource_id: approval.id, result: "deny" });
          await client.query("COMMIT");
          return reply.code(410).send({ error: "approval_expired" });
        }
        const want = requestHash(caller, server_id, tool, args, approval.request_id, String(toolRow.rows[0].definition_hash));
        if (!hashesEqual(want, approval.args_hash) || approval.caller !== caller) {
          await recordDecision(client, { workspace_id: server.workspace_id, caller,
            server_id, tool_name: tool, args_hash: callArgsHash,
            policy_version_id: policy.policy_version_id,
            decision: "deny", reason: "approval binding mismatch", approval_id: approval.id,
            overhead_ms: overheadMs() });
          // A replay or a transplanted approval is the most tell-tale event
          // this endpoint sees; it belongs in the tamper-evident trail.
          await audit(client, { actor_type: "agent", actor_id: caller, action: "approval.binding_mismatch",
            resource_type: "approval", resource_id: approval.id, result: "deny",
            metadata: { server_id, tool } });
          await client.query("COMMIT");
          return reply.code(403).send({ error: "approval_binding_mismatch" });
        }
        // Read the sealed arguments before claiming, so an unreadable row
        // fails closed without burning the single-use approval.
        let stored: Record<string, unknown>;
        try {
          stored = storedArgs(approval);
        } catch {
          await client.query("ROLLBACK");
          return reply.code(500).send({ error: "approval_unreadable" });
        }
        // Consume-time full re-evaluation (§9.2 rule 4), in the same
        // transaction as the claim: the *current* signed policy is loaded
        // again, so a deny, a dropped pin, or a quarantined tool added after
        // the approval invalidates it and nothing is dispatched. Prior human
        // approval never overrides a current deny.
        const freshLoad = await loadActivePolicy(client, server.workspace_id);
        if (!freshLoad.ok) {
          // Fail closed without consuming: the approval stays approved and a
          // retry can proceed once policy storage is healthy again.
          await client.query("ROLLBACK");
          return reply.code(503).send({ error: "policy_unavailable", reason: freshLoad.reason });
        }
        const freshPolicy = freshLoad.policy;
        const toolNow = await client.query(
          "SELECT quarantined, definition_hash FROM server_tools WHERE server_id = $1 AND tool_name = $2",
          [server_id, tool]
        );
        if (!toolNow.rows[0] || toolNow.rows[0].quarantined) {
          await client.query(
            `UPDATE approvals SET status='tool_quarantined', terminal_at=now(), args='{}'::jsonb,
               args_enc=false, args_summary=$2 WHERE id=$1 AND status='approved'`,
            [approval.id, summarizeArgs(stored, { captureRaw: captureRawEnabled() })]
          );
          await audit(client, { actor_type: "agent", actor_id: caller, action: "approval.tool_quarantined",
            resource_type: "approval", resource_id: approval.id, result: "deny" });
          await client.query("COMMIT");
          return reply.code(403).send({ error: "tool_quarantined", approval_id: approval.id });
        }
        // The pin that was active when the approval was issued must still be
        // the active pin now, or the approval authorized a definition the
        // signed policy no longer carries.
        const freshPin = freshPolicy.bundle.pins.find(
          (p) => p.server_id === server.id && p.tool_name === tool
        );
        if (!freshPin || freshPin.definition_hash !== toolNow.rows[0].definition_hash) {
          const why = "the tool pin is no longer active in the signed policy";
          await client.query(
            `UPDATE approvals SET status='policy_invalidated', terminal_at=now(), decision_reason=$2,
               args='{}'::jsonb, args_enc=false, args_summary=$3 WHERE id=$1 AND status='approved'`,
            [approval.id, `invalidated: ${why}`,
             summarizeArgs(stored, { captureRaw: captureRawEnabled() })]
          );
          await recordDecision(client, { workspace_id: server.workspace_id, caller, server_id,
            tool_name: tool, args_hash: callArgsHash, decision: "deny",
            policy_version_id: freshPolicy.policy_version_id,
            reason: `approval invalidated: ${why}`,
            approval_id: approval.id, overhead_ms: overheadMs() });
          await audit(client, { actor_type: "agent", actor_id: caller, action: "approval.policy_invalidated",
            resource_type: "approval", resource_id: approval.id, result: "deny",
            metadata: { reason: why } });
          await client.query("COMMIT");
          return reply.code(403).send({ error: "policy_invalidated", reason: why });
        }
        const recheck = evaluate(rulesFromBundle(freshPolicy.bundle), {
          caller, agent_id: parsed.data.agent_id ?? null, server_id, tool_name: tool,
          args: stored
        });
        if (recheck.decision === "deny") {
          await client.query(
            `UPDATE approvals SET status='policy_invalidated', terminal_at=now(), decision_reason=$2,
               args='{}'::jsonb, args_enc=false, args_summary=$3 WHERE id=$1 AND status='approved'`,
            [approval.id, `invalidated: ${recheck.reason}`,
             summarizeArgs(stored, { captureRaw: captureRawEnabled() })]
          );
          await recordDecision(client, { workspace_id: server.workspace_id, caller, server_id,
            tool_name: tool, args_hash: callArgsHash, decision: "deny",
            policy_id: recheck.rule?.id ?? null, policy_version: recheck.rule?.version ?? null,
            policy_version_id: freshPolicy.policy_version_id,
            matched: recheck.matched,
            reason: `approval invalidated by current policy: ${recheck.reason}`,
            approval_id: approval.id, overhead_ms: overheadMs() });
          await audit(client, { actor_type: "agent", actor_id: caller, action: "approval.policy_invalidated",
            resource_type: "approval", resource_id: approval.id, result: "deny",
            metadata: { rule: recheck.rule?.name ?? null } });
          await client.query("COMMIT");
          return reply.code(403).send({ error: "policy_invalidated", reason: recheck.reason });
        }
        // Claim (compare-and-swap) and execution intent. The committed
        // EXECUTING row is the linearization point: concurrent retries lose
        // the CAS, and a crash before this COMMIT leaves the approval
        // APPROVED because nothing was dispatched by construction.
        const claimed = await client.query(
          `UPDATE approvals SET status='executing', claim_id=$2, execution_started_at=now(),
             args='{}'::jsonb, args_enc=false, args_summary=$3
            WHERE id=$1 AND status='approved' RETURNING id`,
          [approval.id, randomUUID(), summarizeArgs(stored, { captureRaw: captureRawEnabled() })]
        );
        if (!claimed.rows[0]) {
          await client.query("ROLLBACK");
          return reply.code(409).send({ error: "approval_in_progress" });
        }
        await audit(client, { actor_type: "agent", actor_id: caller, action: "approval.execution_intent",
          resource_type: "approval", resource_id: approval.id, result: "executing",
          metadata: { server_id, tool } });
        await client.query("COMMIT");
        // Only now may anything leave for the upstream (§9.2 rule 6).
        let result: unknown;
        try {
          result = await forward(client, server, tool, stored,
            caller, { approval_id: approval.id, policy_version_id: freshPolicy.policy_version_id, overheadMs: overheadMs() });
        } catch (err) {
          // The gateway cannot prove the upstream did not act: burn the
          // approval into a visible ambiguity, never auto-retry.
          await pool.query(
            `UPDATE approvals SET status='outcome_unknown', terminal_at=now(),
               outcome_summary=$2 WHERE id=$1`,
            [approval.id, "The upstream action may have executed."]
          );
          await audit(pool, { actor_type: "agent", actor_id: caller, action: "approval.outcome_unknown",
            resource_type: "approval", resource_id: approval.id, result: "unknown",
            metadata: { detail: err instanceof Error ? err.message : String(err) } });
          return reply.code(502).send({ error: "outcome_unknown", approval_id: approval.id,
            note: "The upstream action may have executed." });
        }
        const upstreamError = !!result && typeof result === "object" &&
          (result as { isError?: unknown }).isError === true;
        const bounded = redactDeep({ result });
        await pool.query(
          `UPDATE approvals SET status='response_received', response_is_error=$2,
             terminal_at=now(), outcome_summary=$3, outcome_hash=$4 WHERE id=$1`,
          [approval.id, upstreamError, boundedSummary(result), sha256Hex(stableStringify(bounded))]
        );
        await audit(pool, { actor_type: "agent", actor_id: caller, action: "approval.response_received",
          resource_type: "approval", resource_id: approval.id,
          result: upstreamError ? "error" : "success" });
        return { result, approval_id: approval.id };
      }

      if (verdict.decision === "need_approval") {
        // §9.4 queue protections: active-pending caps and a creation rate
        // limit, counted against DB time. Limits only tighten (§9.4).
        const pendingCaller = await client.query(
          "SELECT count(*)::int AS n FROM approvals WHERE caller = $1 AND workspace_id = $2 AND status IN ('pending','approved')",
          [caller, server.workspace_id]
        );
        const pendingWs = await client.query(
          "SELECT count(*)::int AS n FROM approvals WHERE workspace_id = $1 AND status IN ('pending','approved')",
          [server.workspace_id]
        );
        const recent = await client.query(
          "SELECT count(*)::int AS n FROM approvals WHERE caller = $1 AND workspace_id = $2 AND requested_at > now() - interval '60 seconds'",
          [caller, server.workspace_id]
        );
        if (pendingCaller.rows[0].n >= approvalEnv("APPROVAL_MAX_PENDING_PER_CALLER", 10) ||
            pendingWs.rows[0].n >= approvalEnv("APPROVAL_MAX_PENDING_PER_WORKSPACE", 100)) {
          return reply.code(429).send({ error: "approval_limit",
            pending_caller: pendingCaller.rows[0].n, pending_workspace: pendingWs.rows[0].n });
        }
        if (recent.rows[0].n >= approvalEnv("APPROVAL_RATE_PER_MINUTE", 5)) {
          return reply.code(429).send({ error: "approval_rate_limited", retry_after_seconds: 60 });
        }
        const requestId = parsed.data.request_id ?? `req-${randomUUID()}`;
        const hash = requestHash(caller, server_id, tool, args as Record<string, unknown>, requestId, String(toolRow.rows[0].definition_hash));
        const expiresAt = new Date(Date.now() + APPROVAL_TTL_SECONDS * 1000).toISOString();
        const sealed = seal(ARGS_KEY, args as Record<string, unknown>, requestId);
        const ap = await client.query(
          `INSERT INTO approvals
             (request_id, workspace_id, caller, server_id, tool_name, args_hash, args, args_enc, requested_by, expires_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10)
           ON CONFLICT (request_id) DO NOTHING RETURNING id, request_id, status, expires_at`,
          [requestId, server.workspace_id, caller, server_id, tool, hash,
           JSON.stringify({ sealed }), true, caller, expiresAt]
        );
        const row = ap.rows[0] ?? (await client.query("SELECT id, request_id, status, expires_at FROM approvals WHERE request_id=$1", [requestId])).rows[0];
        await recordDecision(client, { workspace_id: server.workspace_id, caller, server_id,
          tool_name: tool, args_hash: callArgsHash, decision: "need_approval",
          policy_id: verdict.rule?.id ?? null, policy_version: verdict.rule?.version ?? null,
          policy_version_id: policy.policy_version_id,
          matched: verdict.matched, reason: verdict.reason, approval_id: row.id,
          overhead_ms: overheadMs() });
        await audit(pool, { actor_type: "agent", actor_id: caller, action: "approval.request",
          resource_type: "approval", resource_id: row.id, result: "pending" });
        void notify(server.workspace_id, "approval.requested",
          { approval_id: row.id, caller, server_id, tool });
        reply.header("Cache-Control", "no-store");
        return reply.code(202).send({ approval_id: row.id, status: row.status, expires_at: row.expires_at });
      }

      try {
        const result = await forward(client, server, tool, args as Record<string, unknown>, caller,
          { policy_id: verdict.rule?.id ?? null, policy_version: verdict.rule?.version ?? null,
            policy_version_id: policy.policy_version_id, matched: verdict.matched, overheadMs: overheadMs() });
        return { result };
      } catch {
        return reply.code(502).send({ error: "upstream_failed" });
      }
    } finally {
      client.release();
    }
  });

  app.get("/v1/approvals", async (req, reply) => {
    reply.header("Cache-Control", "no-store");
    const q = req.query as { status?: string; limit?: string };
    const limit = Math.min(Math.max(Number(q.limit ?? 50), 1), 200);
    // Lazy recovery sweep, driven by DB time (§9.2 rules 2, 7, 9): pending
    // past TTL expires; executing without a terminal outcome past the recovery
    // window becomes OUTCOME_UNKNOWN. Claimed-without-executing cannot
    // persist: claim and execution intent commit in one transaction.
    const stale = await pool.query(
      "SELECT * FROM approvals WHERE status = 'pending' AND expires_at < now()"
    );
    for (const row of stale.rows) {
      await pool.query(
        `UPDATE approvals SET status='expired', terminal_at=now(), args='{}'::jsonb,
           args_enc=false, args_summary=$2 WHERE id=$1 AND status='pending'`,
        [row.id, safeSummary(row)]
      );
      await audit(pool, { actor_type: "system", action: "approval.expired",
        resource_type: "approval", resource_id: row.id, result: "expired" });
    }
    const stuck = await pool.query(
      `SELECT id FROM approvals
        WHERE status = 'executing'
          AND execution_started_at < now() - ($1::int * interval '1 second')`,
      [approvalEnv("APPROVAL_EXECUTION_TIMEOUT_SECONDS", 300)]
    );
    for (const row of stuck.rows) {
      await pool.query(
        `UPDATE approvals SET status='outcome_unknown', terminal_at=now(),
           outcome_summary=$2 WHERE id=$1 AND status='executing'`,
        [row.id, "The upstream action may have executed."]
      );
      await audit(pool, { actor_type: "system", action: "approval.outcome_unknown",
        resource_type: "approval", resource_id: row.id, result: "unknown",
        metadata: { reason: "recovery timeout" } });
    }
    const params: unknown[] = [];
    const where: string[] = [];
    if (q.status) {
      params.push(q.status);
      where.push(`status = $${params.length}`);
    }
    // Approvers open plaintext here, so the list itself must already be
    // confined to their workspaces.
    const ascope = scopeClause(req.principal, params, "workspace_id");
    if (ascope) where.push(ascope);
    params.push(limit);
    const res = await pool.query(
      `SELECT * FROM approvals ${where.length ? "WHERE " + where.join(" AND ") : ""}
       ORDER BY requested_at DESC LIMIT $${params.length}`, params
    );
    // Approvers open plaintext here, and only approvers. This route needs
    // just 'read', which members and agent keys hold, so a caller without the
    // approve scope gets the row with the arguments withheld rather than the
    // seal's contents.
    const mayOpenSeal = !!req.principal &&
      (req.principal.scopes.includes("approve") || req.principal.scopes.includes("admin"));
    const items = res.rows.map((row) => {
      if (!row.args_enc) return row;
      if (!mayOpenSeal) return { ...row, args: {}, args_withheld: true };
      try {
        return { ...row, args: storedArgs(row) };
      } catch {
        return { ...row, args: {}, decrypt_error: true };
      }
    });
    return { items };
  });

  app.post("/v1/approvals/:id/decision", async (req, reply) => {
    reply.header("Cache-Control", "no-store");
    const { id } = req.params as { id: string };
    const parsed = z.object({ approved: z.boolean(), reason: z.string().max(512).default("") }).safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_decision" });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      // Locked for the rest of the decision: the expiry check and the status
      // transition cannot be interleaved with a concurrent decide or consume.
      const ap = await client.query("SELECT * FROM approvals WHERE id = $1 FOR UPDATE", [id]);
      if (!ap.rows[0]) {
        await client.query("ROLLBACK");
        return reply.code(404).send({ error: "approval_not_found" });
      }
      const approval = ap.rows[0];
      if (approval.status !== "pending") {
        await client.query("ROLLBACK");
        return reply.code(409).send({ error: "approval_not_pending", status: approval.status });
      }
      // Approvals from other workspaces read as missing here too.
      if (!workspaceAllowed(req.principal, approval.workspace_id)) {
        await client.query("ROLLBACK");
        return reply.code(404).send({ error: "approval_not_found" });
      }
      if (new Date(approval.expires_at).getTime() < Date.now()) {
        const expired = await client.query(
          `UPDATE approvals SET status='expired', args='{}'::jsonb, args_enc=false, args_summary=$2
            WHERE id=$1 AND status='pending' RETURNING id`,
          [id, safeSummary(approval)]
        );
        await client.query("COMMIT");
        if (!expired.rows[0]) {
          return reply.code(409).send({ error: "approval_decided_elsewhere" });
        }
        return reply.code(410).send({ error: "approval_expired" });
      }
      // Single decision wins: only one row can leave pending state. Denying
      // drops the sealed arguments immediately, keeping only the redacted
      // summary and hash; approving keeps them until the retry consumes them.
      // decided_by records the principal, not a constant: an approval trail
      // that cannot name the human who decided it answers nothing.
      const actor = req.principal?.userId ??
        (req.principal?.kind === "env" ? "env_key" : "unknown");
      const updated = await client.query(
        `UPDATE approvals SET status=$2, decided_by=$6, decided_at=now(), decision_reason=$3,
           args = CASE WHEN $4::boolean THEN '{}'::jsonb ELSE args END,
           args_enc = CASE WHEN $4::boolean THEN false ELSE args_enc END,
           args_summary = CASE WHEN $4::boolean THEN $5 ELSE args_summary END
         WHERE id=$1 AND status='pending' RETURNING *`,
        [id, parsed.data.approved ? "approved" : "rejected", parsed.data.reason,
         !parsed.data.approved, parsed.data.approved ? null : safeSummary(approval), actor]
      );
      if (!updated.rows[0]) {
        await client.query("ROLLBACK");
        return reply.code(409).send({ error: "approval_decided_elsewhere" });
      }
      await client.query("COMMIT");
      await audit(pool, { actor_type: "approver", actor_id: actor, action: "approval.decide",
        resource_type: "approval", resource_id: id,
        result: parsed.data.approved ? "approved" : "rejected",
        metadata: { reason: parsed.data.reason } });
      void notify(approval.workspace_id, "approval.decided",
        { approval_id: id, result: parsed.data.approved ? "approved" : "denied" });
      return updated.rows[0];
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  });

  app.get("/v1/decisions", async (req) => {
    const q = req.query as { server_id?: string; tool?: string; limit?: string };
    const limit = Math.min(Math.max(Number(q.limit ?? 50), 1), 200);
    const params: unknown[] = [];
    const where: string[] = [];
    if (q.server_id) {
      params.push(q.server_id);
      where.push(`server_id = $${params.length}`);
    }
    if (q.tool) {
      params.push(q.tool);
      where.push(`tool_name = $${params.length}`);
    }
    const dscope = scopeClause(req.principal, params, "workspace_id");
    if (dscope) where.push(dscope);
    params.push(limit);
    const res = await pool.query(
      `SELECT * FROM policy_decisions ${where.length ? "WHERE " + where.join(" AND ") : ""}
       ORDER BY timestamp DESC LIMIT $${params.length}`, params
    );
    return { items: res.rows };
  });

  app.get("/v1/audit-events", async (req) => {
    const q = req.query as { action?: string; limit?: string };
    const limit = Math.min(Math.max(Number(q.limit ?? 50), 1), 200);
    const params: unknown[] = [];
    const where: string[] = [];
    if (q.action) {
      params.push(q.action);
      where.push(`action = $${params.length}`);
    }
    params.push(limit);
    const res = await pool.query(
      `SELECT * FROM audit_events ${where.length ? "WHERE " + where.join(" AND ") : ""}
       ORDER BY timestamp DESC LIMIT $${params.length}`, params
    );
    return { items: res.rows };
  });

  // §10: verification recomputes every event hash and checks every link. The
  // table is append-only at the database layer (migration 022), so any
  // mutation it detects came from something with schema rights — which is
  // exactly the party an operator-controlled checkpoint exists to catch.
  app.post("/v1/audit/verify", async (req) => {
    const q = (req.query ?? {}) as { limit?: string };
    const limit = Math.min(Math.max(Number(q.limit ?? 200_000), 1), 1_000_000);
    const res = await pool.query(
      `SELECT id, timestamp, actor_type, actor_id, action, resource_type, resource_id,
              result, metadata, prev_hash, hash
         FROM audit_events ORDER BY timestamp ASC, id ASC LIMIT $1`,
      [limit + 1]
    );
    const truncated = res.rows.length > limit;
    const rows = res.rows.slice(0, limit) as Parameters<typeof verifyAuditChain>[0];
    const verification = verifyAuditChain(rows);
    // A bounded read cannot prove the tail it never saw; say so instead of
    // reporting a prefix as the whole chain.
    return {
      ...verification,
      truncated,
      checked_to: rows.length > 0 ? rows[rows.length - 1].hash : null
    };
  });

  // The immutable signed policy editions, newest first, with whether the
  // active pointer currently cites each one. Draft rules live in /v1/policies;
  // only a published version governs enforcement.
  app.get("/v1/policy-versions", async (req) => {
    const params: unknown[] = [];
    const limit = Math.min(Math.max(Number((req.query as { limit?: string }).limit ?? 50), 1), 200);
    const scope = scopeClause(req.principal, params, "pv.workspace_id");
    params.push(limit);
    const res = await pool.query(
      `SELECT pv.id, pv.workspace_id, pv.version, pv.content_hash, pv.previous_version_hash,
              pv.published_at, pv.published_by, pv.signing_key_id,
              pk.key_id, (pk.retired_at IS NOT NULL) AS key_retired,
              (ac.policy_version_id = pv.id) AS active
         FROM policy_versions pv
         JOIN policy_signing_keys pk ON pk.id = pv.signing_key_id
         LEFT JOIN active_config ac ON ac.workspace_id = pv.workspace_id
        ${scope ? `WHERE ${scope}` : ""}
        ORDER BY pv.version DESC LIMIT $${params.length}`,
      params
    );
    return { items: res.rows };
  });

  // Agent-facing MCP Streamable HTTP profile (§7.2), separate from the REST
  // control and dashboard routes.
  registerMcpRoutes(app);

  return app;
}

const isMain = process.argv[1]?.endsWith("gateway.js") || process.argv[1]?.endsWith("gateway.ts");
if (isMain) {
  buildGateway().listen({ port: PORT, host: "0.0.0.0" });
}
