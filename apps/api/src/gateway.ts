import Fastify, { type FastifyInstance } from "fastify";
import { validateAgainstSchema } from "./schema-check.js";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { Pool, PoolClient } from "pg";
import { pool } from "./db.js";
import { audit, type AuditEntry } from "./audit.js";
import { projectAllowed, projectClause } from "./project-scope.js";
import { verifyAuditChain, verifyCheckpoint, type CheckpointPayload } from "@traceguard/audit-chain";
import {
  argsHash,
  evaluate,
  pathEnforcementIssue,
  requestHash,
  sha256Hex,
  stableStringify
} from "./policy.js";
import { loadActivePolicy, rulesFromBundle } from "./policy-bundle.js";
import { callUpstreamTool, checkUpstreamUrlResolved } from "./upstream.js";
import { resolveSecretRef } from "./secret-ref.js";
import { hashesEqual, parseKey, seal, tryOpen } from "./seal.js";
import { authHook, scopeClause, workspaceAllowed } from "./auth.js";
import { assertProductionAuth, oauthConfigFromEnv, protectedResourceMetadata } from "./oauth.js";
import { registerMcpRoutes } from "./mcp.js";
import { notify } from "./notify.js";
import { captureRawEnabled, redactDeep, summarizeArgs } from "./redact.js";

const API_KEY = process.env.API_KEY ?? "";
const APPROVER_KEY = process.env.APPROVER_KEY ?? "";
const PORT = Number(process.env.GATEWAY_PORT ?? 8091);
// Â§9: the human approval surface listens separately from the agent-facing
// gateway. The dashboard talks to this port; agent credentials never do.
const CONTROL_PORT = Number(process.env.GATEWAY_CONTROL_PORT ?? 8093);
// Â§9.4: default 15 minutes, hard maximum 60 minutes. Deployments may lower the
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

// Â§11.3 step 3: hard budget limits gate managed operations. Returns the first
// exhausted block budget covering this run or agent, or null. A tool call does
// not spend the budget, but it may hold a configurable reservation while the
// upstream call is in flight; the gate stops work once the limit is gone.
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

type BudgetExhausted = {
  id: string;
  scope: string;
  spent_micro: string | number;
  reserved_micro: string | number;
  limit_micro: string | number;
};

type ToolCallHoldOutcome = {
  reservation_ids: string[];
  budget_ids: string[];
  exhausted: BudgetExhausted | null;
};

// The hold amount and TTL are read per request so a deployment (or a test) can
// enable, disable, or shrink the reservation without a restart. Zero preserves
// the historical behavior: the gate only checks already-exhausted budgets.
const toolCallHoldMicro = (): number =>
  approvalEnv("TOOL_CALL_RESERVATION_MICRO", 0);
const toolCallHoldTtlSeconds = (): number =>
  approvalEnv("TOOL_CALL_RESERVATION_TTL_SECONDS", 300);

async function releaseToolCallHolds(
  db: Pool | PoolClient, workspaceId: string, reservationIds: string[]
): Promise<number> {
  if (reservationIds.length === 0) return 0;
  const res = await db.query(
    "SELECT gateway_release_tool_call($1,$2) AS released",
    [workspaceId, reservationIds]
  );
  return Number(res.rows[0]?.released ?? 0);
}

// Project-scoped audit entries carry both the workspace and the project. The
// append function rejects a project that does not belong to the workspace.
async function auditForScope(
  db: Parameters<typeof audit>[0],
  server: { workspace_id: string; project_id: string },
  entry: AuditEntry
): Promise<void> {
  await audit(db, {
    ...entry,
    workspace_id: entry.workspace_id ?? server.workspace_id,
    project_id: entry.project_id ?? server.project_id
  });
}

async function recordDecision(client: PoolClient, d: {
  workspace_id: string; project_id?: string | null; caller: string; server_id: string | null; tool_name: string;
  args_hash: string; decision: string; policy_id?: string | null; policy_version?: number | null;
  // The exact signed policy version this decision evaluated (Â§8.5).
  policy_version_id?: string | null;
  matched?: unknown[]; reason?: string; approval_id?: string | null;
  // FR-021: trace and request correlation, so the run view can show which
  // decision (and which approval) belongs to which call.
  run_id?: string | null; span_id?: string | null; request_id?: string | null;
  // Section 14's policy-decision budget, measured from the start of handling
  // the call to the moment the decision is recorded. The upstream round trip
  // it excludes is excluded by construction: the value is read before
  // forwarding, not after.
  overhead_ms?: number | null;
}): Promise<void> {
  await client.query(
    `INSERT INTO policy_decisions
       (workspace_id, project_id, caller, server_id, tool_name, args_hash, decision,
        policy_id, policy_version, policy_version_id, matched_rules, reason, approval_id,
        run_id, span_id, request_id, overhead_ms)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13,$14,$15,$16,$17)`,
    [d.workspace_id, d.project_id ?? null, d.caller, d.server_id, d.tool_name,
     d.args_hash, d.decision,
     d.policy_id ?? null, d.policy_version ?? null, d.policy_version_id ?? null,
     JSON.stringify(d.matched ?? []), d.reason ?? "", d.approval_id ?? null,
     d.run_id ?? null, d.span_id ?? null, d.request_id ?? null,
     d.overhead_ms ?? null]
  );
}

export function buildGateway() {
  assertProductionAuth();
  const app = Fastify({ logger: true, genReqId: () => randomUUID() });

  app.get("/healthz", async () => ({ ok: true }));

  // RFC 9728 Â§7.3: how a client learns which authorization server issues
  // tokens for this gateway. Served only in OAuth mode; in the development
  // profile there is no issuer to point at.
  app.get("/.well-known/oauth-protected-resource", async (_req, reply) => {
    const cfg = oauthConfigFromEnv();
    if (!cfg) return reply.code(404).send({ error: "not_found" });
    return protectedResourceMetadata(cfg);
  });

  // RFC 9728 Â§3.1: a path-bearing resource publishes at the path-appended
  // location; clients try that first and fall back to the bare document.
  // Both answer with the same metadata.
  app.get("/.well-known/oauth-protected-resource/mcp", async (_req, reply) => {
    const cfg = oauthConfigFromEnv();
    if (!cfg) return reply.code(404).send({ error: "not_found" });
    return protectedResourceMetadata(cfg);
  });

  app.addHook("onRequest", async (req, reply) => {
    reply.header("Access-Control-Allow-Origin", DASHBOARD_ORIGIN);
    reply.header("Access-Control-Allow-Credentials", "true");
    reply.header("Access-Control-Allow-Headers", "authorization, content-type, x-csrf-token");
    // Browsers reject PUT/DELETE preflights without an explicit method list.
    reply.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    if (req.method === "OPTIONS") return reply.code(204).send();
    // One scoped-auth table for every route. Agent keys carry gateway scope
    // only, so they can never reach the approval decision endpoint no
    // matter how the call is framed; it needs approve scope.
    await authHook(req, reply);
  });

  // The agent network reaches the gateway and nothing else (Â§24, FR-004), but
  // the agent's project-scoped principal may submit telemetry (Â§7). The
  // gateway therefore forwards the fixed ingest path to the API. This is a
  // write-only forward: reads, policy, approvals, and budget endpoints stay
  // off the agent network, and the API still enforces the key, scope, schema,
  // event quota, and dedupe. CONTROL_API_URL is the API service in compose;
  // outside compose it defaults to the local dev port.
  app.post("/v1/ingest/events", async (req, reply) => {
    const apiUrl = (process.env.CONTROL_API_URL ?? "http://127.0.0.1:8090").replace(/\/$/, "");
    try {
      const upstream = await fetch(`${apiUrl}/v1/ingest/events`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(typeof req.headers.authorization === "string"
            ? { authorization: req.headers.authorization }
            : {})
        },
        body: JSON.stringify(req.body ?? {}),
        signal: AbortSignal.timeout(30_000)
      });
      reply.code(upstream.status);
      reply.header("content-type", upstream.headers.get("content-type") ?? "application/json");
      return reply.send(await upstream.text());
    } catch (err) {
      req.log.error({ err }, "ingest forward failed");
      return reply.code(502).send({ error: "ingest_unavailable" });
    }
  });


  const callSchema = z.object({
    server_id: z.string().guid(),
    tool: z.string().min(1).max(128),
    arguments: z.record(z.string(), z.unknown()).default({}),
    agent_name: z.string().max(128).optional(),
    caller: z.string().max(128).optional(),
    request_id: z.string().max(128).optional(),
    approval_id: z.string().guid().optional(),
    // Attribution the caller supplies, like `caller` itself; see
    // docs/security.md for what that does and does not prove.
    agent_id: z.string().guid().optional(),
    // When a run is named, the gateway writes its own denials into that run's
    // trace, so denied calls show up next to failed ones (FR-005).
    run_id: z.string().guid().optional(),
    span_id: z.string().guid().optional()
  });

  // A blocked call still belongs in the run trace: one span with the denied
  // status the trace view and the eval violations counter look for.
  async function recordDeniedSpan(
    client: PoolClient,
    ctx: { run_id?: string; span_id?: string; request_id?: string; approval_id?: string },
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
         new Date().toISOString(), JSON.stringify(redactDeep({
           server_id: serverId, tool, reason,
           // FR-021: a denied span still points at the decision and the
           // approval it belongs to, so the run view can explain the block.
           request_id: ctx.request_id ?? null, approval_id: ctx.approval_id ?? null
         }, { captureRaw: true }))]
      );
    } catch (err) {
      // A caller can name a run that was never ingested. The foreign-key
      // violation is the only expected failure: the denial still lives in
      // policy_decisions and the audit trail, and a span cannot exist without
      // its run. Every other failure is a real trace-write problem and must
      // stay loud.
      const code = (err as { code?: string }).code;
      if (code === "23503") {
        app.log.debug(`denied-span skipped: run ${ctx.run_id} not found`);
        return;
      }
      app.log.warn(`denied-span write failed: ${(err as Error).message}`);
    }
  }

  async function forward(
    client: PoolClient,
    server: {
      id: string; base_url: string; secret_ref: string | null;
      workspace_id: string; project_id: string;
    },
    tool: string,
    args: Record<string, unknown>,
    caller: string,
    decisionMeta: { approval_id?: string | null; policy_id?: string | null; policy_version?: number | null;
      policy_version_id?: string | null; matched?: unknown[]; overheadMs?: number;
      provenanceRecorded?: boolean;
      // FR-021: the same trace ids the call route attached to its decisions.
      corr?: { run_id: string | null; span_id: string | null; request_id: string | null } }
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
        ...decisionMeta.corr,
        workspace_id: server.workspace_id, caller, server_id: server.id, tool_name: tool,
        args_hash: sha256Hex(stableStringify(args)), decision: "error",
        policy_id: decisionMeta.policy_id, policy_version: decisionMeta.policy_version,
        policy_version_id: decisionMeta.policy_version_id,
        matched: decisionMeta.matched, reason: `upstream fails validation: ${urlRecheck.reason}`,
        approval_id: decisionMeta.approval_id ?? null, overhead_ms: decisionMeta.overheadMs ?? null
      });
      await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "tool.execute",
        resource_type: "mcp_server", resource_id: server.id, result: "failed",
        metadata: { tool, error: urlRecheck.reason } });
      throw new Error(`upstream fails validation: ${urlRecheck.reason}`);
    }
    // Ordinary allows must be durable before the side effect. Approved
    // retries already recorded their decision and execution intent in the
    // linearization transaction; recording here would duplicate that row.
    // The audit write must land now, not after the upstream returns: a
    // database failure has to stop the call, not leave an executed tool with
    // no durable decision evidence (section 15, NFR-007).
    if (!decisionMeta.provenanceRecorded) {
      await recordDecision(client, {
        ...decisionMeta.corr,
        workspace_id: server.workspace_id, caller, server_id: server.id, tool_name: tool,
        args_hash: sha256Hex(stableStringify(args)), decision: decisionMeta.approval_id ? "approved_retry" : "allow",
        policy_id: decisionMeta.policy_id, policy_version: decisionMeta.policy_version,
        policy_version_id: decisionMeta.policy_version_id,
        matched: decisionMeta.matched, reason: decisionMeta.approval_id ? "approved" : "allowed",
        approval_id: decisionMeta.approval_id ?? null, overhead_ms: decisionMeta.overheadMs ?? null
      });
      await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "policy.allow",
        resource_type: "server_tool", resource_id: `${server.id}/${tool}`, result: "allow",
        metadata: { approval_id: decisionMeta.approval_id ?? null } });
      decisionMeta.provenanceRecorded = true;
    }
    let result: unknown;
    try {
      // §7.4: resolve the reference at the last responsible moment. A missing
      // environment variable or unreadable file aborts the call; it never
      // falls back to an unauthenticated request.
      const authSecret = resolveSecretRef(server.secret_ref);
      result = await callUpstreamTool(server.base_url, authSecret, tool, args);
    } catch (err) {
      // Allow-shaped decision, failed call: the trail keeps both the intent
      // and the failure so the console can explain the eventual 502.
      const detail = err instanceof Error ? err.message : String(err);
      await recordDecision(client, {
        ...decisionMeta.corr,
        workspace_id: server.workspace_id, caller, server_id: server.id, tool_name: tool,
        args_hash: sha256Hex(stableStringify(args)), decision: "error",
        policy_id: decisionMeta.policy_id, policy_version: decisionMeta.policy_version,
        policy_version_id: decisionMeta.policy_version_id,
        matched: decisionMeta.matched, reason: `upstream error: ${detail}`,
        approval_id: decisionMeta.approval_id ?? null, overhead_ms: decisionMeta.overheadMs ?? null
      });
      await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "tool.execute",
        resource_type: "mcp_server", resource_id: server.id, result: "failed",
        metadata: { tool, error: detail } });
      throw err;
    }
    // The allow decision and its §10.3 audit event were written before the
    // dispatch above, so the trail exists even if the upstream call now fails.
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
    // Â§9.1: the caller in the binding hash is the authenticated principal,
    // never a request field. Static environment keys carry no subject, so
    // only for them does the body value stand in.
    const caller = req.principal?.userId ?? parsed.data.caller ?? parsed.data.agent_name ?? "agent";
    // FR-021: the trace ids (when the caller supplies them) ride on every
    // decision row this call records â€” including denials that never reach an
    // approval â€” so the run view can show which decision belongs to which span.
    const corr = {
      run_id: parsed.data.run_id ?? null,
      span_id: parsed.data.span_id ?? null,
      request_id: parsed.data.request_id ?? null
    };
    // Tool-call holds are released in the route's finally block. Keeping the
    // ids here means every early return (pending approval, denial, failure)
    // returns the unused headroom without a second code path.
    let heldReservationIds: string[] = [];
    let holdWorkspaceId: string | null = null;
    const client = await pool.connect();
    try {
      const srv = await client.query("SELECT * FROM mcp_servers WHERE id = $1", [server_id]);
      if (!srv.rows[0]) {
        await audit(pool, { actor_type: "agent", actor_id: caller, action: "tool.execute",
          resource_type: "server_tool", resource_id: `${server_id}/${tool}`, result: "unknown_server" });
        return reply.code(404).send({ error: "server_not_found" });
      }
      const server = srv.rows[0];
      holdWorkspaceId = server.workspace_id;

      if (server.disabled_at) {
        const reason = "server disabled";
        await recordDecision(client, { ...corr, workspace_id: server.workspace_id, caller,
          server_id, tool_name: tool, args_hash: argsHash(args as Record<string, unknown>),
          decision: "deny", reason, overhead_ms: overheadMs() });
        await auditForScope(pool, server, { actor_type: "agent", actor_id: caller,
          action: "tool.execute", resource_type: "server_tool",
          resource_id: `${server_id}/${tool}`, result: "denied",
          metadata: { reason: "server_disabled" } });
        await recordDeniedSpan(client, parsed.data, server.id, tool, reason);
        return reply.code(403).send({ error: "server_disabled" });
      }

      if (!workspaceAllowed(req.principal, server.workspace_id)) {
        return reply.code(403).send({ error: "workspace_forbidden", workspace_id: server.workspace_id });
      }
      if (!projectAllowed(req.principal, server.project_id)) {
        return reply.code(403).send({ error: "project_forbidden", project_id: server.project_id });
      }

      // Â§13.3 fails closed: no verified signed policy version, no protected
      // call. The gate runs before anything else measures the request, and
      // its denial is recorded like any other.
      const policyLoad = await loadActivePolicy(client, server.project_id);
      if (!policyLoad.ok) {
        const reason = `policy unavailable: ${policyLoad.reason}`;
        await recordDecision(client, { ...corr, workspace_id: server.workspace_id, caller,
          server_id, tool_name: tool, args_hash: argsHash(args as Record<string, unknown>),
          decision: "deny", reason, overhead_ms: overheadMs() });
        await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "tool.execute",
          resource_type: "server_tool", resource_id: `${server_id}/${tool}`, result: "denied",
          metadata: { reason: "policy_unavailable", detail: policyLoad.reason } });
        await recordDeniedSpan(client, parsed.data, server.id, tool, reason);
        return reply.code(503).send({ error: "policy_unavailable", reason: policyLoad.reason });
      }
      const policy = policyLoad.policy;

      // The server itself must be in the signed manifest: a registered row is
      // a draft, only the manifest makes it connectable (Â§7.4).
      const manifestServer = policy.bundle.servers.find((s) => s.server_id === server.id);
      const inManifest = !!manifestServer && manifestServer.base_url === server.base_url;
      const signedVersion = server.signed_bundle_version == null
        ? null
        : Number(server.signed_bundle_version);
      const secretRefMatches = manifestServer?.secret_ref === undefined
        || manifestServer.secret_ref === server.secret_ref;
      const signedConfigMatches = !!manifestServer
        && manifestServer.base_url === server.base_url
        && signedVersion === policy.bundle.version
        && manifestServer.alias === server.gateway_alias
        && secretRefMatches;
      if (!signedConfigMatches) {
        const reason = inManifest
          ? "server configuration does not match the active signed policy"
          : "server is not in the active signed policy";
        await recordDecision(client, { ...corr, workspace_id: server.workspace_id, caller, server_id,
          tool_name: tool, args_hash: argsHash(args as Record<string, unknown>), decision: "deny", reason,
          policy_version_id: policy.policy_version_id, overhead_ms: overheadMs() });
        await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "tool.execute",
          resource_type: "server_tool", resource_id: `${server_id}/${tool}`, result: "denied",
          metadata: {
            reason: inManifest ? "server_config_mismatch" : "server_not_in_policy",
            signed_bundle_version: signedVersion,
            policy_version: policy.bundle.version
          } });
        await recordDeniedSpan(client, parsed.data, server.id, tool, reason);
        return reply.code(403).send({ error: "tool_blocked", reason });
      }

      // Â§7.4: the signed manifest says how the gateway authenticates
      // upstream. Published as gateway_secret with no credential to send â€”
      // or as credential-less with a secret still attached â€” fails closed
      // rather than quietly calling the wrong way.
      const wantsSecret = manifestServer.auth_mode === "gateway_secret";
      if (wantsSecret !== !!server.secret_ref) {
        const reason = wantsSecret
          ? "server is published with a gateway_secret credential, but no secret reference is configured"
          : "server is published credential-less, but a secret reference is still attached";
        await recordDecision(client, { ...corr, workspace_id: server.workspace_id, caller, server_id,
          tool_name: tool, args_hash: argsHash(args as Record<string, unknown>), decision: "deny", reason,
          policy_version_id: policy.policy_version_id, overhead_ms: overheadMs() });
        await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "tool.execute",
          resource_type: "server_tool", resource_id: `${server_id}/${tool}`, result: "denied",
          metadata: { reason: "auth_mode_mismatch", auth_mode: manifestServer.auth_mode } });
        await recordDeniedSpan(client, parsed.data, server.id, tool, reason);
        return reply.code(403).send({ error: "tool_blocked", reason });
      }
      const toolRow = await client.query(
        "SELECT * FROM server_tools WHERE server_id = $1 AND tool_name = $2", [server_id, tool]
      );
      if (!toolRow.rows[0] || toolRow.rows[0].quarantined) {
        const reason = toolRow.rows[0] ? "tool quarantined" : "unknown tool";
        await recordDecision(client, { ...corr, workspace_id: server.workspace_id, caller,
          server_id, tool_name: tool, args_hash: argsHash(args as Record<string, unknown>),
          decision: "deny", reason, policy_version_id: policy.policy_version_id,
          overhead_ms: overheadMs() });
        await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "tool.execute",
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
              "SELECT * FROM approval_transition($1,$2,NULL,'',$3)",
              [prior.rows[0].id, "invalidate_approved_tool_quarantined", safeSummary(prior.rows[0])]
            );
            await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "approval.tool_quarantined",
              resource_type: "approval", resource_id: prior.rows[0].id, result: "deny" });
          }
        }
        return reply.code(403).send({ error: "tool_blocked", reason: "unknown or quarantined tool" });
      }

      // Â§8.4/FR-010: the arguments must fit the pinned input schema before
      // anything else spends work on the call â€” the schema the signed policy
      // pinned is the contract the upstream reviewed.
      const definition = toolRow.rows[0].definition as Record<string, unknown> | undefined;
      const inputSchema = (definition?.inputSchema as Record<string, unknown> | undefined) ?? {};
      const argsCheck = validateAgainstSchema(inputSchema, args);
      if (!argsCheck.ok) {
        const reason = `arguments do not match the pinned input schema: ${argsCheck.reason}`;
        await recordDecision(client, { ...corr, workspace_id: server.workspace_id, caller, server_id,
          tool_name: tool, args_hash: argsHash(args as Record<string, unknown>), decision: "deny",
          reason, policy_version_id: policy.policy_version_id, overhead_ms: overheadMs() });
        await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "tool.execute",
          resource_type: "server_tool", resource_id: `${server_id}/${tool}`, result: "denied",
          metadata: { reason: "argument_schema_mismatch", detail: argsCheck.reason } });
        await recordDeniedSpan(client, parsed.data, server.id, tool, reason);
        return reply.code(400).send({ error: "invalid_arguments", reason: argsCheck.reason });
      }

      // The pin manifest: a tool executes only when the definition the signed
      // policy activated is the one the upstream serves now. A definition
      // that changed after publication, or was never published, blocks the
      // call (Â§7.5, Â§13.3).
      const pin = policy.bundle.pins.find((p) => p.server_id === server.id && p.tool_name === tool);
      const pinIssue = !pin
        ? "tool is not in the active signed policy"
        : pin.pin_id !== undefined && pin.pin_id !== toolRow.rows[0].active_pin_id
          ? "tool pin changed since it was published"
          : pin.pin_version !== undefined && pin.pin_version !== toolRow.rows[0].definition_version
            ? "tool pin version changed since it was published"
            : pin.definition_hash !== toolRow.rows[0].definition_hash
              ? "tool definition changed since it was published"
              : null;
      if (pinIssue) {
        await recordDecision(client, { ...corr, workspace_id: server.workspace_id, caller, server_id,
          tool_name: tool, args_hash: argsHash(args as Record<string, unknown>), decision: "deny",
          reason: pinIssue, policy_version_id: policy.policy_version_id, overhead_ms: overheadMs() });
        await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "tool.execute",
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
              "SELECT * FROM approval_transition($1,$2,NULL,$3,$4)",
              [prior.rows[0].id, "invalidate_approved_policy", `invalidated: ${pinIssue}`, safeSummary(prior.rows[0])]
            );
            await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "approval.policy_invalidated",
              resource_type: "approval", resource_id: prior.rows[0].id, result: "deny",
              metadata: { reason: pinIssue } });
          }
        }
        return reply.code(403).send({ error: "tool_blocked", reason: pinIssue });
      }

      // Policy evaluation runs before any approval handling: an approval
      // issued earlier must never override a deny rule added since (Â§11.3,
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
        await recordDecision(client, { ...corr, workspace_id: server.workspace_id, caller, server_id,
          tool_name: tool, args_hash: callArgsHash, decision: "deny",
          policy_id: verdict.rule?.id ?? null, policy_version: verdict.rule?.version ?? null,
          policy_version_id: policy.policy_version_id,
          matched: verdict.matched, reason: verdict.reason,
          approval_id: parsed.data.approval_id ?? null, overhead_ms: overheadMs() });
        await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "policy.deny",
          resource_type: "server_tool", resource_id: `${server_id}/${tool}`, result: "deny",
          metadata: { rule: verdict.rule?.name ?? null, reason: verdict.reason } });
        // An approval held for this call is dead on arrival: a newly
        // applicable deny invalidates it instead of letting it wait for TTL.
        if (parsed.data.approval_id) {
          const prior = await client.query(
            "SELECT * FROM approvals WHERE id = $1 AND status = 'approved'",
            [parsed.data.approval_id]
          );
          if (prior.rows[0]) {
            await client.query(
              "SELECT * FROM approval_transition($1,$2,NULL,$3,$4)",
              [prior.rows[0].id, "invalidate_approved_policy", `invalidated: ${verdict.reason}`, safeSummary(prior.rows[0])]
            );
            await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "approval.policy_invalidated",
              resource_type: "approval", resource_id: prior.rows[0].id, result: "deny",
              metadata: { rule: verdict.rule?.name ?? null } });
          }
        }
        void notify(server.workspace_id, "tool.denied",
          { caller, server_id, tool, rule: verdict.rule?.name ?? null, reason: verdict.reason });
        await recordDeniedSpan(client, parsed.data, server.id, tool, verdict.reason);
        return reply.code(403).send({ error: "tool_blocked", reason: verdict.reason });
      }

      // FR-010 / Â§16.3 T9: path_within is enforceable only when the executor
      // attests confinement inside the tool's pinned definition. Checked for
      // every non-deny verdict (allow and require_approval) before any budget
      // or approval work, so an unenforceable path rule fails closed. The
      // gateway string comparison is a pre-check; the executor re-checks the
      // resolved path (realpath, symlinks) itself.
      const pathIssue = pathEnforcementIssue(verdict.rule, definition);
      if (pathIssue) {
        const reason = `path enforcement refused: ${pathIssue}`;
        await recordDecision(client, { ...corr, workspace_id: server.workspace_id, caller, server_id,
          tool_name: tool, args_hash: callArgsHash, decision: "deny",
          policy_id: verdict.rule?.id ?? null, policy_version: verdict.rule?.version ?? null,
          policy_version_id: policy.policy_version_id,
          matched: verdict.matched, reason,
          approval_id: parsed.data.approval_id ?? null, overhead_ms: overheadMs() });
        await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "tool.execute",
          resource_type: "server_tool", resource_id: `${server_id}/${tool}`, result: "denied",
          metadata: { reason: "path_enforcement", detail: pathIssue, rule: verdict.rule?.name ?? null } });
        void notify(server.workspace_id, "tool.denied",
          { caller, server_id, tool, rule: verdict.rule?.name ?? null, reason: pathIssue });
        await recordDeniedSpan(client, parsed.data, server.id, tool, reason);
        return reply.code(403).send({ error: "tool_blocked", reason, code: "path_enforcement" });
      }

      // Â§11.3 step 3: hard budget limits gate managed operations. Tool calls
      // do not spend the budget themselves, but once a block budget covering
      // this run or agent is fully exhausted, the gateway stops forwarding
      // and records which budget stopped the call.
      let exhausted: BudgetExhausted | null = await enforceBudget(client, {
        workspace_id: server.workspace_id,
        run_id: parsed.data.run_id ?? null,
        agent_id: parsed.data.agent_id ?? null
      });
      // The cheap gate above rejects an already-exhausted budget. The
      // reservation procedure then holds headroom for the duration of this
      // call, serialized on the budget rows, so two concurrent calls cannot
      // both spend the same last unit. A zero amount leaves this disabled.
      const holdMicro = toolCallHoldMicro();
      if (!exhausted && holdMicro > 0
          && (parsed.data.run_id || parsed.data.agent_id)) {
        const hold = await client.query(
          "SELECT gateway_reserve_tool_call($1,$2,$3,$4,$5) AS outcome",
          [server.workspace_id, parsed.data.run_id ?? null,
           parsed.data.agent_id ?? null, holdMicro, toolCallHoldTtlSeconds()]
        );
        const outcome = hold.rows[0]?.outcome as ToolCallHoldOutcome | undefined;
        heldReservationIds = outcome?.reservation_ids ?? [];
        if (outcome?.exhausted) {
          exhausted = outcome.exhausted;
        } else if (heldReservationIds.length > 0) {
          try {
            await auditForScope(pool, server, {
              actor_type: "agent", actor_id: caller, action: "budget.reserved",
              resource_type: "budget", resource_id: outcome?.budget_ids?.[0],
              result: "reserved",
              metadata: { tool, server_id, amount_micro: holdMicro,
                reservation_ids: heldReservationIds,
                run_id: parsed.data.run_id ?? null,
                agent_id: parsed.data.agent_id ?? null }
            });
          } catch (err) {
            // A hold with no audit record cannot be reconciled. Return the
            // headroom and fail the call closed.
            try {
              await releaseToolCallHolds(pool, server.workspace_id, heldReservationIds);
            } catch (releaseErr) {
              app.log.warn(`budget hold release failed: ${(releaseErr as Error).message}`);
            }
            heldReservationIds = [];
            throw err;
          }
        }
      }
      if (exhausted) {
        const reason = `budget exhausted (${exhausted.scope} ${exhausted.id})`;
        await recordDecision(client, { ...corr, workspace_id: server.workspace_id, caller, server_id,
          tool_name: tool, args_hash: callArgsHash, decision: "deny",
          policy_version_id: policy.policy_version_id, matched: verdict.matched, reason,
          approval_id: parsed.data.approval_id ?? null, overhead_ms: overheadMs() });
        await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "budget.denied",
          resource_type: "budget", resource_id: exhausted.id, result: "denied",
          metadata: { server_id, tool, scope: exhausted.scope } });
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
      // in one transaction â€” DB-time expiry, binding, consume-time
      // re-evaluation, the claim and the execution-intent audit event.
      if (parsed.data.approval_id) {
        await client.query("BEGIN");
        // No SELECT ... FOR UPDATE here: PostgreSQL requires UPDATE privilege
        // for that lock, and the gateway deliberately has none on approvals.
        // The claim/execute CAS inside approval_transition is the serialization
        // point, so concurrent retries still cannot both dispatch.
        const ap = await client.query(
          "SELECT *, (expires_at < now()) AS ttl_expired FROM approvals WHERE id = $1",
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
            "SELECT * FROM approval_transition($1,$2,NULL,'',$3)",
            [approval.id, "expire_pending", safeSummary(approval)]
          );
          await recordDecision(client, { ...corr, workspace_id: server.workspace_id, caller,
            server_id, tool_name: tool, args_hash: callArgsHash,
            policy_version_id: policy.policy_version_id,
            decision: "deny", reason: "approval expired", approval_id: approval.id,
            overhead_ms: overheadMs() });
          await auditForScope(client, server, { actor_type: "agent", actor_id: caller, action: "approval.expired",
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
            "SELECT * FROM approval_transition($1,$2,NULL,'',$3)",
            [approval.id, "expire_approved", safeSummary(approval)]
          );
          await recordDecision(client, { ...corr, workspace_id: server.workspace_id, caller,
            server_id, tool_name: tool, args_hash: callArgsHash,
            policy_version_id: policy.policy_version_id,
            decision: "deny", reason: "approval expired", approval_id: approval.id,
            overhead_ms: overheadMs() });
          await auditForScope(client, server, { actor_type: "agent", actor_id: caller, action: "approval.expired",
            resource_type: "approval", resource_id: approval.id, result: "deny" });
          await client.query("COMMIT");
          return reply.code(410).send({ error: "approval_expired" });
        }
        const want = requestHash(caller, server_id, tool, args, approval.request_id, String(toolRow.rows[0].definition_hash));
        if (!hashesEqual(want, approval.args_hash) || approval.caller !== caller) {
          await recordDecision(client, { ...corr, workspace_id: server.workspace_id, caller,
            server_id, tool_name: tool, args_hash: callArgsHash,
            policy_version_id: policy.policy_version_id,
            decision: "deny", reason: "approval binding mismatch", approval_id: approval.id,
            overhead_ms: overheadMs() });
          // A replay or a transplanted approval is the most tell-tale event
          // this endpoint sees; it belongs in the tamper-evident trail.
          await auditForScope(client, server, { actor_type: "agent", actor_id: caller, action: "approval.binding_mismatch",
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
        // Consume-time full re-evaluation (Â§9.2 rule 4): the *current* signed
        // policy is loaded again, so a deny, a dropped pin, or a quarantined
        // tool added after the approval invalidates it and nothing is
        // dispatched. Prior human approval never overrides a current deny.
        // This pass fails fast; the binding one runs under the active-config
        // lock at the linearization point below (Â§9.2 rule 5).
        const freshLoad = await loadActivePolicy(client, server.project_id);
        if (!freshLoad.ok) {
          // Fail closed without consuming: the approval stays approved and a
          // retry can proceed once policy storage is healthy again.
          await client.query("ROLLBACK");
          return reply.code(503).send({ error: "policy_unavailable", reason: freshLoad.reason });
        }
        const freshPolicy = freshLoad.policy;
        const toolNow = await client.query(
          `SELECT quarantined, definition_hash, definition, active_pin_id, definition_version
             FROM server_tools WHERE server_id = $1 AND tool_name = $2`,
          [server_id, tool]
        );
        if (!toolNow.rows[0] || toolNow.rows[0].quarantined) {
          await client.query(
            "SELECT * FROM approval_transition($1,'invalidate_approved_tool_quarantined',NULL,'',$2)",
            [approval.id, summarizeArgs(stored, { captureRaw: captureRawEnabled() })]
          );
          await auditForScope(client, server, { actor_type: "agent", actor_id: caller, action: "approval.tool_quarantined",
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
        if (!freshPin
            || (freshPin.pin_id !== undefined && freshPin.pin_id !== toolNow.rows[0].active_pin_id)
            || (freshPin.pin_version !== undefined
              && freshPin.pin_version !== toolNow.rows[0].definition_version)
            || freshPin.definition_hash !== toolNow.rows[0].definition_hash) {
          const why = "the tool pin is no longer active in the signed policy";
          await client.query(
            "SELECT * FROM approval_transition($1,'invalidate_approved_policy',NULL,$2,$3)",
            [approval.id, `invalidated: ${why}`,
             summarizeArgs(stored, { captureRaw: captureRawEnabled() })]
          );
          await recordDecision(client, { ...corr, workspace_id: server.workspace_id, caller, server_id,
            tool_name: tool, args_hash: callArgsHash, decision: "deny",
            policy_version_id: freshPolicy.policy_version_id,
            reason: `approval invalidated: ${why}`,
            approval_id: approval.id, overhead_ms: overheadMs() });
          await auditForScope(client, server, { actor_type: "agent", actor_id: caller, action: "approval.policy_invalidated",
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
            "SELECT * FROM approval_transition($1,'invalidate_approved_policy',NULL,$2,$3)",
            [approval.id, `invalidated: ${recheck.reason}`,
             summarizeArgs(stored, { captureRaw: captureRawEnabled() })]
          );
          await recordDecision(client, { ...corr, workspace_id: server.workspace_id, caller, server_id,
            tool_name: tool, args_hash: callArgsHash, decision: "deny",
            policy_id: recheck.rule?.id ?? null, policy_version: recheck.rule?.version ?? null,
            policy_version_id: freshPolicy.policy_version_id,
            matched: recheck.matched,
            reason: `approval invalidated by current policy: ${recheck.reason}`,
            approval_id: approval.id, overhead_ms: overheadMs() });
          await auditForScope(client, server, { actor_type: "agent", actor_id: caller, action: "approval.policy_invalidated",
            resource_type: "approval", resource_id: approval.id, result: "deny",
            metadata: { rule: recheck.rule?.name ?? null } });
          await client.query("COMMIT");
          return reply.code(403).send({ error: "policy_invalidated", reason: recheck.reason });
        }
        // FR-010: an approval authorizes a call under the policy that was
        // active when it was issued. If the current policy's winning rule
        // carries a path constraint the executor no longer attests (a changed
        // pin) or never attested, the approval dies here.
        const retryPathIssue = pathEnforcementIssue(recheck.rule, toolNow.rows[0].definition);
        if (retryPathIssue) {
          await client.query(
            "SELECT * FROM approval_transition($1,'invalidate_approved_policy',NULL,$2,$3)",
            [approval.id, `invalidated: ${retryPathIssue}`,
             summarizeArgs(stored, { captureRaw: captureRawEnabled() })]
          );
          await recordDecision(client, { ...corr, workspace_id: server.workspace_id, caller, server_id,
            tool_name: tool, args_hash: callArgsHash, decision: "deny",
            policy_id: recheck.rule?.id ?? null, policy_version: recheck.rule?.version ?? null,
            policy_version_id: freshPolicy.policy_version_id, matched: recheck.matched,
            reason: `approval invalidated by path enforcement: ${retryPathIssue}`,
            approval_id: approval.id, overhead_ms: overheadMs() });
          await auditForScope(client, server, { actor_type: "agent", actor_id: caller, action: "approval.policy_invalidated",
            resource_type: "approval", resource_id: approval.id, result: "deny",
            metadata: { reason: retryPathIssue } });
          await client.query("COMMIT");
          return reply.code(403).send({ error: "policy_invalidated", reason: retryPathIssue });
        }
        // Claim (compare-and-swap) with a short lease, committed separately
        // from the execution intent (Â§9.2): a crash after this COMMIT but
        // before the intent leaves a durable CLAIMED row. No dispatch can
        // have happened, so the recovery sweep returns it to APPROVED once
        // the lease expires. Concurrent retries lose the CAS.
        const claimId = randomUUID();
        const claimed = await client.query(
          "SELECT * FROM approval_transition($1,'claim',$2,'','',NULL,NULL,$3)",
          [approval.id, claimId, approvalEnv("APPROVAL_CLAIM_LEASE_SECONDS", 30)]
        );
        if (!claimed.rows[0]) {
          await client.query("ROLLBACK");
          return reply.code(409).send({ error: "approval_in_progress" });
        }
        // Â§10.3: the transition itself is audited inside the transaction that
        // makes it â€” a claim that exists without its event would be a hole
        // in the trail.
        await auditForScope(client, server, { actor_type: "agent", actor_id: caller, action: "approval.claimed",
          resource_type: "approval", resource_id: approval.id, result: "claimed",
          metadata: { server_id, tool, claim_id: claimId } });
        await client.query("COMMIT");

        // The linearization point (Â§9.2 rules 5-6, Â§8.5): everything that
        // authorizes dispatch â€” the active-config lock, the binding
        // re-evaluation, its provenance, and the EXECUTING row itself â€” is
        // decided and recorded in this one transaction, before any byte may
        // leave for the upstream. The lock makes an activation published
        // after the consent decision wait until this transaction commits, so
        // the recorded policy version and matched rules are the ones the
        // dispatch actually ran under. Losing the CAS here means the lease
        // expired and recovery already released the claim.
        await client.query("BEGIN");
        await client.query("SELECT lock_active_config_share($1)", [server.workspace_id]);
        const lastLoad = await loadActivePolicy(client, server.project_id);
        if (!lastLoad.ok) {
          // Nothing may be dispatched without a verdict recorded here; the
          // claim is released so a retry can proceed once policy storage
          // recovers. The lease guard keeps this from racing recovery.
          await client.query(
            "SELECT * FROM approval_transition($1,'release_claim',$2)",
            [approval.id, claimId]
          );
          await auditForScope(client, server, { actor_type: "agent", actor_id: caller, action: "approval.claim_released",
            resource_type: "approval", resource_id: approval.id, result: "approved",
            metadata: { reason: "policy storage unavailable at the linearization point" } });
          await client.query("COMMIT");
          return reply.code(503).send({ error: "policy_unavailable", reason: lastLoad.reason });
        }
        const lastPolicy = lastLoad.policy;
        const toolLast = await client.query(
          `SELECT quarantined, definition_hash, definition, active_pin_id, definition_version
             FROM server_tools WHERE server_id = $1 AND tool_name = $2`,
          [server_id, tool]
        );
        const pinLast = lastPolicy.bundle.pins.find(
          (p) => p.server_id === server.id && p.tool_name === tool
        );
        const lastVerdict = evaluate(rulesFromBundle(lastPolicy.bundle), {
          caller, agent_id: parsed.data.agent_id ?? null, server_id, tool_name: tool,
          args: stored
        });
        // FR-010: the verdict recorded at the linearization point must be one
        // the executor can actually enforce, not just one the gateway matched.
        const lastPathIssue = lastVerdict.decision === "deny"
          ? null
          : pathEnforcementIssue(lastVerdict.rule, toolLast.rows[0]?.definition);
        const lastWhy = !toolLast.rows[0] || toolLast.rows[0].quarantined
          ? "the tool is quarantined"
          : !pinLast
            || (pinLast.pin_id !== undefined && pinLast.pin_id !== toolLast.rows[0].active_pin_id)
            || (pinLast.pin_version !== undefined
              && pinLast.pin_version !== toolLast.rows[0].definition_version)
            || pinLast.definition_hash !== toolLast.rows[0].definition_hash
            ? "the tool pin is no longer active in the signed policy"
            : lastPathIssue
              ? `path enforcement refused: ${lastPathIssue}`
              : lastVerdict.decision === "deny"
                ? lastVerdict.reason
                : null;
        if (lastWhy) {
          const quarantined = !toolLast.rows[0] || !!toolLast.rows[0].quarantined;
          await client.query(
            "SELECT * FROM approval_transition($1,$2,$3,$4,$5)",
            [approval.id, quarantined ? "invalidate_claimed_tool_quarantined" : "invalidate_claimed_policy",
             claimId, `invalidated: ${lastWhy}`,
             summarizeArgs(stored, { captureRaw: captureRawEnabled() })]
          );
          await recordDecision(client, { ...corr, workspace_id: server.workspace_id, caller, server_id,
            tool_name: tool, args_hash: callArgsHash, decision: "deny",
            policy_id: lastVerdict.rule?.id ?? null, policy_version: lastVerdict.rule?.version ?? null,
            policy_version_id: lastPolicy.policy_version_id, matched: lastVerdict.matched,
            reason: `approval invalidated at the linearization point: ${lastWhy}`,
            approval_id: approval.id, overhead_ms: overheadMs() });
          await auditForScope(client, server, { actor_type: "agent", actor_id: caller, action: "approval.policy_invalidated",
            resource_type: "approval", resource_id: approval.id, result: "deny",
            metadata: { reason: lastWhy, at: "linearization point" } });
          await client.query("COMMIT");
          return quarantined
            ? reply.code(403).send({ error: "tool_quarantined", approval_id: approval.id })
            : reply.code(403).send({ error: "policy_invalidated", reason: lastWhy });
        }
        const intent = await client.query(
          "SELECT * FROM approval_transition($1,'execute',$2,'',$3)",
          [approval.id, claimId, summarizeArgs(stored, { captureRaw: captureRawEnabled() })]
        );
        if (!intent.rows[0]) {
          await client.query("ROLLBACK");
          return reply.code(409).send({ error: "approval_claim_lost" });
        }
        // The verdict that authorizes this dispatch is recorded â€” with its
        // policy version and matched rules â€” before the intent commits, so a
        // crash in EXECUTING leaves the provenance behind (Â§9.2 rule 5).
        await recordDecision(client, { ...corr, workspace_id: server.workspace_id, caller, server_id,
          tool_name: tool, args_hash: callArgsHash, decision: "approved_retry",
          policy_id: lastVerdict.rule?.id ?? null, policy_version: lastVerdict.rule?.version ?? null,
          policy_version_id: lastPolicy.policy_version_id, matched: lastVerdict.matched,
          reason: "approved under the consume-time re-evaluation",
          approval_id: approval.id, overhead_ms: overheadMs() });
        await auditForScope(client, server, { actor_type: "agent", actor_id: caller, action: "approval.execution_started",
          resource_type: "approval", resource_id: approval.id, result: "executing",
          metadata: { server_id, tool, claim_id: claimId,
            policy_version_id: lastPolicy.policy_version_id,
            matched_rules: lastVerdict.matched.map((m) => m.id) } });
        await client.query("COMMIT");
        // Only now may anything leave for the upstream (Â§9.2 rule 6).
        let result: unknown;
        try {
          result = await forward(client, server, tool, stored,
            caller, { corr, approval_id: approval.id, policy_version_id: lastPolicy.policy_version_id,
              // The decision trail keeps the linearization-point verdict's
              // rule attribution, not just the version it ran under.
              policy_id: lastVerdict.rule?.id ?? null, policy_version: lastVerdict.rule?.version ?? null,
              matched: lastVerdict.matched, overheadMs: overheadMs(), provenanceRecorded: true });
        } catch (err) {
          // The gateway cannot prove the upstream did not act: burn the
          // approval into a visible ambiguity, never auto-retry. If the
          // recovery sweep already finalized it, that verdict stands â€” the
          // ambiguity is real and the sweep recorded it.
          const burned = await pool.query(
            "SELECT * FROM approval_transition($1,'outcome_unknown',NULL,'',$2)",
            [approval.id, "The upstream action may have executed."]
          );
          if (burned.rows[0]) {
            await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "approval.outcome_unknown",
              resource_type: "approval", resource_id: approval.id, result: "unknown",
              metadata: { detail: err instanceof Error ? err.message : String(err) } });
          }
          return reply.code(502).send({ error: "outcome_unknown", approval_id: approval.id,
            note: "The upstream action may have executed." });
        }
        const upstreamError = !!result && typeof result === "object" &&
          (result as { isError?: unknown }).isError === true;
        const bounded = redactDeep({ result });
        const outcomeHash = sha256Hex(stableStringify(bounded));
        const finalized = await pool.query(
          "SELECT * FROM approval_transition($1,'response_received',NULL,'',$2,$3,$4)",
          [approval.id, boundedSummary(result), upstreamError, outcomeHash]
        );
        if (finalized.rows[0]) {
          await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "approval.response_received",
            resource_type: "approval", resource_id: approval.id,
            result: upstreamError ? "error" : "success",
            metadata: { response_is_error: upstreamError } });
        } else {
          // The recovery sweep finalized this approval while the upstream was
          // still in flight. The response is evidence, not a reset: the
          // approval stays OUTCOME_UNKNOWN until reconciliation closes it.
          await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "approval.response_late",
            resource_type: "approval", resource_id: approval.id,
            result: upstreamError ? "error" : "success",
            metadata: { outcome_hash: outcomeHash,
              note: "arrived after the approval was finalized as outcome_unknown" } });
        }
        return { result, approval_id: approval.id };
      }

      if (verdict.decision === "need_approval") {
        // Â§9.4 queue protections: active-pending caps and a creation rate
        // limit, counted against DB time. Limits only tighten (Â§9.4).
        const requestId = parsed.data.request_id ?? `req-${randomUUID()}`;
        const hash = requestHash(caller, server_id, tool, args as Record<string, unknown>, requestId, String(toolRow.rows[0].definition_hash));
        const sealed = seal(ARGS_KEY, args as Record<string, unknown>, requestId);
        // A retry of the same logical call must return the existing row even
        // when the caller is at a queue or rate cap. Check dedupe before the
        // caps; only genuinely new approvals consume a slot.
        const priorExisting = await client.query(
          `SELECT id, request_id, status, expires_at, args_hash FROM approvals
            WHERE project_id=$1 AND caller=$2 AND request_id=$3`,
          [server.project_id, caller, requestId]
        );
        const existingApproval = priorExisting.rows[0];
        if (existingApproval) {
          if (!hashesEqual(String(existingApproval.args_hash), hash)) {
            await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "approval.request_conflict",
              resource_type: "approval", resource_id: existingApproval.id, result: "deny",
              metadata: { server_id, tool } });
            return reply.code(409).send({ error: "request_id_conflict" });
          }
          await recordDecision(client, { ...corr, workspace_id: server.workspace_id, caller, server_id,
            tool_name: tool, args_hash: callArgsHash, decision: "need_approval",
            policy_id: verdict.rule?.id ?? null, policy_version: verdict.rule?.version ?? null,
            policy_version_id: policy.policy_version_id,
            matched: verdict.matched, reason: verdict.reason, approval_id: existingApproval.id,
            overhead_ms: overheadMs() });
          await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "policy.approval_required",
            resource_type: "server_tool", resource_id: `${server_id}/${tool}`, result: "need_approval",
            metadata: { rule: verdict.rule?.name ?? null, reason: verdict.reason, approval_id: existingApproval.id } });
          await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "approval.created",
            resource_type: "approval", resource_id: existingApproval.id, result: "pending" });
          void notify(server.workspace_id, "approval.requested",
            { approval_id: existingApproval.id, caller, server_id, tool });
          reply.header("Cache-Control", "no-store");
          return reply.code(202).send({ approval_id: existingApproval.id,
            status: existingApproval.status, expires_at: existingApproval.expires_at });
        }
        const pendingCaller = await client.query(
          "SELECT count(*)::int AS n FROM approvals WHERE caller = $1 AND project_id = $2 AND status IN ('pending','approved')",
          [caller, server.project_id]
        );
        const pendingProject = await client.query(
          "SELECT count(*)::int AS n FROM approvals WHERE project_id = $1 AND status IN ('pending','approved')",
          [server.project_id]
        );
        const recent = await client.query(
          "SELECT count(*)::int AS n FROM approvals WHERE caller = $1 AND project_id = $2 AND requested_at > now() - interval '60 seconds'",
          [caller, server.project_id]
        );
        // Approval caps are spec hard maxima: operators may lower them via
        // environment, never raise them past the boundary (10 / 100 / 5).
        const projectLimit = approvalEnv(
          "APPROVAL_MAX_PENDING_PER_PROJECT",
          approvalEnv("APPROVAL_MAX_PENDING_PER_WORKSPACE", 100)
        );
        if (pendingCaller.rows[0].n >= Math.min(approvalEnv("APPROVAL_MAX_PENDING_PER_CALLER", 10), 10) ||
            pendingProject.rows[0].n >= Math.min(projectLimit, 100)) {
          return reply.code(429).send({ error: "approval_limit",
            pending_caller: pendingCaller.rows[0].n,
            pending_project: pendingProject.rows[0].n,
            // Kept for older dashboard clients; the value is the project cap.
            pending_workspace: pendingProject.rows[0].n });
        }
        if (recent.rows[0].n >= Math.min(approvalEnv("APPROVAL_RATE_PER_MINUTE", 5), 5)) {
          return reply.code(429).send({ error: "approval_rate_limited", retry_after_seconds: 60 });
        }
        // TTLs run on database time (Â§9.4): the row's expiry and every later
        // check compare against the one clock the gateway process cannot skew.
        const ap = await client.query(
          `SELECT id, request_id, status, expires_at
             FROM approval_request($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11)`,
          [requestId, server.workspace_id, caller, server_id, tool, hash,
           JSON.stringify({ sealed }), true, caller, APPROVAL_TTL_SECONDS, server.project_id]
        );
        type ApprovalRow = { id: string; request_id: string; status: string; expires_at: string };
        let row: ApprovalRow | undefined = ap.rows[0] as ApprovalRow | undefined;
        if (!row) {
          // Dedupe replays of one logical call by request id (Â§9.4): the same
          // id must present the same binding. A reused id with different
          // arguments â€” or from a different caller â€” is a conflict, not a
          // cache hit, and is recorded as one.
          const prior = await client.query(
            `SELECT id, request_id, status, expires_at, args_hash FROM approvals
              WHERE project_id=$1 AND caller=$2 AND request_id=$3`,
            [server.project_id, caller, requestId]
          );
          const found = prior.rows[0];
          if (!found || !hashesEqual(String(found.args_hash), hash)) {
            await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "approval.request_conflict",
              resource_type: "approval", resource_id: found?.id ?? null, result: "deny",
              metadata: { server_id, tool } });
            return reply.code(409).send({ error: "request_id_conflict" });
          }
          row = found as ApprovalRow;
        }
        await recordDecision(client, { ...corr, workspace_id: server.workspace_id, caller, server_id,
          tool_name: tool, args_hash: callArgsHash, decision: "need_approval",
          policy_id: verdict.rule?.id ?? null, policy_version: verdict.rule?.version ?? null,
          policy_version_id: policy.policy_version_id,
          matched: verdict.matched, reason: verdict.reason, approval_id: row.id,
          overhead_ms: overheadMs() });
        await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "policy.approval_required",
          resource_type: "server_tool", resource_id: `${server_id}/${tool}`, result: "need_approval",
          metadata: { rule: verdict.rule?.name ?? null, reason: verdict.reason, approval_id: row.id } });
        await auditForScope(pool, server, { actor_type: "agent", actor_id: caller, action: "approval.created",
          resource_type: "approval", resource_id: row.id, result: "pending" });
        void notify(server.workspace_id, "approval.requested",
          { approval_id: row.id, caller, server_id, tool });
        reply.header("Cache-Control", "no-store");
        return reply.code(202).send({ approval_id: row.id, status: row.status, expires_at: row.expires_at });
      }

      try {
        const result = await forward(client, server, tool, args as Record<string, unknown>, caller,
          { corr, policy_id: verdict.rule?.id ?? null, policy_version: verdict.rule?.version ?? null,
            policy_version_id: policy.policy_version_id, matched: verdict.matched, overheadMs: overheadMs() });
        return { result };
      } catch {
        return reply.code(502).send({ error: "upstream_failed" });
      }
    } finally {
      if (heldReservationIds.length > 0 && holdWorkspaceId) {
        // Release through the pool, not the request client: an aborted
        // transaction on that client must not block returning the hold. A
        // failure leaves the hold for the expiry sweep to settle at its
        // reserved maximum, the conservative outcome.
        try {
          await releaseToolCallHolds(pool, holdWorkspaceId, heldReservationIds);
        } catch (err) {
          app.log.warn(`budget hold release failed: ${(err as Error).message}`);
        }
      }
      client.release();
    }
  });

  // The human approval queue and its decision endpoint are served on the
  // dedicated control listener (Â§9: registerApprovalControlRoutes below), so
  // no route on the agent-facing listener can reach them.




  app.get("/v1/decisions", async (req) => {
    const q = req.query as { server_id?: string; tool?: string; limit?: string;
      // FR-021: the run view and the approval cards filter by trace ids.
      run_id?: string; span_id?: string; request_id?: string };
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
    if (q.run_id) {
      params.push(q.run_id);
      where.push(`run_id = $${params.length}`);
    }
    if (q.span_id) {
      params.push(q.span_id);
      where.push(`span_id = $${params.length}`);
    }
    if (q.request_id) {
      params.push(q.request_id);
      where.push(`request_id = $${params.length}`);
    }
    const dscope = scopeClause(req.principal, params, "workspace_id");
    if (dscope) where.push(dscope);
    const dproject = projectClause(req.principal, params, "project_id");
    if (dproject) where.push(dproject);
    params.push(limit);
    const res = await pool.query(
      `SELECT * FROM policy_decisions ${where.length ? "WHERE " + where.join(" AND ") : ""}
       ORDER BY timestamp DESC LIMIT $${params.length}`, params
    );
    return { items: res.rows };
  });

  app.get("/v1/audit-events", async (req, reply) => {
    const q = req.query as { action?: string; limit?: string; cursor?: string };
    const limit = Math.min(Math.max(Number(q.limit ?? 50), 1), 200);
    const params: unknown[] = [];
    const where: string[] = [];
    if (q.action) {
      params.push(q.action);
      where.push(`action = $${params.length}`);
    }
    const ascope = scopeClause(req.principal, params, "workspace_id");
    if (ascope) where.push(ascope);
    const aproject = projectClause(req.principal, params, "project_id");
    if (aproject) where.push(aproject);
    if (q.cursor) {
      let decoded = "";
      try {
        decoded = Buffer.from(q.cursor, "base64url").toString("utf8");
      } catch {
        return reply.code(400).send({ error: "invalid_cursor" });
      }
      const [timestamp, id] = decoded.split("|");
      if (!timestamp || !id || Number.isNaN(Date.parse(timestamp))
          || !z.string().guid().safeParse(id).success) {
        return reply.code(400).send({ error: "invalid_cursor" });
      }
      params.push(timestamp);
      const timestampParam = params.length;
      params.push(id);
      where.push(`(timestamp, id) < ($${timestampParam}::timestamptz, $${params.length}::uuid)`);
    }
    params.push(limit + 1);
    const res = await pool.query(
      `SELECT * FROM audit_events ${where.length ? "WHERE " + where.join(" AND ") : ""}
       ORDER BY timestamp DESC, id DESC LIMIT $${params.length}`, params
    );
    const hasMore = res.rows.length > limit;
    const items = res.rows.slice(0, limit);
    const last = items[items.length - 1];
    const next_cursor = hasMore && last
      ? Buffer.from(`${new Date(last.timestamp).toISOString()}|${last.id}`).toString("base64url")
      : null;
    return { items, next_cursor };
  });

  // Â§10: verification recomputes every event hash and checks every link. The
  // table is append-only at the database layer (migration 022), so any
  // mutation it detects came from something with schema rights â€” which is
  // exactly the party an operator-controlled checkpoint exists to catch.
  // Â§10.3: a checkpoint signs the chain head with a key held outside the
  // §10.2/FR-019: checkpoint creation, export, and pruning are operator-side
  // (`pnpm audit:checkpoint`). The gateway holds only the public key and
  // can verify an imported checkpoint; it cannot sign or prune one.


  app.post("/v1/audit/verify", async (req, reply) => {
    // The chain is global across workspaces. A project- or workspace-scoped
    // principal cannot verify a partial chain and must not receive another
    // tenant's event hashes, so only an unscoped operator may run verification.
    if (!(req.principal?.workspaces === "all" && req.principal?.projects === "all")) {
      return reply.code(403).send({ error: "audit_verify_requires_global_scope" });
    }
    const q = (req.query ?? {}) as { limit?: string };
    const limit = Math.min(Math.max(Number(q.limit ?? 200_000), 1), 1_000_000);
    // Migration 028 columns travel with every row: the verifier recomputes
    // each hash with the formula the row's hash_version names, and the v2
    // fields (workspace, policy attribution) must be present for that.
    const res = await pool.query(
      `SELECT id, timestamp, actor_type, actor_id, action, resource_type, resource_id,
              result, metadata, prev_hash, hash,
              workspace_id, seq, hash_version, policy_version_id, matched_rule_ids,
              project_id
         FROM audit_events ORDER BY timestamp ASC, id ASC LIMIT $1`,
      [limit + 1]
    );
    const truncated = res.rows.length > limit;
    const rows = res.rows.slice(0, limit) as Parameters<typeof verifyAuditChain>[0];
    let verification = verifyAuditChain(rows);
    // Â§10.3: a chain whose first link is broken is only trustworthy if the
    // missing prefix is covered by a signed checkpoint held outside the
    // database. Verify that anchor before calling the gap corruption. The
    // checkpoint's cut is the event immediately before the first retained
    // row; its per-workspace segment heads also bound sequence continuity.
    let anchored: { checkpoint_id: string; up_to_timestamp: string; up_to_hash: string; event_count: number } | null = null;
    const first = verification.problems[0];
    const checkpointPublicKey = process.env.AUDIT_CHECKPOINT_PUBLIC_KEY;
    if (first && rows.length > 0 && first.id === rows[0].id
        && first.problem.startsWith("chain link broken") && checkpointPublicKey
        && typeof rows[0].prev_hash === "string" && rows[0].prev_hash.length > 0) {
      const cp = await pool.query(
        `SELECT id, up_to_timestamp, up_to_hash, event_count, payload, signature FROM audit_checkpoints
          WHERE up_to_hash = $1 AND up_to_timestamp <= $2
          ORDER BY created_at DESC LIMIT 1`,
        [rows[0].prev_hash, rows[0].timestamp]
      );
      if (cp.rows[0] && verifyCheckpoint(cp.rows[0].payload as CheckpointPayload, cp.rows[0].signature, checkpointPublicKey)) {
        const payload = cp.rows[0].payload as CheckpointPayload;
        const expectedSequences = "segments" in payload ? payload.segments : [];
        const rechecked = verifyAuditChain(rows, {
          anchorHash: cp.rows[0].up_to_hash,
          expectedSequences
        });
        verification = rechecked;
        if (rechecked.ok) {
          anchored = { checkpoint_id: cp.rows[0].id,
            up_to_timestamp: new Date(cp.rows[0].up_to_timestamp).toISOString(),
            up_to_hash: cp.rows[0].up_to_hash, event_count: Number(cp.rows[0].event_count) };
        }
      }
    }
    // A bounded read cannot prove the tail it never saw; say so instead of
    // reporting a prefix as the whole chain.
    // FR-019 / Â§10.2: "never report a partial chain as fully verified". A
    // complete verification means the whole retained history was read and
    // every link checks out; an empty chain, a truncated read, or an
    // anchored (pruned) prefix is not full verification and is labelled as
    // such.
    return {
      ...verification,
      truncated,
      empty: rows.length === 0,
      complete: verification.ok && rows.length > 0 && !truncated && !anchored,
      checked_to: rows.length > 0 ? rows[rows.length - 1].hash : null,
      anchored
    };
  });

  // The immutable signed policy editions, newest first, with whether the
  // active pointer currently cites each one. Draft rules live in /v1/policies;
  // only a published version governs enforcement.
  app.get("/v1/policy-versions", async (req) => {
    const params: unknown[] = [];
    const limit = Math.min(Math.max(Number((req.query as { limit?: string }).limit ?? 50), 1), 200);
    const conditions: string[] = [];
    const workspaceScope = scopeClause(req.principal, params, "pv.workspace_id");
    if (workspaceScope) conditions.push(workspaceScope);
    const projectScope = projectClause(req.principal, params, "pv.project_id");
    if (projectScope) conditions.push(projectScope);
    params.push(limit);
    const res = await pool.query(
      `SELECT pv.id, pv.workspace_id, pv.project_id, pv.version, pv.content_hash, pv.previous_version_hash,
              pv.published_at, pv.published_by, pv.signing_key_id,
              pk.key_id, (pk.retired_at IS NOT NULL) AS key_retired,
              (ac.policy_version_id = pv.id) AS active
         FROM policy_versions pv
         JOIN policy_signing_keys pk ON pk.id = pv.signing_key_id
         LEFT JOIN active_config ac ON ac.project_id = pv.project_id
        ${conditions.length ? `WHERE ${conditions.join(" AND ")}` : ""}
        ORDER BY pv.version DESC LIMIT $${params.length}`,
      params
    );
    return { items: res.rows };
  });

  // Agent-facing MCP Streamable HTTP profile (Â§7.2), separate from the REST
  // control and dashboard routes.
  registerMcpRoutes(app);

  return app;
}

// Â§9: the human approval surface. It lists the queue (driving the lazy
// recovery sweep) and records approve/reject decisions. It is registered
// only on the control listener, and the auth table gates every route behind
// 'approve' scope â€” which agent keys never carry â€” so agent credentials
// cannot reach an approval, no matter which caller tries.
export function registerApprovalControlRoutes(app: FastifyInstance): void {
  app.get("/_control/v1/approvals", async (req, reply) => {
    reply.header("Cache-Control", "no-store");
    const q = req.query as { status?: string; limit?: string };
    const limit = Math.min(Math.max(Number(q.limit ?? 50), 1), 200);
    // Lazy recovery sweep, driven by DB time (Â§9.2 rules 2, 7, 8, 9): pending
    // past TTL expires; a CLAIMED row whose lease expired without an
    // execution intent returns to APPROVED â€” nothing was dispatched, so the
    // approval is still safely consumable; executing without a terminal
    // outcome past the recovery window becomes OUTCOME_UNKNOWN.
    const sweepScope = (params: unknown[]): string => {
      const parts: string[] = [];
      const w = scopeClause(req.principal, params, "workspace_id");
      if (w) parts.push(w);
      const p = projectClause(req.principal, params, "project_id");
      if (p) parts.push(p);
      return parts.length ? ` AND ${parts.join(" AND ")}` : "";
    };
    const staleParams: unknown[] = [];
    const stale = await pool.query(
      `SELECT * FROM approvals WHERE status = 'pending' AND expires_at < now()
       ${sweepScope(staleParams)}`, staleParams
    );
    for (const row of stale.rows) {
      await pool.query(
        "SELECT * FROM approval_transition($1,'expire_pending',NULL,'',$2)",
        [row.id, safeSummary(row)]
      );
      await audit(pool, { actor_type: "system", action: "approval.expired",
        resource_type: "approval", resource_id: row.id, result: "expired",
        workspace_id: row.workspace_id, project_id: row.project_id });
    }
    const claimParams: unknown[] = [];
    const staleClaims = await pool.query(
      `SELECT *, (expires_at > now()) AS still_live FROM approvals
        WHERE status = 'claimed' AND claim_lease_expires_at < now()
        ${sweepScope(claimParams)}`, claimParams
    );
    for (const row of staleClaims.rows) {
      if (row.still_live) {
        // The lease died, but the request has not: nothing was dispatched
        // (the intent audit is the marker for that), so the approval safely
        // returns to APPROVED (Â§9.2 rule 2).
        await pool.query(
          "SELECT * FROM approval_transition($1,'sweep_release')",
          [row.id]
        );
        await audit(pool, { actor_type: "system", action: "approval.claim_expired",
          resource_type: "approval", resource_id: row.id, result: "approved",
          workspace_id: row.workspace_id, project_id: row.project_id,
          metadata: { reason: "claim lease expired without an execution intent" } });
      } else {
        // Lease and TTL are both gone: the approval expires rather than
        // being briefly re-armed into the queue.
        await pool.query(
          "SELECT * FROM approval_transition($1,'sweep_expire_claimed',NULL,'',$2)",
          [row.id, safeSummary(row)]
        );
        await audit(pool, { actor_type: "system", action: "approval.expired",
          resource_type: "approval", resource_id: row.id, result: "expired",
          workspace_id: row.workspace_id, project_id: row.project_id,
          metadata: { reason: "claim lease and request TTL both expired" } });
      }
    }
    const stuckParams: unknown[] = [approvalEnv("APPROVAL_EXECUTION_TIMEOUT_SECONDS", 300)];
    const stuck = await pool.query(
      `SELECT * FROM approvals
        WHERE status = 'executing'
          AND execution_started_at < now() - ($1::int * interval '1 second')
          ${sweepScope(stuckParams)}`,
      stuckParams
    );
    for (const row of stuck.rows) {
      await pool.query(
        "SELECT * FROM approval_transition($1,'sweep_expire_executing',NULL,'',$2)",
        [row.id, "The upstream action may have executed."]
      );
      await audit(pool, { actor_type: "system", action: "approval.outcome_unknown",
        resource_type: "approval", resource_id: row.id, result: "unknown",
        workspace_id: row.workspace_id, project_id: row.project_id,
        metadata: { reason: "recovery timeout" } });
    }
    const params: unknown[] = [];
    const where: string[] = [];
    if (q.status) {
      params.push(q.status);
      where.push(`a.status = $${params.length}`);
    }
    // The control surface requires approve scope (auth table), and approval
    // authority is project-scoped. Workspace membership alone is not enough:
    // two projects can share a workspace.
    const ascope = scopeClause(req.principal, params, "a.workspace_id");
    if (ascope) where.push(ascope);
    const apProject = projectClause(req.principal, params, "a.project_id");
    if (apProject) where.push(apProject);
    params.push(limit);
    // FR-021: carry the gateway decision correlation (run/span/request) so the
    // approver can open the trace the held call belongs to. The decision row
    // that queued the approval is the latest one citing this approval id.
    const res = await pool.query(
      `SELECT a.*, d.run_id, d.span_id, d.request_id
         FROM approvals a
         LEFT JOIN LATERAL (
           SELECT run_id, span_id, request_id FROM policy_decisions
            WHERE approval_id = a.id
            ORDER BY timestamp DESC LIMIT 1
         ) d ON true
        ${where.length ? "WHERE " + where.join(" AND ") : ""}
        ORDER BY a.requested_at DESC LIMIT $${params.length}`, params
    );
    // Approvers may open the seal; anything else with access gets the row
    // with the arguments withheld rather than the seal's contents.
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

  app.get("/_control/v1/approvals/:id", async (req, reply) => {
    reply.header("Cache-Control", "no-store");
    const { id } = req.params as { id: string };
    const res = await pool.query(
      `SELECT a.*, d.run_id, d.span_id, d.request_id
         FROM approvals a
         LEFT JOIN LATERAL (
           SELECT run_id, span_id, request_id FROM policy_decisions
            WHERE approval_id = a.id
            ORDER BY timestamp DESC LIMIT 1
         ) d ON true
        WHERE a.id = $1`,
      [id]
    );
    const approval = res.rows[0];
    if (!approval) return reply.code(404).send({ error: "approval_not_found" });
    if (!workspaceAllowed(req.principal, approval.workspace_id) ||
        !projectAllowed(req.principal, approval.project_id)) {
      return reply.code(404).send({ error: "approval_not_found" });
    }
    if (!approval.args_enc) return approval;
    try {
      return { ...approval, args: storedArgs(approval) };
    } catch {
      return { ...approval, args: {}, decrypt_error: true };
    }
  });

  app.post("/_control/v1/approvals/:id/decision", async (req, reply) => {
    reply.header("Cache-Control", "no-store");
    const { id } = req.params as { id: string };
    const parsed = z.object({ approved: z.boolean(), reason: z.string().max(512).default("") }).safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_decision" });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      // The read is unlocked because gateway_runtime has SELECT but not UPDATE
      // on approvals, and PostgreSQL requires UPDATE privilege for
      // SELECT ... FOR UPDATE. approval_decide below performs the compare-and-
      // swap from pending, so a concurrent decision still loses cleanly.
      const ap = await client.query("SELECT * FROM approvals WHERE id = $1", [id]);
      if (!ap.rows[0]) {
        await client.query("ROLLBACK");
        return reply.code(404).send({ error: "approval_not_found" });
      }
      const approval = ap.rows[0];
      if (approval.status !== "pending") {
        await client.query("ROLLBACK");
        return reply.code(409).send({ error: "approval_not_pending", status: approval.status });
      }
      // Approvals outside the approver's workspace or project read as missing.
      if (!workspaceAllowed(req.principal, approval.workspace_id) ||
          !projectAllowed(req.principal, approval.project_id)) {
        await client.query("ROLLBACK");
        return reply.code(404).send({ error: "approval_not_found" });
      }
      const actor = req.principal?.userId ??
        (req.principal?.kind === "env" ? "env_key" : "unknown");
      // TTL runs on database time (Â§9.4). The transition and its audit event
      // commit together: an expiry that exists without a trail would be a
      // hole, and one missed here is exactly what the queue sweep is for.
      const expiredCheck = await client.query(
        "SELECT expires_at < now() AS expired FROM approvals WHERE id = $1",
        [id]
      );
      if (expiredCheck.rows[0]?.expired) {
        const expired = await client.query(
          "SELECT id FROM approval_transition($1,'expire_pending',NULL,'',$2)",
          [id, safeSummary(approval)]
        );
        if (!expired.rows[0]) {
          await client.query("ROLLBACK");
          return reply.code(409).send({ error: "approval_decided_elsewhere" });
        }
        await audit(client, { actor_type: "system", action: "approval.expired",
          resource_type: "approval", resource_id: id, result: "expired",
          workspace_id: approval.workspace_id, project_id: approval.project_id,
          metadata: { reason: "the request TTL had run out when a decision arrived" } });
        await client.query("COMMIT");
        return reply.code(410).send({ error: "approval_expired" });
      }
      // Single decision wins: only one row can leave pending state. Denying
      // drops the sealed arguments immediately, keeping only the redacted
      // summary and hash; approving keeps them until the retry consumes them.
      // The transition and its audit event commit together, so a decision
      // that exists without a trail is impossible. decided_by records the
      // principal, not a constant: an approval trail that cannot name the
      // human who decided it answers nothing.
      const updated = await client.query(
        "SELECT * FROM approval_decide($1,$2,$3,$4,$5)",
        [id, parsed.data.approved, actor, parsed.data.reason,
         parsed.data.approved ? null : safeSummary(approval)]
      );
      if (!updated.rows[0]) {
        await client.query("ROLLBACK");
        return reply.code(409).send({ error: "approval_decided_elsewhere" });
      }
      await audit(client, { actor_type: "approver", actor_id: actor,
        action: parsed.data.approved ? "approval.approved" : "approval.rejected",
        resource_type: "approval", resource_id: id,
        result: parsed.data.approved ? "approved" : "rejected",
        workspace_id: approval.workspace_id, project_id: approval.project_id,
        metadata: { reason: parsed.data.reason } });
      await client.query("COMMIT");
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
}

// The control listener: same CORS and scoped auth as the gateway, but only
// the human approval surface. Nothing agent-facing is reachable here.
export function buildGatewayControl() {
  const app = Fastify({ logger: true, genReqId: () => randomUUID() });
  app.get("/healthz", async () => ({ ok: true }));
  app.addHook("onRequest", async (req, reply) => {
    reply.header("Access-Control-Allow-Origin", DASHBOARD_ORIGIN);
    reply.header("Access-Control-Allow-Credentials", "true");
    reply.header("Access-Control-Allow-Headers", "authorization, content-type, x-csrf-token");
    reply.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    if (req.method === "OPTIONS") return reply.code(204).send();
    await authHook(req, reply);
  });
  registerApprovalControlRoutes(app);
  return app;
}

const isMain = process.argv[1]?.endsWith("gateway.js") || process.argv[1]?.endsWith("gateway.ts");
if (isMain) {
  buildGateway().listen({ port: PORT, host: "0.0.0.0" });
  buildGatewayControl().listen({ port: CONTROL_PORT, host: "0.0.0.0" });
}
