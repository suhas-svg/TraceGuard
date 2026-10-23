import type { FastifyInstance } from "fastify";
import { pool } from "./db.js";
import { audit } from "./audit.js";
import { evaluate } from "./policy.js";
import { loadActivePolicy, rulesFromBundle } from "./policy-bundle.js";
import type { Principal } from "./auth.js";
import { resolveProject } from "./project-scope.js";

// The agent-facing boundary is the MCP Streamable HTTP profile of the
// 2026-07-28 revision: stateless requests, per-request metadata, and only
// server/discover, tools/list and tools/call. Everything else is rejected and
// never forwarded upstream (§7.2).
export const MCP_PROTOCOL_VERSION = "2026-07-28";
const META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion";
const META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities";
const META_LOGICAL_REQUEST_ID = "io.traceguard/logical_request_id";
// FR-021: optional trace correlation the shim may carry; the gateway records
// them on the decision row and the span so the run view can join them.
const META_RUN_ID = "io.traceguard/run_id";
const META_SPAN_ID = "io.traceguard/span_id";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TOOLS_TTL_MS = 60_000;

type JsonRpcId = string | number;

function rpcResult(id: JsonRpcId, result: unknown) {
  return { jsonrpc: "2.0", id, result };
}

function rpcError(id: JsonRpcId | null, code: number, message: string, data?: unknown) {
  return { jsonrpc: "2.0", id, error: { code, message, ...(data === undefined ? {} : { data }) } };
}

export function gatewayAlias(name: string): string {
  const alias = name.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 32);
  return alias || "server";
}

async function resolveWorkspace(principal?: Principal): Promise<string | null> {
  if (principal && Array.isArray(principal.workspaces)) return principal.workspaces[0] ?? null;
  const found = await pool.query("SELECT id FROM workspaces WHERE name = 'default'");
  return (found.rows[0]?.id as string | undefined) ?? null;
}

interface RpcEnvelope {
  id: JsonRpcId;
  method: string;
  params: Record<string, unknown>;
}

function parseEnvelope(body: unknown):
  | { ok: true; env: RpcEnvelope }
  | { ok: false; id: JsonRpcId | null; message: string } {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { ok: false, id: null, message: "body must be a JSON-RPC object" };
  }
  const b = body as Record<string, unknown>;
  if (b.jsonrpc !== "2.0") return { ok: false, id: null, message: "jsonrpc must be \"2.0\"" };
  // v1 is request-only: no notifications, no server-initiated messages.
  if (typeof b.id !== "string" && typeof b.id !== "number") {
    return { ok: false, id: null, message: "a request id is required" };
  }
  if (typeof b.method !== "string" || !b.method) {
    return { ok: false, id: b.id, message: "method is required" };
  }
  const params = b.params === undefined ? {} : b.params;
  if (!params || typeof params !== "object" || Array.isArray(params)) {
    return { ok: false, id: b.id, message: "params must be an object" };
  }
  return { ok: true, env: { id: b.id, method: b.method, params: params as Record<string, unknown> } };
}

// The three header/body checks the revision requires: a supported protocol
// version, the method repeated in Mcp-Method, and the tool name repeated in
// Mcp-Name for tools/call. Routing on one representation while authorising
// another is exactly the gap this closes.
function protocolIssue(
  headers: Record<string, string | string[] | undefined>, env: RpcEnvelope
): string | null {
  const version = headers["mcp-protocol-version"];
  if (version !== MCP_PROTOCOL_VERSION) {
    return `MCP-Protocol-Version must be ${MCP_PROTOCOL_VERSION}`;
  }
  if (headers["mcp-method"] !== env.method) {
    return "Mcp-Method does not match the JSON-RPC method";
  }
  if (env.method === "tools/call") {
    const name = env.params.name;
    if (typeof name !== "string" || headers["mcp-name"] !== name) {
      return "Mcp-Name does not match params.name";
    }
  }
  const meta = env.params._meta;
  if (!meta || typeof meta !== "object" || Array.isArray(meta)) {
    return "params._meta is required";
  }
  const fields = meta as Record<string, unknown>;
  if (fields[META_PROTOCOL_VERSION] !== MCP_PROTOCOL_VERSION) {
    return `${META_PROTOCOL_VERSION} must be ${MCP_PROTOCOL_VERSION}`;
  }
  const caps = fields[META_CLIENT_CAPABILITIES];
  if (!caps || typeof caps !== "object" || Array.isArray(caps)) {
    return `${META_CLIENT_CAPABILITIES} is required`;
  }
  // §7.2: a method is served only when the client declared the capability it
  // belongs to. Undeclared capabilities are rejected by default, so a client
  // that never declared tools cannot list or call them.
  if (env.method === "tools/list" || env.method === "tools/call") {
    const toolsCap = (caps as Record<string, unknown>).tools;
    if (!toolsCap || typeof toolsCap !== "object" || Array.isArray(toolsCap)) {
      return `${META_CLIENT_CAPABILITIES} must declare the tools capability for ${env.method}`;
    }
  }
  return null;
}

// §7.2: multi-round-trip input (MRTR) and task flows have no place on this
// boundary. A result is delivered only when it is a plain completed call;
// anything input- or task-shaped is refused rather than handed to the agent.
function unsupportedResultReason(result: unknown): string | null {
  if (!result || typeof result !== "object" || Array.isArray(result)) return null;
  const r = result as Record<string, unknown>;
  if (typeof r.resultType === "string" && r.resultType !== "complete") {
    return `unsupported resultType "${r.resultType}"`;
  }
  if (Array.isArray(r.inputRequests)) return "inputRequests are not supported in v1";
  if (r.input_required !== undefined || r.requestState !== undefined) {
    return "multi-round-trip input is not supported in v1";
  }
  if (r.task !== undefined) return "task-based results are not supported in v1";
  return null;
}

// §7.2/FR-003: a tools/call result must keep the revision's result shape. A
// peer that answers with something else is refused the same way MRTR and task
// flows are — the agent never receives a malformed result as data.
function malformedResultReason(result: unknown): string | null {
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    return "tool result is not an object";
  }
  const r = result as Record<string, unknown>;
  if (r.content !== undefined) {
    if (!Array.isArray(r.content)) return "tool result content is not an array";
    for (const block of r.content) {
      if (!block || typeof block !== "object" || Array.isArray(block)) {
        return "tool result content block is not an object";
      }
      if (typeof (block as Record<string, unknown>).type !== "string") {
        return "tool result content block has no type";
      }
    }
  }
  if (r.isError !== undefined && typeof r.isError !== "boolean") {
    return "tool result isError is not a boolean";
  }
  if (r.structuredContent !== undefined) {
    if (!r.structuredContent || typeof r.structuredContent !== "object" || Array.isArray(r.structuredContent)) {
      return "tool result structuredContent is not an object";
    }
  }
  return null;
}

async function callTool(app: FastifyInstance, req: { headers: Record<string, string | string[] | undefined>; principal?: Principal; }, env: RpcEnvelope) {
  const name = env.params.name;
  if (typeof name !== "string" || !name) {
    return rpcError(env.id, -32602, "Invalid params", { error: "tool name is required" });
  }
  const sep = name.indexOf("__");
  if (sep <= 0 || sep + 2 >= name.length) {
    return rpcError(env.id, -32602, "Invalid params", { error: "tool name must be <server-alias>__<tool>" });
  }
  const alias = name.slice(0, sep);
  const tool = name.slice(sep + 2);
  const rawArgs = env.params.arguments;
  if (rawArgs !== undefined && (!rawArgs || typeof rawArgs !== "object" || Array.isArray(rawArgs))) {
    return rpcError(env.id, -32602, "Invalid params", { error: "arguments must be an object" });
  }
  const args = (rawArgs ?? {}) as Record<string, unknown>;

  const workspaceId = await resolveWorkspace(req.principal);
  if (!workspaceId) {
    return rpcError(env.id, -32003, "Tool not found", { error: "workspace_not_found" });
  }
  const resolved = await resolveProject(pool, req.principal, { workspaceId });
  if (!resolved) {
    return rpcError(env.id, -32003, "Tool not found", { error: "unknown_server_alias", name });
  }
  const serverRow = await pool.query(
    `SELECT * FROM mcp_servers
      WHERE project_id = $1 AND gateway_alias = $2 AND disabled_at IS NULL`,
    [resolved.project.id, alias]
  );
  const server = serverRow.rows[0];
  if (!server) {
    return rpcError(env.id, -32003, "Tool not found", { error: "unknown_server_alias", name });
  }

  // The authenticated principal is the caller; MCP clientInfo is diagnostic
  // only (§9.1). The env key has no human identity and is a dev profile.
  const caller = req.principal?.userId ?? "agent";
  const meta = env.params._meta as Record<string, unknown>;
  const logicalRaw = meta[META_LOGICAL_REQUEST_ID];
  const logicalId = typeof logicalRaw === "string" && logicalRaw.length > 0 && logicalRaw.length <= 128
    ? logicalRaw
    : undefined;
  // FR-021: trace ids travel only as client metadata, never as call
  // arguments; malformed values are dropped rather than refused so a broken
  // correlator cannot block a call. The gateway schema takes UUIDs, so only
  // UUID-shaped values are forwarded.
  const runRaw = meta[META_RUN_ID];
  const runId = typeof runRaw === "string" && UUID_RE.test(runRaw) ? runRaw : undefined;
  const spanRaw = meta[META_SPAN_ID];
  const spanId = typeof spanRaw === "string" && UUID_RE.test(spanRaw) ? spanRaw : undefined;

  // §9.5: an approval needing call without the shim's stable logical id is
  // refused explicitly rather than silently creating an unmatchable hold.
  if (!logicalId) {
    const loaded = await loadActivePolicy(pool, resolved.project.id);
    if (!loaded.ok) {
      return rpcError(env.id, -32008, "Policy unavailable", {
        error: "POLICY_UNAVAILABLE", reason: loaded.reason
      });
    }
    const verdict = evaluate(rulesFromBundle(loaded.policy.bundle), {
      caller, agent_id: null, server_id: server.id, tool_name: tool, args
    });
    if (verdict.decision === "need_approval") {
      return rpcError(env.id, -32005, "Approval client required", {
        error: "APPROVAL_CLIENT_REQUIRED",
        detail: `send ${META_LOGICAL_REQUEST_ID} so the retry can match its approval`
      });
    }
  }

  // A retry presents the same logical request id, so the approval is found
  // durably rather than being a reusable token in the payload.
  let approvalId: string | undefined;
  if (logicalId) {
    const ap = await pool.query(
      `SELECT id FROM approvals
        WHERE request_id = $1 AND caller = $2 AND workspace_id = $3 AND project_id = $4`,
      [logicalId, caller, workspaceId, server.project_id]
    );
    approvalId = ap.rows[0]?.id as string | undefined;
  }

  // Reuse the enforcing call path rather than reimplementing it: the REST
  // route applies quarantine, policy, budgets, approval consume and upstream
  // credential injection in one place.
  const res = await app.inject({
    method: "POST",
    url: "/v1/gateway/tools/call",
    headers: { authorization: typeof req.headers.authorization === "string" ? req.headers.authorization : "" },
    payload: {
      server_id: server.id,
      tool,
      arguments: args,
      caller,
      ...(logicalId ? { request_id: logicalId } : {}),
      ...(approvalId ? { approval_id: approvalId } : {}),
      ...(runId ? { run_id: runId } : {}),
      ...(spanId ? { span_id: spanId } : {})
    }
  });
  const body = res.json() as Record<string, unknown> & { result?: unknown };

  if (res.statusCode === 200) {
    const result = body.result;
    // A tool server must not smuggle unsupported multi-round-trip input
    // requests or task flows through tools/call; do not deliver them.
    const problem = unsupportedResultReason(result) ?? malformedResultReason(result);
    if (problem) {
      await audit(pool, {
        actor_type: "agent", actor_id: caller, action: "mcp.protocol_rejected",
        resource_type: "server_tool", resource_id: `${server.id}/${tool}`,
        result: "rejected", metadata: { reason: problem }
      });
      return rpcError(env.id, -32006, "Unsupported result", {
        error: "UNSUPPORTED_RESULT", detail: problem
      });
    }
    return rpcResult(env.id, result);
  }
  switch (res.statusCode) {
    case 202:
      return rpcError(env.id, -32002, "Approval pending", {
        error: "APPROVAL_PENDING",
        approval_id: body.approval_id,
        logical_request_id: logicalId ?? null,
        expires_at: body.expires_at,
        status: body.status
      });
    case 403:
      return rpcError(env.id, -32001, "Denied", {
        error: body.error ?? "denied", reason: body.reason ?? null
      });
    case 404:
      return rpcError(env.id, -32003, "Not found", { error: body.error ?? "not_found" });
    case 409:
      return rpcError(env.id, -32004, "Approval not pending", {
        error: body.error ?? "approval_not_pending", status: body.status ?? null
      });
    case 410:
      return rpcError(env.id, -32004, "Approval terminal", {
        error: body.error ?? "approval_terminal", status: body.status ?? null
      });
    case 502:
      if (body.error === "outcome_unknown") {
        // A post-dispatch ambiguity is not a retryable failure; the client
        // must surface it as OUTCOME_UNKNOWN (§9.5).
        return rpcError(env.id, -32007, "Outcome unknown", {
          error: "OUTCOME_UNKNOWN", approval_id: body.approval_id,
          note: "The upstream action may have executed."
        });
      }
      return rpcError(env.id, -32603, "Upstream failed", { error: "UPSTREAM_FAILED" });
    default:
      return rpcError(env.id, -32603, "Internal error", { error: body.error ?? "internal_error" });
  }
}

export function registerMcpRoutes(app: FastifyInstance): void {
  app.post("/mcp", async (req, reply) => {
    // Approvals and tool contracts are per-caller state; never cacheable.
    reply.header("Cache-Control", "no-store");
    const parsed = parseEnvelope(req.body);
    if (!parsed.ok) {
      return reply.code(400).send(rpcError(parsed.id, -32600, "Invalid Request", { error: parsed.message }));
    }
    const env = parsed.env;
    const issue = protocolIssue(req.headers, env);
    if (issue) {
      return reply.code(400).send(rpcError(env.id, -32600, "Invalid Request", { error: issue }));
    }
    switch (env.method) {
      case "server/discover":
        return rpcResult(env.id, {
          protocolVersion: MCP_PROTOCOL_VERSION,
          serverInfo: { name: "traceguard-gateway", version: "0.1.0" },
          capabilities: { tools: { listChanged: false } },
          resultType: "complete"
        });
      case "tools/list": {
        const workspaceId = await resolveWorkspace(req.principal);
        if (!workspaceId) {
          return rpcResult(env.id, {
            tools: [], ttlMs: TOOLS_TTL_MS, cacheScope: "workspace", resultType: "complete"
          });
        }
        const resolved = await resolveProject(pool, req.principal, { workspaceId });
        if (!resolved) {
          return rpcResult(env.id, {
            tools: [], ttlMs: TOOLS_TTL_MS, cacheScope: "workspace", resultType: "complete"
          });
        }
        // Listing is gated by the signed manifests: only servers the active
        // policy carries, and only tools whose exact pinned definition it
        // activated, are ever shown to a client (§7.2, §13.3).
        const loaded = await loadActivePolicy(pool, resolved.project.id);
        if (!loaded.ok) {
          return rpcError(env.id, -32008, "Policy unavailable", {
            error: "POLICY_UNAVAILABLE", reason: loaded.reason
          });
        }
        const manifest = new Map(loaded.policy.bundle.servers.map((s) => [s.server_id, s]));
        const pins = new Map(
          loaded.policy.bundle.pins.map((p) => [`${p.server_id}|${p.tool_name}`, p])
        );
        const rows = await pool.query(
          `SELECT s.id AS server_id, s.gateway_alias, t.tool_name, t.definition,
                  t.definition_hash, t.active_pin_id, t.definition_version
             FROM mcp_servers s JOIN server_tools t ON t.server_id = s.id
            WHERE s.project_id = $1 AND s.disabled_at IS NULL AND t.quarantined = false
            ORDER BY s.gateway_alias, t.tool_name`,
          [resolved.project.id]
        );
        const rules = rulesFromBundle(loaded.policy.bundle);
        return rpcResult(env.id, {
          // The reviewed definition is what clients see: every field the pin
          // covers, so a client cannot observe a description or schema the
          // human never approved (§7.5).
          tools: rows.rows
            .filter((r) => {
              const listed = manifest.get(r.server_id as string);
              if (listed?.alias !== r.gateway_alias) return false;
              const pin = pins.get(`${r.server_id}|${r.tool_name}`);
              if (!pin
                  || (pin.pin_id !== undefined && pin.pin_id !== r.active_pin_id)
                  || (pin.pin_version !== undefined && pin.pin_version !== r.definition_version)
                  || pin.definition_hash !== r.definition_hash) return false;
              // §7.2: only enabled tools are listed. v1 has no per-tool
              // enable flag, so a tool counts as disabled when an enabled
              // unconditional deny rule covers it; conditional denies stay
              // call-time. Tools that require the Tasks flow are not listed
              // because this profile cannot call them.
              const scopeDenied = rules.some((rule) =>
                rule.enabled && rule.effect === "deny" &&
                (rule.server_id === null || rule.server_id === r.server_id) &&
                (rule.tool_name === null || rule.tool_name === r.tool_name) &&
                (rule.conditions?.required?.length ?? 0) === 0 &&
                Object.keys(rule.conditions?.arguments ?? {}).length === 0);
              if (scopeDenied) return false;
              const d = (r.definition ?? {}) as Record<string, unknown>;
              const execution = d.execution as Record<string, unknown> | undefined;
              return execution?.taskSupport !== "required";
            })
            .map((r) => {
              const d = (r.definition ?? {}) as Record<string, unknown>;
              return { ...d, name: `${r.gateway_alias}__${r.tool_name}` };
            }),
          ttlMs: TOOLS_TTL_MS,
          cacheScope: "workspace",
          resultType: "complete"
        });
      }
      case "tools/call":
        return callTool(app, req, env);
      // resources/*, prompts/*, subscriptions, sampling, elicitation, Tasks,
      // Apps and every unknown method land here and are never forwarded.
      default:
        return rpcError(env.id, -32601, "Method not found", {
          error: "unsupported_method", method: env.method
        });
    }
  });

  // v1 has no server-initiated stream and no SSESession resumption.
  app.get("/mcp", async (_req, reply) => reply.code(405).send({ error: "method_not_allowed" }));
}
