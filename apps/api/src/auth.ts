import { createHash, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import type { FastifyReply, FastifyRequest } from "fastify";
import { pool } from "./db.js";
import { oauthConfigFromEnv, resourceMetadataUrl, verifyAccessToken } from "./oauth.js";
import { audit } from "./audit.js";
import { projectIdsForWorkspaces } from "./project-scope.js";
import {
  ADMIN_SESSION_COOKIE, APPROVER_SESSION_COOKIE, cookieValue, csrfMatches, findSession,
  type DashboardSession
} from "./session-store.js";

// Scoped credentials. Roles map to scope sets; keys carry a subset of their
// owner's role scopes. Only the approver role (and an OAuth token the trusted
// issuer stamps with "approve") can decide approvals: the admin role
// administers but does not approve, so automation that holds the admin key
// still cannot reach the approval surface (§9.1).
export const ALL_SCOPES = ["admin", "ingest", "gateway", "approve", "read"];

// The static env keys and the admin role keep full administrative scope;
// "approve" is deliberately absent.
export const ADMIN_SCOPES = ["admin", "ingest", "gateway", "read"];

export const ROLE_SCOPES: Record<string, string[]> = {
  admin: ADMIN_SCOPES,
  member: ["read", "ingest", "gateway"],
  approver: ["read", "approve"]
};

export interface Principal {
  kind: "env" | "user" | "oauth" | "ingest";
  userId: string | null;
  scopes: string[];
  // Workspaces this principal may write into. "all" is env keys and admins.
  workspaces: "all" | string[];
  // Projects this principal may write into. Agent and ingestion credentials
  // are always pinned to a project; humans inherit their memberships.
  projects: "all" | string[];
  // Set when an OAuth token matched an active, provisioned AgentPrincipal.
  agentPrincipalId?: string | null;
  issuer?: string | null;
}

// Writes that non-admin actors may perform. Everything else that mutates
// state needs admin.
const WRITE_ALLOW: [string, string][] = [
  ["/v1/auth/login", "public"],
  ["/v1/auth/register", "public"],
  ["/v1/auth/session", "public"],
  ["/v1/auth/logout", "read"],
  ["/v1/budgets/check", "ingest"],
  ["/v1/budgets/settle", "ingest"],
  ["/v1/budgets/release", "ingest"],
  ["/v1/ingest", "ingest"],
  ["/v1/traces", "ingest"],
  ["/v1/gateway/tools/call", "gateway"],
  ["/mcp", "gateway"],
  ["/_control/v1/approvals/", "approve"]
];
const ROUTES: [string, string][] = [
  ["/v1/auth/login", "public"],
  ["/v1/auth/register", "public"],
  ["/v1/auth/session", "public"],
  ["/v1/budgets/check", "ingest"],
  ["/v1/budgets/settle", "ingest"],
  ["/v1/budgets/release", "ingest"],
  ["/v1/ingest", "ingest"],
  ["/v1/traces", "ingest"],
  ["/v1/gateway/tools/call", "gateway"],
  ["/mcp", "gateway"],
  // The approval control surface is human-only and lives on its own
  // listener; even listing the queue requires the approver's scope.
  ["/_control/v1/approvals/", "approve"],
  ["/_control/v1/approvals", "approve"],
  ["/v1/overview", "read"],
  ["/v1/agents", "read"],
  ["/v1/runs", "read"],
  ["/v1/pricing", "read"],
  ["/v1/budgets", "read"],
  ["/v1/decisions", "read"],
  ["/v1/evaluations/runs/compare", "read"],
  ["/v1/evaluations/runs/", "read"],
  ["/v1/webhooks/deliveries", "read"],
  ["/v1/evaluations", "admin"],
  ["/v1/policies", "read"],
  ["/v1/policy-drafts", "read"],
  ["/v1/policy-decisions", "read"],
  ["/v1/policy-versions", "read"],
  ["/v1/mcp-servers", "read"],
  ["/v1/mcp-server-drafts", "read"],
  ["/v1/approvals", "read"],
  ["/v1/servers", "read"],
  ["/v1/budgets", "admin"],
  ["/v1/pricing", "admin"],
  ["/v1/webhooks", "admin"],
  ["/v1/retention", "admin"],
  ["/v1/reconciliation/actuals", "admin"],
  ["/v1/reconciliation/compare", "read"],
  ["/v1/admin/", "admin"],
  ["/v1/users", "admin"],
  ["/v1/workspaces", "read"],
  ["/v1/projects", "read"],
  ["/v1/whoami", "read"],
  ["/v1/auth/me", "read"],
  ["/v1/auth/", "admin"]
];

export function requiredScope(url: string, method: string): string {
  if (method === "OPTIONS") return "public";
  if (method === "GET" || method === "HEAD") {
    for (const [prefix, scope] of ROUTES) {
      if (url.startsWith(prefix)) return scope;
    }
    return "admin";
  }
  // Writes default to admin unless the path is an explicit agent or
  // approver action. Reads may be broad; effects stay narrow.
  for (const [prefix, scope] of WRITE_ALLOW) {
    if (url.startsWith(prefix)) return scope;
  }
  return "admin";
}

export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, 64);
  return `scrypt$16$64$${salt.toString("hex")}$${hash.toString("hex")}`;
}

export function checkPassword(password: string, stored: string): boolean {
  const parts = stored.split("$");
  if (parts.length !== 5 || parts[0] !== "scrypt") return false;
  const salt = Buffer.from(parts[3], "hex");
  const want = Buffer.from(parts[4], "hex");
  const got = scryptSync(password, salt, 64);
  return got.length === want.length && timingSafeEqual(got, want);
}

export function newKey(): { plaintext: string; hash: string } {
  const plaintext = `tg_${randomBytes(24).toString("hex")}`;
  const hash = createHash("sha256").update(plaintext).digest("hex");
  return { plaintext, hash };
}

// Ingestion keys are deliberately a different credential type and prefix:
// they authenticate OTLP/trace ingestion only and are never accepted on the
// MCP gateway (§7.3).
export function newIngestKey(): { plaintext: string; hash: string } {
  const plaintext = `tgi_${randomBytes(24).toString("hex")}`;
  const hash = createHash("sha256").update(plaintext).digest("hex");
  return { plaintext, hash };
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function resolvePrincipal(
  authHeader: string,
  options: { allowIngest?: boolean } = {}
): Promise<Principal | null> {
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (!token) return null;
  const oauth = oauthConfigFromEnv();
  // §7.3: static development keys stop authenticating in a production
  // deployment even if their environment variables are still set.
  const staticKeysAllowed = !(oauth && process.env.NODE_ENV === "production");
  if (staticKeysAllowed && process.env.API_KEY && token === process.env.API_KEY) {
    return { kind: "env", userId: null, scopes: ADMIN_SCOPES, workspaces: "all", projects: "all" };
  }
  if (staticKeysAllowed && process.env.APPROVER_KEY && token === process.env.APPROVER_KEY) {
    return {
      kind: "env", userId: null, scopes: ["approve", "read"],
      workspaces: "all", projects: "all"
    };
  }
  // Ingestion keys are not MCP credentials. They are only resolved on the
  // telemetry routes; on every other listener/path this branch is skipped
  // before any database lookup.
  if (token.startsWith("tgi_")) {
    if (options.allowIngest === false) return null;
    const hash = createHash("sha256").update(token).digest("hex");
    const res = await pool.query(
      `SELECT k.id, k.project_id, k.scopes, k.expires_at, k.revoked_at,
              p.workspace_id
         FROM ingest_api_keys k
         JOIN projects p ON p.id = k.project_id
        WHERE k.key_hash = $1`,
      [hash]
    );
    const row = res.rows[0];
    if (!row) return null;
    if (row.revoked_at) return null;
    if (row.expires_at && new Date(row.expires_at).getTime() < Date.now()) return null;
    await pool.query("UPDATE ingest_api_keys SET last_used_at = now() WHERE id = $1", [row.id])
      .catch(() => undefined);
    return {
      kind: "ingest",
      userId: null,
      scopes: ["ingest"],
      workspaces: [row.workspace_id],
      projects: [row.project_id],
      issuer: null,
      agentPrincipalId: null
    };
  }
  // A token shaped like a JWT is validated as an OAuth access token and is
  // never retried down another path; a rejection is a rejection.
  if (oauth && token.split(".").length === 3) {
    try {
      const claims = await verifyAccessToken(token, oauth);
      const projectIds = claims.projects.filter((p) => UUID_RE.test(p));
      let scopes = claims.scopes.filter((s) => ALL_SCOPES.includes(s));
      let agentPrincipalId: string | null = null;
      let agentPrincipalProject: string | null = null;
      if (projectIds.length > 0) {
        const principalRows = await pool.query(
          `SELECT id, project_id, allowed_scopes FROM agent_principals
            WHERE project_id = ANY($1::uuid[]) AND issuer = $2 AND subject = $3
              AND status = 'active'`,
          [projectIds, oauth.issuer, claims.sub]
        );
        // A validated token maps to one project-scoped AgentPrincipal. If the
        // issuer names several projects, take the first provisioned project in
        // the token's own order and narrow the principal to it. Retaining the
        // whole claim here would let a token act in a project where no
        // principal was ever provisioned.
        const byProject = new Map(
          principalRows.rows.map((r) => [r.project_id as string, r])
        );
        const chosen = projectIds.map((id) => byProject.get(id)).find(Boolean);
        if (chosen) {
          agentPrincipalId = chosen.id as string;
          agentPrincipalProject = chosen.project_id as string;
          const allowed = new Set((chosen.allowed_scopes ?? []) as string[]);
          scopes = scopes.filter((s) => allowed.has(s));
        }
      }
      // Legacy tokens name workspaces instead of projects. Only UUID-shaped
      // workspace ids can be resolved against the database; the original
      // claim is preserved on the principal for compatibility with old
      // deployments.
      let projects: "all" | string[] = agentPrincipalProject
        ? [agentPrincipalProject]
        : projectIds;
      if (projectIds.length === 0) {
        const workspaceIds = claims.workspaces.filter((w) => UUID_RE.test(w));
        if (workspaceIds.length > 0) {
          projects = await projectIdsForWorkspaces(pool, workspaceIds);
        }
      }
      return {
        kind: "oauth",
        userId: claims.sub,
        scopes,
        // The issuer names the workspaces this principal may act in; a token
        // without them authenticates but can write nowhere.
        workspaces: claims.workspaces,
        projects,
        agentPrincipalId,
        issuer: oauth.issuer
      };
    } catch (err) {
      console.warn(`oauth access token rejected: ${(err as Error).message}`);
      return null;
    }
  }
  const hash = createHash("sha256").update(token).digest("hex");
  const res = await pool.query(
    `SELECT k.user_id, k.scopes, k.expires_at, k.workspace_id AS key_workspace,
            u.role FROM api_keys k
     JOIN users u ON u.id = k.user_id WHERE k.key_hash = $1`,
    [hash]
  );
  const row = res.rows[0];
  if (!row) return null;
  if (row.expires_at && new Date(row.expires_at).getTime() < Date.now()) return null;
  const roleScopes = ROLE_SCOPES[row.role] ?? [];
  const scopes = ((row.scopes ?? []) as string[]).filter((s) => roleScopes.includes(s));
  let workspaces: "all" | string[];
  if (row.role === "admin") {
    workspaces = "all";
  } else {
    const mem = await pool.query("SELECT workspace_id FROM memberships WHERE user_id = $1",
      [row.user_id]);
    const mine = mem.rows.map((r) => r.workspace_id as string);
    // A pinned key narrows to one workspace; a pin outside the owner's
    // memberships leaves the key with nowhere to write.
    workspaces = row.key_workspace
      ? (mine.includes(row.key_workspace) ? [row.key_workspace] : [])
      : mine;
  }
  const projects = row.role === "admin"
    ? "all"
    : await projectIdsForWorkspaces(pool, workspaces);
  await pool.query("SELECT identity_touch_key($1)", [hash])
    .catch(() => undefined);
  return {
    kind: "user", userId: row.user_id, scopes, workspaces, projects,
    issuer: null, agentPrincipalId: null
  };
}

export function forbidden(reply: FastifyReply, scope: string) {
  return reply.code(403).send({ error: "forbidden", required_scope: scope });
}

// Appends a workspace membership predicate for list queries. Unrestricted
// principals add nothing; everyone else sees only their own rows. An empty
// membership matches nothing, so strangers see an empty list, not an error.
export function scopeClause(
  principal: Principal | undefined, params: unknown[], column: string
): string | null {
  if (!principal || principal.workspaces === "all") return null;
  params.push(principal.workspaces);
  return `${column} = ANY($${params.length})`;
}

// Write-path guard. Admins and env keys pass; everyone else must belong to
// the target workspace. Denials name the workspace so operators see why.
export function workspaceAllowed(principal: Principal | undefined, workspaceId: string): boolean {
  if (!principal) return false;
  if (principal.workspaces === "all") return true;
  return principal.workspaces.includes(workspaceId);
}

declare module "fastify" {
  interface FastifyRequest {
    principal?: Principal;
    session?: DashboardSession;
  }
}

export async function authHook(req: FastifyRequest, reply: FastifyReply): Promise<void> {
  if (!req.url.startsWith("/v1/") && !req.url.startsWith("/mcp") && !req.url.startsWith("/_control/")) return;
  const scope = requiredScope(req.url, req.method);
  if (scope === "public") return;
  const presented = (req.headers.authorization ?? "").replace(/^Bearer\s+/i, "");
  const ingestRoute = req.url.startsWith("/v1/ingest") || req.url.startsWith("/v1/traces");

  // The dashboard exchanges its bearer key for a short-lived, server-side
  // session. Sessions are deliberately not a dispatch credential: the
  // approval executor and MCP surface only accept the agent's own client.
  const sessionRole = req.url.startsWith("/_control/") ? "approver" : "admin";
  let session: DashboardSession | null = null;
  if (!presented) {
    const cookieName = sessionRole === "approver" ? APPROVER_SESSION_COOKIE : ADMIN_SESSION_COOKIE;
    const token = cookieValue(req.headers.cookie, cookieName);
    if (token) session = await findSession(sessionRole, token);
  }
  if (session && (req.url.startsWith("/mcp") || req.url.startsWith("/v1/gateway/tools/call"))) {
    return reply.code(403).send({ error: "APPROVAL_CLIENT_REQUIRED" }) as unknown as void;
  }
  if (session && !["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    const csrf = req.headers["x-csrf-token"];
    if (!csrfMatches(session, typeof csrf === "string" ? csrf : undefined)) {
      return reply.code(403).send({ error: "csrf_required" }) as unknown as void;
    }
  }

  const principal = session?.principal ?? await resolvePrincipal(req.headers.authorization ?? "", {
    // Ingestion keys are only looked up on the telemetry routes. The gateway
    // listener therefore cannot turn one into an MCP principal.
    allowIngest: ingestRoute
  });
  if (!principal) {
    // A well-formed ingestion credential presented to any other surface is a
    // scope error, not an anonymous request. No lookup is needed here: the
    // prefix is deliberately distinct from user and OAuth credentials. On the
    // ingest surface a missing principal means revoked or expired, which is a
    // plain 401.
    if (!ingestRoute && presented.startsWith("tgi_")) {
      return reply.code(403).send({ error: "ingest_key_scope" }) as unknown as void;
    }
    // RFC 9728: point a challenged client at the resource metadata document
    // so it can discover the authorization server.
    const oauth = oauthConfigFromEnv();
    if (oauth) {
      reply.header("WWW-Authenticate", `Bearer resource_metadata="${resourceMetadataUrl(oauth)}"`);
    }
    if (req.url.startsWith("/_control/")) {
      // §10.3: failed access to the approval control surface is audited — an
      // unauthenticated probe is exactly the signal an operator wants.
      await audit(pool, { actor_type: "anonymous", action: "control.access_denied",
        resource_type: "route", resource_id: req.url, result: "rejected",
        metadata: { method: req.method, required_scope: scope } }).catch(() => undefined);
    }
    return reply.code(401).send({ error: "unauthorized" }) as unknown as void;
  }
  // An OTLP key is a telemetry credential, not a general API key. It cannot
  // reach MCP, approvals, administration, or even reads.
  if (principal.kind === "ingest" && scope !== "ingest") {
    return reply.code(403).send({ error: "ingest_key_scope" }) as unknown as void;
  }
  // §7.3: in production the gateway maps an OAuth subject to a provisioned,
  // project-scoped AgentPrincipal. A valid token that was never provisioned
  // authenticates as a person elsewhere but cannot act as an MCP caller.
  // Server discovery stays available; tool listing and execution do not.
  const mcpBody = req.body && typeof req.body === "object" && !Array.isArray(req.body)
    ? req.body as { method?: unknown }
    : null;
  const mcpMethod = req.headers["mcp-method"] ?? mcpBody?.method;
  const mcpAction = req.url.startsWith("/mcp") && mcpMethod !== "server/discover";
  if (
    principal.kind === "oauth" &&
    process.env.NODE_ENV === "production" &&
    (mcpAction || req.url.startsWith("/v1/gateway")) &&
    !principal.agentPrincipalId
  ) {
    return reply.code(403).send({ error: "agent_principal_required" }) as unknown as void;
  }
  // The approval control surface takes the approve scope itself; "admin"
  // does not shortcut it, so a plain admin key cannot decide in place of the
  // approver and agent automation can never approve itself (§9.1).
  const adminShortcut = !req.url.startsWith("/_control/");
  if (!principal.scopes.includes(scope) && !(adminShortcut && principal.scopes.includes("admin"))) {
    if (req.url.startsWith("/_control/")) {
      await audit(pool, { actor_type: "system", action: "control.access_denied",
        resource_type: "route", resource_id: req.url, result: "rejected",
        metadata: { method: req.method, required_scope: scope,
          actor: principal.userId ?? principal.kind } }).catch(() => undefined);
    }
    return forbidden(reply, scope) as unknown as void;
  }
  req.principal = principal;
  if (session) req.session = session;
}
