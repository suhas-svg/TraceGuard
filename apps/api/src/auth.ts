import { createHash, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import type { FastifyReply, FastifyRequest } from "fastify";
import { pool } from "./db.js";
import { oauthConfigFromEnv, resourceMetadataUrl, verifyAccessToken } from "./oauth.js";
import { audit } from "./audit.js";

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
  kind: "env" | "user" | "oauth";
  userId: string | null;
  scopes: string[];
  // Workspaces this principal may write into. "all" is env keys and admins.
  workspaces: "all" | string[];
}

// Writes that non-admin actors may perform. Everything else that mutates
// state needs admin.
const WRITE_ALLOW: [string, string][] = [
  ["/v1/auth/login", "public"],
  ["/v1/auth/register", "public"],
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
  ["/v1/policy-versions", "read"],
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

export async function resolvePrincipal(authHeader: string): Promise<Principal | null> {
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (!token) return null;
  const oauth = oauthConfigFromEnv();
  // §7.3: static development keys stop authenticating in a production
  // deployment even if their environment variables are still set.
  const staticKeysAllowed = !(oauth && process.env.NODE_ENV === "production");
  if (staticKeysAllowed && process.env.API_KEY && token === process.env.API_KEY) {
    return { kind: "env", userId: null, scopes: ADMIN_SCOPES, workspaces: "all" };
  }
  if (staticKeysAllowed && process.env.APPROVER_KEY && token === process.env.APPROVER_KEY) {
    return { kind: "env", userId: null, scopes: ["approve", "read"], workspaces: "all" };
  }
  // A token shaped like a JWT is validated as an OAuth access token and is
  // never retried down another path; a rejection is a rejection.
  if (oauth && token.split(".").length === 3) {
    try {
      const claims = await verifyAccessToken(token, oauth);
      return {
        kind: "oauth",
        userId: claims.sub,
        scopes: claims.scopes.filter((s) => ALL_SCOPES.includes(s)),
        // The issuer names the workspaces this principal may act in; a token
        // without them authenticates but can write nowhere.
        workspaces: claims.workspaces
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
  await pool.query("UPDATE api_keys SET last_used_at = now() WHERE key_hash = $1", [hash])
    .catch(() => undefined);
  return { kind: "user", userId: row.user_id, scopes, workspaces };
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
  }
}

export async function authHook(req: FastifyRequest, reply: FastifyReply): Promise<void> {
  if (!req.url.startsWith("/v1/") && !req.url.startsWith("/mcp") && !req.url.startsWith("/_control/")) return;
  const scope = requiredScope(req.url, req.method);
  if (scope === "public") return;
  const principal = await resolvePrincipal(req.headers.authorization ?? "");
  if (!principal) {
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
}
