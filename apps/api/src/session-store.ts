import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { pool } from "./db.js";
import type { Principal } from "./auth.js";

// FR-016: dashboard sessions are server-side and short-lived. The cookie is
// opaque; only the hash is stored. Admin and approver get separate cookie
// names so one browser can hold both roles without either becoming a shortcut
// for the other (§9.1).
export const SESSION_TTL_SECONDS = 30 * 60;
export const ADMIN_SESSION_COOKIE = "tg_session";
export const APPROVER_SESSION_COOKIE = "tg_approver_session";
export const ADMIN_CSRF_COOKIE = "tg_csrf";
export const APPROVER_CSRF_COOKIE = "tg_approver_csrf";

export type SessionRole = "admin" | "approver";

export interface DashboardSession {
  id: string;
  role: SessionRole;
  principal: Principal;
  csrfHash: string;
  expiresAt: number;
}

export interface CreatedSession {
  role: SessionRole;
  token: string;
  csrf: string;
  cookieName: string;
  csrfCookieName: string;
  expiresAt: number;
}

function hash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function randomToken(): string {
  return randomBytes(32).toString("base64url");
}

export function sessionRole(principal: Principal): SessionRole {
  // An approver key carries "approve" and not "admin". A dual-scope OAuth
  // principal stays on the admin cookie: approval remains an explicit second
  // session, never an implied capability of the administrative one.
  return principal.scopes.includes("approve") && !principal.scopes.includes("admin")
    ? "approver"
    : "admin";
}

export function sessionCookieName(role: SessionRole): string {
  return role === "approver" ? APPROVER_SESSION_COOKIE : ADMIN_SESSION_COOKIE;
}

export function csrfCookieName(role: SessionRole): string {
  return role === "approver" ? APPROVER_CSRF_COOKIE : ADMIN_CSRF_COOKIE;
}

export async function createSession(principal: Principal): Promise<CreatedSession> {
  const role = sessionRole(principal);
  const token = randomToken();
  const csrf = randomToken();
  const expiresAt = Date.now() + SESSION_TTL_SECONDS * 1000;
  await pool.query("DELETE FROM dashboard_sessions WHERE expires_at < now()").catch(() => undefined);
  await pool.query(
    `INSERT INTO dashboard_sessions (token_hash, csrf_hash, principal, expires_at)
     VALUES ($1, $2, $3::jsonb, $4)`,
    [hash(token), hash(csrf), JSON.stringify(principal), new Date(expiresAt).toISOString()]
  );
  return {
    role, token, csrf, cookieName: sessionCookieName(role),
    csrfCookieName: csrfCookieName(role), expiresAt
  };
}

export async function findSession(role: SessionRole, token: string): Promise<DashboardSession | null> {
  if (!token) return null;
  const res = await pool.query(
    `SELECT id, csrf_hash, principal, expires_at FROM dashboard_sessions WHERE token_hash = $1`,
    [hash(token)]
  );
  const row = res.rows[0];
  if (!row) return null;
  const expiresAt = new Date(row.expires_at).getTime();
  if (expiresAt <= Date.now()) {
    await pool.query("DELETE FROM dashboard_sessions WHERE id = $1", [row.id]).catch(() => undefined);
    return null;
  }
  // Best effort: the gateway connection has SELECT only.
  await pool.query("UPDATE dashboard_sessions SET last_used_at = now() WHERE id = $1", [row.id])
    .catch(() => undefined);
  return {
    id: row.id,
    role,
    principal: row.principal as Principal,
    csrfHash: row.csrf_hash,
    expiresAt
  };
}

export async function deleteSession(id: string): Promise<void> {
  await pool.query("DELETE FROM dashboard_sessions WHERE id = $1", [id]);
}

export function cookieValue(header: string | undefined, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(";")) {
    const trimmed = part.trim();
    const eq = trimmed.indexOf("=");
    if (eq < 0) continue;
    if (trimmed.slice(0, eq) === name) {
      try {
        return decodeURIComponent(trimmed.slice(eq + 1));
      } catch {
        return null;
      }
    }
  }
  return null;
}

export function serializeCookie(
  name: string, value: string, opts: { httpOnly: boolean; maxAge: number }
): string {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    "SameSite=Strict",
    `Max-Age=${opts.maxAge}`
  ];
  if (opts.httpOnly) parts.push("HttpOnly");
  if (process.env.NODE_ENV === "production") parts.push("Secure");
  return parts.join("; ");
}

export function clearCookie(name: string, httpOnly: boolean): string {
  return serializeCookie(name, "", { httpOnly, maxAge: 0 });
}

export function csrfMatches(session: DashboardSession, presented: string | undefined): boolean {
  if (!presented) return false;
  const expected = Buffer.from(session.csrfHash, "hex");
  const actual = Buffer.from(hash(presented), "hex");
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}
