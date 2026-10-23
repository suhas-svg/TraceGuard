import type { FastifyInstance, FastifyReply } from "fastify";
import { resolvePrincipal } from "./auth.js";
import {
  ADMIN_SESSION_COOKIE, APPROVER_SESSION_COOKIE, SESSION_TTL_SECONDS,
  clearCookie, cookieValue, createSession, csrfCookieName, csrfMatches, deleteSession,
  findSession, serializeCookie, sessionCookieName, type CreatedSession, type SessionRole
} from "./session-store.js";

function setSessionCookies(reply: FastifyReply, created: CreatedSession) {
  // Two cookies on purpose: the session cookie is unreadable to JavaScript,
  // while the CSRF cookie is the double-submit half the dashboard echoes in
  // X-CSRF-Token. Neither contains a privileged bearer key.
  reply.header("Set-Cookie", [
    serializeCookie(created.cookieName, created.token,
      { httpOnly: true, maxAge: SESSION_TTL_SECONDS }),
    serializeCookie(created.csrfCookieName, created.csrf,
      { httpOnly: false, maxAge: SESSION_TTL_SECONDS })
  ]);
}

function publicSession(session: { principal: unknown; expiresAt: number } | null) {
  if (!session) return null;
  return {
    principal: session.principal,
    expires_at: new Date(session.expiresAt).toISOString()
  };
}

export function registerSessionRoutes(app: FastifyInstance) {
  // The browser presents a bearer key once. From then on it uses the HttpOnly
  // session cookie; the key is not written to localStorage or returned.
  app.post("/v1/auth/session", async (req, reply) => {
    const principal = await resolvePrincipal(req.headers.authorization ?? "", { allowIngest: false });
    if (!principal) return reply.code(401).send({ error: "unauthorized" });
    if (principal.kind === "ingest") {
      return reply.code(403).send({ error: "ingest_key_scope" });
    }
    const created = await createSession(principal);
    setSessionCookies(reply, created);
    reply.header("Cache-Control", "no-store");
    return {
      ok: true,
      role: created.role,
      expires_at: new Date(created.expiresAt).toISOString()
    };
  });

  // A reload asks the server which sessions this browser still holds. The
  // response is intentionally non-secret: no cookie values or hashes.
  app.get("/v1/auth/session", async (req, reply) => {
    const admin = await findSession(
      "admin", cookieValue(req.headers.cookie, ADMIN_SESSION_COOKIE) ?? ""
    );
    const approver = await findSession(
      "approver", cookieValue(req.headers.cookie, APPROVER_SESSION_COOKIE) ?? ""
    );
    reply.header("Cache-Control", "no-store");
    return { ok: true, admin: publicSession(admin), approver: publicSession(approver) };
  });

  // Logout is a state-changing request, so it needs the CSRF half of the
  // session even though the cookie is already present. An expired/absent
  // session is an idempotent success and still clears the browser cookies.
  app.delete("/v1/auth/session", async (req, reply) => {
    const requested = (req.query as { role?: string } | undefined)?.role;
    const role: SessionRole = requested === "approver" ? "approver" : "admin";
    const cookieName = sessionCookieName(role);
    const token = cookieValue(req.headers.cookie, cookieName) ?? "";
    const session = await findSession(role, token);
    if (session && !csrfMatches(session, req.headers["x-csrf-token"] as string | undefined)) {
      return reply.code(403).send({ error: "csrf_required" });
    }
    if (session) await deleteSession(session.id);
    reply.header("Set-Cookie", [
      clearCookie(cookieName, true),
      clearCookie(csrfCookieName(role), false)
    ]);
    reply.header("Cache-Control", "no-store");
    return { ok: true };
  });
}
