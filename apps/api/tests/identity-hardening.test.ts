import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildApp } from "../src/index.js";
import { pool } from "../src/db.js";

// §13.1: human identity and trusted roles come from the external issuer. The
// local password/key plane is a development bootstrap and must not survive as
// a parallel way to mint or keep an identity once OAuth is configured.
describe("identity hardening", () => {
  const api = buildApp();
  const admin = { authorization: "Bearer test_key" };
  const tag = Date.now().toString(36);
  const envNames = [
    "OAUTH_ISSUER", "OAUTH_AUDIENCE", "OAUTH_JWKS_FILE", "OAUTH_JWKS_URL"
  ] as const;
  const previous: Partial<Record<(typeof envNames)[number], string>> = {};
  let dir = "";
  let localAdminKey = "";
  let localMemberKey = "";
  let localSessionCookie = "";
  let memberId = "";
  let workspaceId = "";

  const post = (url: string, body: unknown, headers: Record<string, string> = admin) =>
    api.inject({ method: "POST", url, headers, payload: body as never });
  const get = (url: string, headers: Record<string, string> = admin) =>
    api.inject({ method: "GET", url, headers });

  beforeAll(async () => {
    for (const name of envNames) previous[name] = process.env[name];
    for (const name of envNames) delete process.env[name];

    const email = `local-admin-${tag}@example.test`;
    const password = "local-admin-password";
    const registered = await post("/v1/auth/register", { email, password }, {});
    expect(registered.statusCode).toBe(201);

    const loggedIn = await post("/v1/auth/login", { email, password }, {});
    expect(loggedIn.statusCode).toBe(200);
    localAdminKey = loggedIn.json().token;
    expect((await get("/v1/whoami", { authorization: `Bearer ${localAdminKey}` })).statusCode)
      .toBe(200);

    const session = await post("/v1/auth/session", {}, {
      authorization: `Bearer ${localAdminKey}`
    });
    expect(session.statusCode).toBe(200);
    const cookies = session.headers["set-cookie"];
    const list = Array.isArray(cookies) ? cookies : [cookies ?? ""];
    const cookie = list.map((value) => value.split(";")[0])
      .find((value) => value.startsWith("tg_session="));
    expect(cookie).toBeTruthy();
    localSessionCookie = cookie as string;

    const member = await post("/v1/users", {
      email: `local-member-${tag}@example.test`,
      password: "local-member-password",
      role: "member"
    });
    expect(member.statusCode).toBe(201);
    memberId = member.json().id;

    const key = await post(`/v1/users/${memberId}/keys`, {
      name: "legacy-local-key", scopes: ["read"], expires_days: 30
    });
    expect(key.statusCode).toBe(201);
    localMemberKey = key.json().key;

    const workspace = await post("/v1/workspaces", { name: `identity-hardening-${tag}` });
    expect(workspace.statusCode).toBe(201);
    workspaceId = workspace.json().id;
  });

  afterAll(async () => {
    for (const name of envNames) {
      const value = previous[name];
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    if (dir) rmSync(dir, { recursive: true, force: true });
    await api.close();
    await pool.end();
  });

  it("keeps the development identity plane usable before OAuth is configured", async () => {
    const member = await get("/v1/whoami", { authorization: `Bearer ${localMemberKey}` });
    expect(member.statusCode).toBe(200);
    expect(member.json().kind).toBe("user");

    const session = await get("/v1/auth/session", { cookie: localSessionCookie });
    expect(session.statusCode).toBe(200);
    expect(session.json().admin?.principal.kind).toBe("user");
  });

  it("closes local identity routes and rejects pre-existing local credentials in OAuth mode", async () => {
    dir = mkdtempSync(join(tmpdir(), "tg-identity-hardening-"));
    const jwks = join(dir, "jwks.json");
    writeFileSync(jwks, JSON.stringify({ keys: [] }));
    process.env.OAUTH_ISSUER = "https://issuer.identity-hardening.test";
    process.env.OAUTH_AUDIENCE = "http://localhost:8091/mcp";
    process.env.OAUTH_JWKS_FILE = jwks;
    delete process.env.OAUTH_JWKS_URL;

    const register = await post("/v1/auth/register", {
      email: `blocked-${tag}@example.test`, password: "blocked-password"
    }, {});
    expect(register.statusCode).toBe(403);
    expect(register.json().error).toBe("external_identity_required");

    const login = await post("/v1/auth/login", {
      email: `local-admin-${tag}@example.test`, password: "local-admin-password"
    }, {});
    expect(login.statusCode).toBe(403);
    expect(login.json().error).toBe("external_identity_required");

    expect((await post("/v1/users", {
      email: `blocked-user-${tag}@example.test`, password: "blocked-user-password"
    })).json().error).toBe("external_identity_required");

    expect((await post(`/v1/users/${memberId}/keys`, {
      name: "blocked", scopes: ["read"]
    })).json().error).toBe("external_identity_required");

    expect((await post(`/v1/users/${memberId}/memberships`, {
      workspace_id: workspaceId
    })).json().error).toBe("external_identity_required");

    // A local login key minted before OAuth must not authenticate afterward.
    expect((await get("/v1/whoami", {
      authorization: `Bearer ${localMemberKey}`
    })).statusCode).toBe(401);
    expect((await post("/v1/auth/session", {}, {
      authorization: `Bearer ${localAdminKey}`
    })).statusCode).toBe(401);

    // Nor may a pre-existing dashboard cookie keep a local user alive.
    expect((await get("/v1/projects", { cookie: localSessionCookie })).statusCode).toBe(401);
    const reported = await get("/v1/auth/session", { cookie: localSessionCookie });
    expect(reported.statusCode).toBe(200);
    expect(reported.json().admin).toBeNull();
  });
});
