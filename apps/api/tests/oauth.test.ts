import { createServer } from "node:http";
import { createPublicKey, generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { buildGateway } from "../src/gateway.js";
import { resolvePrincipal } from "../src/auth.js";
import { assertProductionAuth, oauthConfigFromEnv, verifyAccessToken } from "../src/oauth.js";

// §7.3 / FR-002: the gateway is an OAuth 2.1 protected resource. These tests
// mint real tokens with node:crypto against a real JWKS and assert every
// rejection reason, plus the RFC 9728 discovery surface.

const ISSUER = "https://issuer.test";
const AUDIENCE = "http://localhost:8091/mcp";
const PROTOCOL = "2026-07-28";

const b64 = (value: unknown): string =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

interface Signer {
  kid: string;
  alg: string;
  privateKey: KeyObject;
}

function mint(
  claims: Record<string, unknown>,
  signer: Signer,
  overrides: { header?: Record<string, unknown>; payloadOverride?: Record<string, unknown> } = {}
): string {
  const header = { alg: signer.alg, typ: "JWT", kid: signer.kid, ...(overrides.header ?? {}) };
  const payload = { ...claims, ...(overrides.payloadOverride ?? {}) };
  const signingInput = `${b64(header)}.${b64(payload)}`;
  const signature =
    signer.alg === "ES256"
      ? cryptoSign("sha256", Buffer.from(signingInput), { key: signer.privateKey, dsaEncoding: "ieee-p1363" })
      : signer.alg === "RS256"
        ? cryptoSign("RSA-SHA256", Buffer.from(signingInput), signer.privateKey)
        : cryptoSign(null, Buffer.from(signingInput), signer.privateKey);
  return `${signingInput}.${signature.toString("base64url")}`;
}

const dir = mkdtempSync(join(tmpdir(), "tg-oauth-"));
const jwksFile = join(dir, "jwks.json");

const ed = generateKeyPairSync("ed25519");
const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });

const signer = (kid: string, alg: string, privateKey: KeyObject): Signer => ({ kid, alg, privateKey });
const edSigner = signer("ed-1", "EdDSA", ed.privateKey);
const rsaSigner = signer("rsa-1", "RS256", rsa.privateKey);
const ecSigner = signer("ec-1", "ES256", ec.privateKey);

function jwkOf(key: KeyObject, kid: string): Record<string, unknown> {
  return { ...key.export({ format: "jwk" }), kid, use: "sig" };
}

const NOW = Math.floor(Date.now() / 1000);
const baseClaims = {
  iss: ISSUER,
  aud: AUDIENCE,
  // RFC 8707: the token names the gateway resource, not just its audience.
  resource: AUDIENCE,
  sub: "agent-7",
  exp: NOW + 300,
  scope: "gateway read",
  workspaces: ["ws-1"]
};

const originalEnv = { ...process.env };

beforeAll(() => {
  writeFileSync(
    jwksFile,
    JSON.stringify({
      keys: [
        jwkOf(createPublicKey(ed.privateKey), "ed-1"),
        jwkOf(createPublicKey(rsa.privateKey), "rsa-1"),
        jwkOf(createPublicKey(ec.privateKey), "ec-1")
      ]
    })
  );
  process.env.OAUTH_ISSUER = ISSUER;
  process.env.OAUTH_AUDIENCE = AUDIENCE;
  process.env.OAUTH_JWKS_FILE = jwksFile;
  delete process.env.OAUTH_JWKS_URL;
});

afterAll(() => {
  for (const key of ["OAUTH_ISSUER", "OAUTH_AUDIENCE", "OAUTH_JWKS_FILE", "OAUTH_JWKS_URL"]) {
    if (originalEnv[key] === undefined) delete process.env[key];
    else process.env[key] = originalEnv[key];
  }
  rmSync(dir, { recursive: true, force: true });
});

describe("OAuth access token validation", () => {
  const cfg = { issuer: ISSUER, audience: AUDIENCE, jwksFile };

  it("accepts a valid EdDSA token and reports its claims", async () => {
    const claims = await verifyAccessToken(mint(baseClaims, edSigner), cfg);
    expect(claims.sub).toBe("agent-7");
    expect(claims.scopes).toEqual(["gateway", "read"]);
    expect(claims.workspaces).toEqual(["ws-1"]);
  });

  it("verifies RS256 and ES256 tokens too", async () => {
    await expect(verifyAccessToken(mint(baseClaims, rsaSigner), cfg)).resolves.toMatchObject({ sub: "agent-7" });
    await expect(verifyAccessToken(mint(baseClaims, ecSigner), cfg)).resolves.toMatchObject({ sub: "agent-7" });
  });

  it("rejects a tampered payload with a valid-looking header", async () => {
    const token = mint(baseClaims, edSigner);
    const [header, , signature] = token.split(".");
    const forged = `${header}.${b64({ ...baseClaims, sub: "attacker" })}.${signature}`;
    await expect(verifyAccessToken(forged, cfg)).rejects.toThrow(/signature/);
  });

  it("rejects alg none, unknown issuer, wrong audience, expiry, and not-yet-valid", async () => {
    const none = mint(baseClaims, edSigner, { header: { alg: "none" } });
    await expect(verifyAccessToken(none, cfg)).rejects.toThrow(/not accepted/);

    const wrongIss = mint(baseClaims, edSigner, { payloadOverride: { iss: "https://evil.test" } });
    await expect(verifyAccessToken(wrongIss, cfg)).rejects.toThrow(/issuer/);

    const wrongAud = mint(baseClaims, edSigner, { payloadOverride: { aud: "https://other-resource" } });
    await expect(verifyAccessToken(wrongAud, cfg)).rejects.toThrow(/audience/);

    const missingResource = mint(baseClaims, edSigner, { payloadOverride: { resource: undefined } });
    await expect(verifyAccessToken(missingResource, cfg)).rejects.toThrow(/missing resource/);

    const wrongResource = mint(baseClaims, edSigner, {
      payloadOverride: { resource: "https://other-resource/mcp" }
    });
    await expect(verifyAccessToken(wrongResource, cfg)).rejects.toThrow(/wrong resource/);

    const expired = mint(baseClaims, edSigner, { payloadOverride: { exp: NOW - 3600 } });
    await expect(verifyAccessToken(expired, cfg)).rejects.toThrow(/expired/);

    const future = mint(baseClaims, edSigner, { payloadOverride: { nbf: NOW + 3600 } });
    await expect(verifyAccessToken(future, cfg)).rejects.toThrow(/not yet valid/);

    const unknownKid = mint(baseClaims, signer("ed-9", "EdDSA", ed.privateKey));
    await expect(verifyAccessToken(unknownKid, cfg)).rejects.toThrow(/no trusted key/);

    // Declaring ES256 while the kid names an RSA key must fail, not throw
    // out of the crypto layer.
    const wrongType = mint(baseClaims, signer("rsa-1", "ES256", ec.privateKey));
    await expect(verifyAccessToken(wrongType, cfg)).rejects.toThrow(/signature/);
  });

  it("accepts audience/resource lists and a space- or array-shaped scope claim", async () => {
    const listAud = mint(baseClaims, edSigner, {
      payloadOverride: {
        aud: ["https://other", AUDIENCE],
        resource: ["https://other-resource", `${AUDIENCE}/`],
        scope: undefined,
        scp: ["gateway", "approve"]
      }
    });
    const claims = await verifyAccessToken(listAud, cfg);
    expect(claims.scopes).toEqual(["gateway", "approve"]);
  });

  it("fails closed when the JWKS is unreadable", async () => {
    await expect(verifyAccessToken(mint(baseClaims, edSigner), { ...cfg, jwksFile: join(dir, "missing.json") }))
      .rejects.toThrow();
  });
});

describe("JWKS over HTTP", () => {
  // §7.3: key rotation must be picked up without a gateway restart, and a
  // client naming garbage kids must not turn every request into a fetch.
  const served = { keys: [jwkOf(createPublicKey(ed.privateKey), "ed-1")] };
  let hits = 0;
  const server = createServer((_req, res) => {
    hits += 1;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(served));
  });
  const cfg = { issuer: ISSUER, audience: AUDIENCE, jwksUrl: "" };

  beforeAll(async () => {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    cfg.jwksUrl = `http://127.0.0.1:${typeof address === "object" && address ? address.port : 0}/jwks`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("fetches keys, and picks up a rotated-in kid after the refresh interval", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      await expect(verifyAccessToken(mint(baseClaims, edSigner), cfg)).resolves.toMatchObject({ sub: "agent-7" });
      expect(hits).toBe(1);

      // The issuer rotates: new kid published, old one still served.
      const rotated = generateKeyPairSync("ed25519");
      served.keys = [jwkOf(createPublicKey(ed.privateKey), "ed-1"), jwkOf(createPublicKey(rotated.privateKey), "ed-2")];
      const rotatedToken = mint(baseClaims, signer("ed-2", "EdDSA", rotated.privateKey));

      // Immediately after a fetch, an unknown kid is refused rather than
      // triggering another outbound call.
      await expect(verifyAccessToken(rotatedToken, cfg)).rejects.toThrow(/no trusted key/);
      expect(hits).toBe(1);

      // Past the refresh interval the same token verifies: no restart needed.
      vi.setSystemTime(Date.now() + 11_000);
      await expect(verifyAccessToken(rotatedToken, cfg)).resolves.toMatchObject({ sub: "agent-7" });
      expect(hits).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("principal resolution in OAuth mode", () => {
  it("maps a validated token to an oauth principal and drops ungranted scopes", async () => {
    const token = mint({ ...baseClaims, scope: "gateway read evolve admin" }, edSigner);
    const principal = await resolvePrincipal(`Bearer ${token}`);
    expect(principal).toMatchObject({ kind: "oauth", userId: "agent-7", workspaces: ["ws-1"] });
    expect(principal?.scopes).toEqual(["gateway", "read", "admin"]);
  });

  it("a token with no workspaces claim authenticates but can write nowhere", async () => {
    const token = mint({ ...baseClaims, workspaces: undefined }, edSigner);
    const principal = await resolvePrincipal(`Bearer ${token}`);
    expect(principal?.workspaces).toEqual([]);
  });

  it("returns no principal for an invalid token and does not fall through", async () => {
    const token = mint(baseClaims, edSigner, { payloadOverride: { aud: "https://elsewhere" } });
    await expect(resolvePrincipal(`Bearer ${token}`)).resolves.toBeNull();
  });

  it("keeps accepting the static development keys outside production", async () => {
    const principal = await resolvePrincipal(`Bearer ${process.env.API_KEY}`);
    expect(principal).toMatchObject({ kind: "env" });
  });

  it("stops accepting static keys when NODE_ENV=production", async () => {
    process.env.NODE_ENV = "production";
    try {
      await expect(resolvePrincipal(`Bearer ${process.env.API_KEY}`)).resolves.toBeNull();
    } finally {
      delete process.env.NODE_ENV;
    }
  });
});

describe("production configuration", () => {
  it("refuses to start in production without an issuer", () => {
    expect(() => assertProductionAuth({ NODE_ENV: "production", API_KEY: "x" })).toThrow(/OAUTH_ISSUER/);
  });

  it("accepts a fully configured OAuth deployment", () => {
    expect(() =>
      assertProductionAuth({
        NODE_ENV: "production",
        OAUTH_ISSUER: ISSUER,
        OAUTH_AUDIENCE: AUDIENCE,
        OAUTH_JWKS_FILE: jwksFile
      })
    ).not.toThrow();
  });

  it("reads a JWKS URL as an alternative to a file", () => {
    const cfg = oauthConfigFromEnv({
      OAUTH_ISSUER: ISSUER,
      OAUTH_AUDIENCE: AUDIENCE,
      OAUTH_JWKS_URL: "https://issuer.test/jwks"
    });
    expect(cfg?.jwksUrl).toBe("https://issuer.test/jwks");
  });
});

describe("gateway discovery surface in OAuth mode", () => {
  const gw = buildGateway();
  afterAll(async () => {
    await gw.close();
  });

  it("serves the protected-resource metadata document", async () => {
    const res = await gw.inject({ method: "GET", url: "/.well-known/oauth-protected-resource" });
    expect(res.statusCode).toBe(200);
    const body = res.json() as Record<string, unknown>;
    expect(body.resource).toBe(AUDIENCE);
    expect(body.authorization_servers).toEqual([ISSUER]);
  });

  it("challenges an unauthenticated MCP request with the metadata URL", async () => {
    const res = await gw.inject({
      method: "POST", url: "/mcp",
      headers: { "mcp-protocol-version": PROTOCOL, "mcp-method": "server/discover" },
      payload: { jsonrpc: "2.0", id: 1, method: "server/discover", params: {} }
    });
    expect(res.statusCode).toBe(401);
    expect(res.headers["www-authenticate"]).toContain("resource_metadata=");
    expect(res.headers["www-authenticate"]).toContain("/.well-known/oauth-protected-resource");
  });

  it("lets a JWT-authenticated client reach the MCP surface", async () => {
    const token = mint({ ...baseClaims, scope: "gateway" }, edSigner);
    const res = await gw.inject({
      method: "POST", url: "/mcp",
      headers: {
        authorization: `Bearer ${token}`,
        "mcp-protocol-version": PROTOCOL,
        "mcp-method": "server/discover"
      },
      payload: {
        jsonrpc: "2.0", id: 1, method: "server/discover",
        params: {
          _meta: {
            "io.modelcontextprotocol/protocolVersion": PROTOCOL,
            "io.modelcontextprotocol/clientCapabilities": { tools: {} }
          }
        }
      }
    });
    expect(res.statusCode).toBe(200);
    expect((res.json() as { result: { capabilities: unknown } }).result.capabilities)
      .toEqual({ tools: { listChanged: false } });
  });

  it("rejects a JWT signed by the wrong key", async () => {
    const other = generateKeyPairSync("ed25519");
    const token = mint({ ...baseClaims, scope: "gateway" }, signer("ed-1", "EdDSA", other.privateKey));
    const res = await gw.inject({
      method: "POST", url: "/mcp",
      headers: { authorization: `Bearer ${token}`, "mcp-protocol-version": PROTOCOL, "mcp-method": "server/discover" },
      payload: { jsonrpc: "2.0", id: 1, method: "server/discover", params: {} }
    });
    expect(res.statusCode).toBe(401);
  });
});
