#!/usr/bin/env node
// NFR-009: a clean-clone run of the production auth profile. The dev stack
// runs on static bearer keys; this script proves that a checkout plus a
// generated OAuth issuer boots both services in production mode, refuses the
// static keys, and accepts a real RS256 access token end to end.
// Run after the tsc matrix (it imports apps/api/dist), from the repo root.
import { createServer } from "node:http";
import { generateKeyPairSync, randomUUID, sign as signBytes } from "node:crypto";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const kid = "clean-run";
// The issuer names workspace ids; a fresh UUID keeps the run independent of any
// seeded data while still exercising the scoped read path.
const workspaceId = randomUUID();
const jwk = publicKey.export({ format: "jwk" });
const jwksDoc = { keys: [{ ...jwk, kid, alg: "RS256", use: "sig" }] };

const jwksHttp = createServer((req, res) => {
  if (req.url?.startsWith("/jwks.json")) {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(jwksDoc));
    return;
  }
  res.writeHead(404).end();
});
await new Promise((resolve) => jwksHttp.listen(0, "127.0.0.1", resolve));
const jwksPort = jwksHttp.address().port;
const issuer = `http://127.0.0.1:${jwksPort}`;
const audience = "http://traceguard.test/gateway";

const apiKey = process.env.CLEAN_RUN_API_KEY ?? "clean_run_key";
const approverKey = process.env.CLEAN_RUN_APPROVER_KEY ?? "clean_run_approver";
Object.assign(process.env, {
  NODE_ENV: "production",
  OAUTH_ISSUER: issuer,
  OAUTH_AUDIENCE: audience,
  OAUTH_JWKS_URL: `${issuer}/jwks.json`,
  API_KEY: apiKey,
  APPROVER_KEY: approverKey,
  APPROVAL_ARGS_KEY: process.env.APPROVAL_ARGS_KEY ?? "ab".repeat(32)
});

const apiModule = await import(new URL("../../apps/api/dist/index.js", import.meta.url).href);
const gatewayModule = await import(new URL("../../apps/api/dist/gateway.js", import.meta.url).href);

const b64url = (value) => Buffer.from(value).toString("base64url");
const mint = (scopes) => {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: "RS256", kid, typ: "JWT" }));
  const payload = b64url(JSON.stringify({
    iss: issuer, aud: audience, resource: audience, sub: "clean-run-user", scope: scopes,
    workspaces: [workspaceId], iat: now, exp: now + 300
  }));
  const signature = b64url(signBytes("RSA-SHA256", Buffer.from(`${header}.${payload}`), privateKey));
  return `${header}.${payload}.${signature}`;
};

let failures = 0;
const check = (name, ok, detail = "") => {
  console.log(`${ok ? "ok" : "FAIL"} ${name}${detail ? ` - ${detail}` : ""}`);
  if (!ok) failures += 1;
};

const api = apiModule.buildApp();
await api.listen({ host: "127.0.0.1", port: 0 });
const gw = gatewayModule.buildGateway();
await gw.listen({ host: "127.0.0.1", port: 0 });
const apiPort = api.server.address().port;
const gwPort = gw.server.address().port;

const request = async (base, method, path, headers, body) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { "content-type": "application/json", ...headers },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  return { status: res.status, body: await res.json().catch(() => null) };
};

const staticHeaders = { authorization: `Bearer ${apiKey}` };
const bearer = (token) => ({ authorization: `Bearer ${token}` });

try {
  const staticOverview = await request(`http://127.0.0.1:${apiPort}`, "GET", "/v1/overview", staticHeaders);
  check("static key is refused in production", staticOverview.status === 401, `HTTP ${staticOverview.status}`);

  const oauthOverview = await request(`http://127.0.0.1:${apiPort}`, "GET", "/v1/overview", bearer(mint("read")));
  check("OAuth read token reaches the API", oauthOverview.status === 200, `HTTP ${oauthOverview.status}`);

  const discover = await request(
    `http://127.0.0.1:${gwPort}`, "POST", "/mcp",
    {
      ...bearer(mint("gateway")),
      "mcp-protocol-version": "2026-07-28",
      "mcp-method": "server/discover"
    },
    {
      jsonrpc: "2.0",
      id: "clean-1",
      method: "server/discover",
      params: {
        _meta: {
          "io.modelcontextprotocol/protocolVersion": "2026-07-28",
          "io.modelcontextprotocol/clientCapabilities": { tools: {} }
        }
      }
    }
  );
  const discovered = discover.body;
  check(
    "OAuth gateway token reaches MCP",
    discover.status === 200 && discovered?.result?.serverInfo?.name === "traceguard-gateway",
    `HTTP ${discover.status}`
  );

  const staticMcp = await request(
    `http://127.0.0.1:${gwPort}`, "POST", "/mcp",
    { ...staticHeaders, "mcp-protocol-version": "2026-07-28", "mcp-method": "server/discover" },
    { jsonrpc: "2.0", id: "clean-2", method: "server/discover", params: {} }
  );
  check("static key is refused at the gateway", staticMcp.status === 401, `HTTP ${staticMcp.status}`);
} finally {
  await api.close();
  await gw.close();
  await new Promise((resolve) => jwksHttp.close(() => resolve()));
}

if (failures > 0) {
  console.error(`oauth clean run: ${failures} failure(s)`);
  process.exit(1);
}
console.log("oauth clean run: production auth profile works from a clean checkout");
process.exit(0);
