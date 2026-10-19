import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CertifiedClient, OAuthClientError, ShimError } from "../src/index.js";

// FR-002, client half: the shim discovers the protected-resource metadata,
// discovers the authorization server it names, asks for a token with the
// RFC 8707 resource indicator, checks the issuer binding, caches the token,
// and refreshes once on a 401. A real HTTP server plays both the gateway and
// the issuer, because the shim's half of the contract is HTTP.

// The resource and issuer are the test server itself; a request to any other
// host would leave the test process, which is exactly what the fake names in
// the mismatch cases assert against (they are compared, never fetched).
let RESOURCE = "";
let ISSUER = "";

interface Recorded {
  url: string;
  authorization?: string;
  body: string;
}

let server: ReturnType<typeof createServer>;
let base = "";
let requests: Recorded[] = [];
let mcpCalls: Recorded[] = [];
let tokenRequests = 0;
let counter = 0;
const valid = new Set<string>();
const stale = new Set<string>();
let poisonFirst = false;
let advertiseResource = "";
let advertiseIssuer = "";
let metadataIssuer = "";
let servePathAppended = false;
let tokenIssuer = "";

function body(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => resolve(data));
  });
}

function json(res: ServerResponse, status: number, payload: unknown, headers: Record<string, string> = {}) {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(payload));
}

beforeAll(async () => {
  server = createServer(async (req, res) => {
    const url = `${base}${req.url}`;
    const payload = req.method === "POST" ? await body(req) : "";
    const authorization = req.headers.authorization as string | undefined;
    requests.push({ url, authorization, body: payload });

    if (servePathAppended && req.url === "/.well-known/oauth-protected-resource/mcp") {
      return json(res, 200, {
        resource: advertiseResource,
        authorization_servers: [advertiseIssuer],
        scopes_supported: ["gateway"]
      });
    }
    if (req.url === "/.well-known/oauth-protected-resource") {
      return json(res, 200, {
        resource: advertiseResource,
        authorization_servers: [advertiseIssuer],
        scopes_supported: ["gateway"]
      });
    }
    if (req.url === "/.well-known/oauth-authorization-server") {
      return json(res, 200, {
        issuer: metadataIssuer,
        token_endpoint: `${base}/token`,
        grant_types_supported: ["client_credentials"]
      });
    }
    if (req.url === "/token") {
      tokenRequests += 1;
      const token = `tok-${++counter}`;
      (poisonFirst && tokenRequests === 1 ? stale : valid).add(token);
      return json(res, 200, {
        access_token: token, token_type: "Bearer", expires_in: 300,
        ...(tokenIssuer ? { iss: tokenIssuer } : {})
      });
    }
    if (req.url === "/mcp") {
      mcpCalls.push({ url, authorization, body: payload });
      const presented = authorization?.replace(/^Bearer /, "") ?? "";
      if (!valid.has(presented)) {
        return json(res, 401, { error: "invalid_token" }, {
          "www-authenticate": `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource"`
        });
      }
      const rpc = JSON.parse(payload) as { id: unknown };
      return json(res, 200, { jsonrpc: "2.0", id: rpc.id, result: { ok: true } });
    }
    res.writeHead(404).end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  base = `http://127.0.0.1:${port}`;
  RESOURCE = `${base}/mcp`;
  ISSUER = base;
  advertiseResource = RESOURCE;
  advertiseIssuer = ISSUER;
  metadataIssuer = ISSUER;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("OAuth client half", () => {
  it("discovers both metadata documents, sends the resource indicator, and calls with the token", async () => {
    requests = [];
    mcpCalls = [];
    tokenRequests = 0;
    valid.clear();
    const c = new CertifiedClient({
      url: `${base}/mcp`,
      oauth: { resource: RESOURCE, clientId: "agent-1", clientSecret: "s3cret" },
      retryIntervalMs: 10
    });

    await expect(c.callTool("read_file", { path: "/notes.txt" })).resolves.toEqual({ ok: true });

    const urls = requests.map((r) => r.url);
    expect(urls).toContain(`${base}/.well-known/oauth-protected-resource`);
    expect(urls).toContain(`${base}/.well-known/oauth-authorization-server`);

    const tokenRequest = requests.find((r) => r.url === `${base}/token`);
    expect(tokenRequest).toBeTruthy();
    const form = new URLSearchParams(tokenRequest!.body);
    expect(form.get("grant_type")).toBe("client_credentials");
    expect(form.get("resource")).toBe(RESOURCE);
    expect(form.get("scope")).toBeNull();
    // The client authenticated as itself, and the access token never went to
    // the issuer (no pass-through).
    expect(tokenRequest!.authorization).toBe(`Basic ${Buffer.from("agent-1:s3cret").toString("base64")}`);
    for (const r of requests) {
      if (r.url !== `${base}/mcp`) expect(r.authorization ?? "").not.toContain("tok-");
    }
    expect(mcpCalls).toHaveLength(1);
    expect(mcpCalls[0].authorization).toBe("Bearer tok-1");
  });

  it("sends requested scopes and a public client id in the body", async () => {
    requests = [];
    valid.clear();
    const c = new CertifiedClient({
      url: `${base}/mcp`,
      oauth: { resource: RESOURCE, clientId: "public-agent", scopes: ["gateway", "approve"] },
      retryIntervalMs: 10
    });

    await c.callTool("read_file", {});

    const tokenRequest = requests.find((r) => r.url === `${base}/token`)!;
    const form = new URLSearchParams(tokenRequest.body);
    expect(form.get("scope")).toBe("gateway approve");
    expect(form.get("client_id")).toBe("public-agent");
    expect(tokenRequest.authorization).toBeUndefined();
  });

  it("refuses an authorization server whose metadata names another issuer", async () => {
    metadataIssuer = "http://somewhere-else.test";
    try {
      const c = new CertifiedClient({
        url: `${base}/mcp`,
        oauth: { resource: RESOURCE, clientId: "agent-1" },
        retryIntervalMs: 10
      });
      await expect(c.callTool("read_file", {})).rejects.toThrow(/names issuer/);
      await expect(c.callTool("read_file", {})).rejects.toBeInstanceOf(OAuthClientError);
    } finally {
      metadataIssuer = ISSUER;
    }
  });

  it("refuses protected-resource metadata for a different resource", async () => {
    advertiseResource = "http://elsewhere.test/mcp";
    try {
      const c = new CertifiedClient({
        url: `${base}/mcp`,
        oauth: { resource: RESOURCE, clientId: "agent-1" },
        retryIntervalMs: 10
      });
      await expect(c.callTool("read_file", {})).rejects.toThrow(/advertises resource/);
    } finally {
      advertiseResource = RESOURCE;
    }
  });

  it("refuses an issuer the gateway does not advertise when one is pinned", async () => {
    advertiseIssuer = "http://other-issuer.test";
    try {
      const c = new CertifiedClient({
        url: `${base}/mcp`,
        oauth: { resource: RESOURCE, clientId: "agent-1", issuer: ISSUER },
        retryIntervalMs: 10
      });
      await expect(c.callTool("read_file", {})).rejects.toThrow(/does not accept tokens from issuer/);
    } finally {
      advertiseIssuer = ISSUER;
    }
  });

  it("caches the token until it expires", async () => {
    valid.clear();
    tokenRequests = 0;
    let clock = 0;
    const c = new CertifiedClient({
      url: `${base}/mcp`,
      oauth: { resource: RESOURCE, clientId: "agent-1", nowMs: () => clock },
      retryIntervalMs: 10
    });

    await c.callTool("read_file", {});
    await c.callTool("read_file", {});
    expect(tokenRequests).toBe(1);

    clock += 400_000; // past expires_in (300s)
    await c.callTool("read_file", {});
    expect(tokenRequests).toBe(2);
  });

  it("refreshes once on a 401 and retries the call", async () => {
    valid.clear();
    stale.clear();
    tokenRequests = 0;
    counter = 0;
    mcpCalls = [];
    poisonFirst = true;
    const c = new CertifiedClient({
      url: `${base}/mcp`,
      oauth: { resource: RESOURCE, clientId: "agent-1" },
      retryIntervalMs: 10
    });

    await expect(c.callTool("read_file", {})).resolves.toEqual({ ok: true });
    expect(mcpCalls).toHaveLength(2);
    expect(mcpCalls[0].authorization).toBe("Bearer tok-1");
    expect(mcpCalls[1].authorization).toBe("Bearer tok-2");
    expect(tokenRequests).toBe(2);
    poisonFirst = false;
  });

  it("prefers the path-appended protected-resource metadata (RFC 9728)", async () => {
    requests = [];
    valid.clear();
    servePathAppended = true;
    try {
      const c = new CertifiedClient({
        url: `${base}/mcp`,
        oauth: { resource: RESOURCE, clientId: "agent-1" },
        retryIntervalMs: 10
      });
      await c.callTool("read_file", {});
      expect(requests[0]?.url).toBe(`${base}/.well-known/oauth-protected-resource/mcp`);
    } finally {
      servePathAppended = false;
    }
  });

  it("refuses a token response whose iss names another issuer (RFC 9207)", async () => {
    valid.clear();
    tokenIssuer = "http://somewhere-else.test";
    try {
      const c = new CertifiedClient({
        url: `${base}/mcp`,
        oauth: { resource: RESOURCE, clientId: "agent-1" },
        retryIntervalMs: 10
      });
      await expect(c.callTool("read_file", {})).rejects.toThrow(/minted the token for issuer/);
      await expect(c.callTool("read_file", {})).rejects.toBeInstanceOf(OAuthClientError);
    } finally {
      tokenIssuer = "";
    }
  });

  it("requires exactly one credential", () => {
    expect(() => new CertifiedClient({ url: `${base}/mcp` })).toThrow(ShimError);
    expect(() => new CertifiedClient({
      url: `${base}/mcp`, token: "static",
      oauth: { resource: RESOURCE, clientId: "agent-1" }
    })).toThrow(/exactly one/);
    expect(() => new CertifiedClient({
      url: `${base}/mcp`,
      oauth: { resource: RESOURCE, clientId: "" }
    })).toThrow(/client id/);
  });
});
