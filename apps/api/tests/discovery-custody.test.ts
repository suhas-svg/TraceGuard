import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildApp } from "../src/index.js";
import { buildGatewayInternal } from "../src/gateway.js";
import { pool } from "../src/db.js";

// ADR-0010: only the gateway resolves upstream credentials. The API delegates
// discovery over an unpublished internal listener guarded by a shared token.
// These tests pin the delegation contract itself: the token gate, the error
// vocabulary, and the API's fail-closed behaviour when the gateway is absent.
describe("gateway-only credential custody", () => {
  const api = buildApp();
  const internal = buildGatewayInternal();
  const key = { authorization: "Bearer test_key" };
  const token = { authorization: `Bearer ${process.env.GATEWAY_INTERNAL_TOKEN}` };
  const tag = Date.now().toString(36);
  let serverId = "";
  let secretServerId = "";
  const baseUrl = "http://127.0.0.1:9/mcp";

  async function register(name: string, extra: Record<string, unknown> = {}): Promise<string> {
    const res = await api.inject({
      method: "POST",
      url: "/v1/servers",
      headers: key,
      payload: { name: `${name}-${tag}`, base_url: baseUrl, ...extra }
    });
    expect(res.statusCode).toBe(201);
    return res.json().id as string;
  }

  beforeAll(async () => {
    serverId = await register("custody");
    secretServerId = await register("custody-secret", { secret_ref: "env:TG_TEST_MISSING_SECRET" });
  });

  afterAll(async () => {
    await internal.close();
    await api.close();
    await pool.end();
  });

  it("refuses the internal listener without the right bearer token", async () => {
    const missing = await internal.inject({
      method: "POST",
      url: `/internal/v1/servers/${serverId}/discover`
    });
    expect(missing.statusCode).toBe(401);
    expect(missing.json().error).toBe("unauthorized");

    const wrong = await internal.inject({
      method: "POST",
      url: `/internal/v1/servers/${serverId}/discover`,
      headers: { authorization: "Bearer not_the_token" }
    });
    expect(wrong.statusCode).toBe(401);
  });

  it("keeps its health probe open", async () => {
    const res = await internal.inject({ method: "GET", url: "/healthz" });
    expect(res.statusCode).toBe(200);
    expect(res.json().ok).toBe(true);
  });

  it("returns 404 for an unknown server", async () => {
    const res = await internal.inject({
      method: "POST",
      url: `/internal/v1/servers/${randomUUID()}/discover`,
      headers: token
    });
    expect(res.statusCode).toBe(404);
    expect(res.json().error).toBe("server_not_found");
  });

  it("refuses a disabled server", async () => {
    const id = await register("custody-disabled");
    await pool.query("UPDATE mcp_servers SET disabled_at = now() WHERE id = $1", [id]);
    const res = await internal.inject({
      method: "POST",
      url: `/internal/v1/servers/${id}/discover`,
      headers: token
    });
    expect(res.statusCode).toBe(409);
    expect(res.json().error).toBe("server_disabled");
  });

  it("refuses an upstream that does not resolve", async () => {
    const id = await register("custody-unsafe");
    await pool.query("UPDATE mcp_servers SET base_url = $1 WHERE id = $2", [
      "http://does-not-resolve.invalid/mcp",
      id
    ]);
    // The suite allows private upstreams so it can dial a local mock, which
    // also short-circuits the name check. Turn that off for this case so the
    // resolver actually classifies the host, then exercise both layers: the
    // API's pre-dispatch recheck and the gateway's own check.
    const previous = process.env.ALLOW_PRIVATE_UPSTREAMS;
    delete process.env.ALLOW_PRIVATE_UPSTREAMS;
    try {
      const direct = await internal.inject({
        method: "POST",
        url: `/internal/v1/servers/${id}/discover`,
        headers: token
      });
      expect(direct.statusCode).toBe(400);
      expect(direct.json().error).toBe("unsafe_upstream");

      const viaApi = await api.inject({
        method: "POST",
        url: `/v1/servers/${id}/discover`,
        headers: key
      });
      expect(viaApi.statusCode).toBe(400);
      expect(viaApi.json().error).toBe("unsafe_upstream");
    } finally {
      if (previous === undefined) delete process.env.ALLOW_PRIVATE_UPSTREAMS;
      else process.env.ALLOW_PRIVATE_UPSTREAMS = previous;
    }
  });

  it("reports an unavailable secret without leaking it", async () => {
    const res = await internal.inject({
      method: "POST",
      url: `/internal/v1/servers/${secretServerId}/discover`,
      headers: token
    });
    expect(res.statusCode).toBe(503);
    expect(res.json().error).toBe("secret_unavailable");
    expect(JSON.stringify(res.json())).not.toContain("TG_TEST_MISSING_SECRET");
  });

  it("fails closed when the API has no gateway URL", async () => {
    const saved = process.env.GATEWAY_INTERNAL_URL;
    delete process.env.GATEWAY_INTERNAL_URL;
    try {
      const res = await api.inject({
        method: "POST",
        url: `/v1/servers/${serverId}/discover`,
        headers: key
      });
      expect(res.statusCode).toBe(503);
      expect(res.json().error).toBe("discovery_unavailable");
    } finally {
      process.env.GATEWAY_INTERNAL_URL = saved;
    }
  });

  it("fails closed when the gateway is unreachable", async () => {
    const saved = process.env.GATEWAY_INTERNAL_URL;
    process.env.GATEWAY_INTERNAL_URL = "http://127.0.0.1:1";
    try {
      const res = await api.inject({
        method: "POST",
        url: `/v1/servers/${serverId}/discover`,
        headers: key
      });
      expect(res.statusCode).toBe(503);
      expect(res.json().error).toBe("discovery_unavailable");
    } finally {
      process.env.GATEWAY_INTERNAL_URL = saved;
    }
  });
});
