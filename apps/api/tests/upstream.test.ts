import { describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import { createServer } from "node:http";
import { checkUpstreamUrl, guardedFetch, isPrivateHost } from "../src/upstream.js";

// The SSRF gate guards registration and is re-checked at discover and call
// time. These cases pin the ranges the old prefix check missed (metadata,
// unspecified, CGNAT, ULA, link-local, v4-mapped) and the shapes that must
// stay public.
describe("upstream URL validation", () => {
  it("flags private, loopback, link-local, and unspecified addresses", () => {
    for (const host of [
      "localhost", "api.localhost", "svc.internal",
      "127.0.0.1", "127.99.1.2", "10.0.0.1", "172.16.0.1", "172.31.255.254",
      "192.168.1.1", "169.254.169.254", "0.0.0.0", "100.64.0.1",
      "::1", "::", "fc00::1", "fd12:3456::1", "fe80::1", "::ffff:10.0.0.1"
    ]) {
      expect(isPrivateHost(host), host).toBe(true);
    }
  });

  it("leaves public hosts alone", () => {
    for (const host of ["example.com", "8.8.8.8", "172.32.0.1", "192.169.0.1", "2001:4860:4860::8888"]) {
      expect(isPrivateHost(host), host).toBe(false);
    }
  });

  it("rejects non-http schemes, credentials, and unparseable URLs", () => {
    expect(checkUpstreamUrl("ftp://evil/x").ok).toBe(false);
    expect(checkUpstreamUrl("http://user:pw@example.com/mcp").ok).toBe(false);
    expect(checkUpstreamUrl("not a url").ok).toBe(false);
  });

  it("never allows the cloud metadata address, even with private upstreams enabled", () => {
    const prev = process.env.ALLOW_PRIVATE_UPSTREAMS;
    process.env.ALLOW_PRIVATE_UPSTREAMS = "true";
    try {
      const res = checkUpstreamUrl("http://169.254.169.254/latest/meta-data");
      expect(res.ok).toBe(false);
      expect(res.reason).toContain("metadata");
    } finally {
      if (prev === undefined) delete process.env.ALLOW_PRIVATE_UPSTREAMS;
      else process.env.ALLOW_PRIVATE_UPSTREAMS = prev;
    }
  });

  it("gates other private hosts behind the environment flag", () => {
    const prev = process.env.ALLOW_PRIVATE_UPSTREAMS;
    delete process.env.ALLOW_PRIVATE_UPSTREAMS;
    try {
      expect(checkUpstreamUrl("http://10.0.0.5/mcp").ok).toBe(false);
      expect(checkUpstreamUrl("http://example.com/mcp").ok).toBe(true);
    } finally {
      process.env.ALLOW_PRIVATE_UPSTREAMS = prev ?? "true";
    }
  });
});

// The gate above runs at registration and again at discover and call, but the
// transport resolves the name a third time when it opens the socket, so a name
// that answered publicly at those checks and privately a moment later would
// still be dialled. These two cases hold the last hop: one that the guard must
// stop, and one it must not.
describe("upstream request guard", () => {
  async function listen(): Promise<{ url: string; hits: () => number; close: () => Promise<void> }> {
    let hits = 0;
    const server = createServer((_req, res) => { hits += 1; res.end("ok"); });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;
    return {
      url: `http://127.0.0.1:${port}/mcp`,
      hits: () => hits,
      close: () => new Promise<void>((resolve) => server.close(() => resolve()))
    };
  }

  async function withPrivateUpstreams(value: string | undefined, run: () => Promise<void>) {
    const prev = process.env.ALLOW_PRIVATE_UPSTREAMS;
    if (value === undefined) delete process.env.ALLOW_PRIVATE_UPSTREAMS;
    else process.env.ALLOW_PRIVATE_UPSTREAMS = value;
    try {
      await run();
    } finally {
      if (prev === undefined) delete process.env.ALLOW_PRIVATE_UPSTREAMS;
      else process.env.ALLOW_PRIVATE_UPSTREAMS = prev;
    }
  }

  it("refuses a private address at request time, and the request never lands", async () => {
    // A row can exist without having passed the gate: a direct insert, a
    // restore, or a name that resolved publicly when it was registered.
    const upstream = await listen();
    try {
      await withPrivateUpstreams(undefined, async () => {
        await expect(guardedFetch(upstream.url)).rejects.toThrow(/private/);
      });
      expect(upstream.hits(), "the request must never reach the upstream").toBe(0);
    } finally {
      await upstream.close();
    }
  });

  it("still reaches an allowed upstream, so the guard is not a blanket refusal", async () => {
    const upstream = await listen();
    try {
      await withPrivateUpstreams("true", async () => {
        const res = await guardedFetch(upstream.url);
        expect(res.status).toBe(200);
      });
      expect(upstream.hits()).toBe(1);
    } finally {
      await upstream.close();
    }
  });
});
