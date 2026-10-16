import { describe, expect, it } from "vitest";
import { checkUpstreamUrl, isPrivateHost } from "../src/upstream.js";

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
