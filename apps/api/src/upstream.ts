import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { sha256Hex, stableStringify } from "./policy.js";

export interface DiscoveredTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

// Hash of name, description, and schema. A changed upstream definition gets a
// new hash and the tool is quarantined until a human re-approves it.
export function definitionHash(tool: DiscoveredTool): string {
  return sha256Hex(stableStringify([tool.name, tool.description, tool.inputSchema]));
}

// SSRF guard: http(s) only, no credentials in the URL, cloud metadata
// addresses never, and private hosts only when the operator opts in for
// local development. Discover and call re-run the resolved variant so a
// rebinding name cannot dodge the registration gate.
export function isPrivateHost(host: string): boolean {
  const h = (host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host).toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".internal")) return true;
  if (h === "::1" || h === "::") return true;
  if (/^f[cd][0-9a-f]*:/.test(h)) return true; // fc00::/7 unique local
  if (/^fe[89ab][0-9a-f]*:/.test(h)) return true; // fe80::/10 link local
  const mapped = h.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateHost(mapped[1]);
  const hexMapped = h.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hexMapped) {
    const hi = parseInt(hexMapped[1], 16);
    const lo = parseInt(hexMapped[2], 16);
    return isPrivateHost(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
  }
  const v4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const octets = [Number(v4[1]), Number(v4[2]), Number(v4[3]), Number(v4[4])];
    if (octets.some((n) => n > 255)) return false;
    const [a, b] = octets;
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }
  return false;
}

export function checkUpstreamUrl(raw: string): { ok: boolean; reason?: string } {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: "not a valid URL" };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, reason: "only http and https upstreams are allowed" };
  }
  if (url.username || url.password) {
    return { ok: false, reason: "credentials in the URL are not allowed" };
  }
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  // The metadata service is never a legitimate upstream; deny it outright
  // so a misconfigured environment cannot reach cloud credentials.
  if (host === "169.254.169.254") {
    return { ok: false, reason: "cloud metadata addresses are never allowed" };
  }
  if (isPrivateHost(host) && process.env.ALLOW_PRIVATE_UPSTREAMS !== "true") {
    return { ok: false, reason: "private upstream hosts need ALLOW_PRIVATE_UPSTREAMS=true" };
  }
  return { ok: true };
}

// Resolve DNS names and reject those pointing at private ranges, unless the
// operator explicitly allowed private upstreams. IP literals were already
// classified by checkUpstreamUrl.
export async function checkUpstreamUrlResolved(raw: string): Promise<{ ok: boolean; reason?: string }> {
  const sync = checkUpstreamUrl(raw);
  if (!sync.ok) return sync;
  if (process.env.ALLOW_PRIVATE_UPSTREAMS === "true") return { ok: true };
  const host = new URL(raw).hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":")) return { ok: true };
  const { lookup } = await import("node:dns/promises");
  let address: string;
  try {
    ({ address } = await lookup(host));
  } catch {
    return { ok: false, reason: "upstream host does not resolve" };
  }
  if (isPrivateHost(address)) {
    return { ok: false, reason: "upstream host resolves to a private address" };
  }
  return { ok: true };
}

interface PooledClient {
  client: Client;
  queue: Promise<unknown>;
  lastUsed: number;
}

const pool = new Map<string, PooledClient>();
const IDLE_MS = 60_000;

// Operator-tunable ceiling on one upstream exchange. The MCP SDK's own 60s
// protocol default rejects the promise but never aborts the HTTP request, so a
// hung upstream would pin the socket and this server's pool slot. The signal
// is created per request, not per client: a signal made at connect time would
// expire 60s after the client was opened and then abort every later call.
const UPSTREAM_TIMEOUT_MS = Math.max(1_000, Number(process.env.UPSTREAM_TIMEOUT_MS ?? 60_000));

function timeoutFetch(url: string | URL, init?: RequestInit): Promise<Response> {
  return fetch(url, { ...init, signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS) });
}

function poolKey(baseUrl: string, authSecret: string | null): string {
  return sha256Hex(`${baseUrl}|${authSecret ?? ""}`);
}

async function openClient(baseUrl: string, authSecret: string | null): Promise<Client> {
  const headers = authSecret ? { Authorization: "Bearer " + authSecret } : undefined;
  const transport = new StreamableHTTPClientTransport(new URL(baseUrl), {
    requestInit: { headers },
    fetch: timeoutFetch
  });
  const client = new Client({ name: "traceguard-gateway", version: "0.1.0" });
  // The gateway holds upstream credentials and injects them here. Agent
  // tokens never leave the gateway toward upstream servers.
  await client.connect(transport);
  return client;
}

function dropPooled(key: string): void {
  const entry = pool.get(key);
  if (entry) {
    pool.delete(key);
    entry.client.close().catch(() => undefined);
  }
}

// One reused client per upstream. Calls to the same server queue behind each
// other on a promise chain, so two concurrent calls never share one MCP
// exchange. Idle clients reconnect on next use. Only read-only discovery
// retries once after a transport failure; a tool call never does, because a
// lost response does not prove the tool did not run (spec section 14).
async function withClient<T>(
  baseUrl: string,
  authSecret: string | null,
  fn: (client: Client) => Promise<T>,
  retryTransport = false
): Promise<T> {
  const key = poolKey(baseUrl, authSecret);
  const run = async (retried: boolean): Promise<T> => {
    let entry = pool.get(key);
    if (!entry || Date.now() - entry.lastUsed > IDLE_MS) {
      dropPooled(key);
      entry = { client: await openClient(baseUrl, authSecret), queue: Promise.resolve(), lastUsed: Date.now() };
      pool.set(key, entry);
    }
    const current = entry;
    const task = current.queue.then(async () => {
      current.lastUsed = Date.now();
      return fn(current.client);
    });
    current.queue = task.catch(() => undefined);
    try {
      return await task;
    } catch (err) {
      // A failed exchange may poison the pooled client; drop it either way.
      if (pool.get(key) === current) dropPooled(key);
      if (retryTransport && !retried) return run(true);
      throw err;
    }
  };
  return run(false);
}

export async function discoverTools(
  baseUrl: string,
  authSecret: string | null
): Promise<DiscoveredTool[]> {
  return withClient(baseUrl, authSecret, async (client) => {
    const res = await client.listTools();
    return res.tools.map((t) => ({
      name: t.name,
      description: t.description ?? "",
      inputSchema: (t.inputSchema as Record<string, unknown>) ?? {}
    }));
  }, true);
}

export async function callUpstreamTool(
  baseUrl: string,
  authSecret: string | null,
  toolName: string,
  args: Record<string, unknown>
): Promise<unknown> {
  return withClient(baseUrl, authSecret, async (client) =>
    client.callTool({ name: toolName, arguments: args })
  );
}
