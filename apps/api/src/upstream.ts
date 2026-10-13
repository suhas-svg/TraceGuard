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

// Minimal SSRF guard: http(s) only, no credentials in the URL, and private
// hostnames only when the operator opts in for local development.
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
  const host = url.hostname.toLowerCase();
  const privateHost =
    host === "localhost" || host === "127.0.0.1" || host === "::1" ||
    host.startsWith("10.") || host.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host) || host.endsWith(".internal");
  if (privateHost && process.env.ALLOW_PRIVATE_UPSTREAMS !== "true") {
    return { ok: false, reason: "private upstream hosts need ALLOW_PRIVATE_UPSTREAMS=true" };
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

function poolKey(baseUrl: string, authSecret: string | null): string {
  return sha256Hex(`${baseUrl}|${authSecret ?? ""}`);
}

async function openClient(baseUrl: string, authSecret: string | null): Promise<Client> {
  const headers = authSecret ? { Authorization: "Bearer " + authSecret } : undefined;
  const transport = new StreamableHTTPClientTransport(new URL(baseUrl), { requestInit: { headers } });
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
// exchange. Idle clients reconnect on next use; a failed call drops the
// client and retries once on a fresh connection.
async function withClient<T>(
  baseUrl: string,
  authSecret: string | null,
  fn: (client: Client) => Promise<T>
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
      if (!retried) {
        if (pool.get(key) === current) dropPooled(key);
        return run(true);
      }
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
  });
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
