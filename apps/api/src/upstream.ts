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

async function withClient<T>(
  baseUrl: string,
  authSecret: string | null,
  fn: (client: Client) => Promise<T>
): Promise<T> {
  const headers = authSecret ? { Authorization: `Bearer ${authSecret}` } : undefined;
  const transport = new StreamableHTTPClientTransport(new URL(baseUrl), { requestInit: { headers } });
  const client = new Client({ name: "traceguard-gateway", version: "0.1.0" });
  // The gateway holds upstream credentials and injects them here. Agent
  // tokens never leave the gateway toward upstream servers.
  await client.connect(transport);
  try {
    return await fn(client);
  } finally {
    await client.close();
  }
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
