import { createHash } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { canonicalize } from "@traceguard/canonical-json";
import { PATH_CONFINEMENT_META_KEY } from "@traceguard/schemas";
import { sha256Hex } from "./policy.js";

export interface DiscoveredTool {
  name: string;
  title?: string;
  description?: string;
  inputSchema: Record<string, unknown>;
  outputSchema?: Record<string, unknown>;
  annotations?: Record<string, unknown>;
  icons?: unknown[];
  execution?: Record<string, unknown>;
  // Allowlisted _meta entries only; see TOOL_PIN_META_ALLOWLIST below.
  meta?: Record<string, unknown>;
}

// §7.5: the pin covers every declared field that may affect what the client
// sees or how the tool executes. Absent fields stay absent (an added or
// removed field changes the hash both ways), and the object is canonicalized
// with RFC 8785 before hashing so two implementations agree on the bytes.
export function pinnedDefinition(tool: DiscoveredTool): Record<string, unknown> {
  const d: Record<string, unknown> = { name: tool.name, inputSchema: tool.inputSchema ?? {} };
  if (tool.title !== undefined) d.title = tool.title;
  if (tool.description !== undefined) d.description = tool.description;
  if (tool.outputSchema !== undefined) d.outputSchema = tool.outputSchema;
  if (tool.annotations !== undefined) d.annotations = tool.annotations;
  if (tool.icons !== undefined) d.icons = tool.icons;
  if (tool.execution !== undefined) d.execution = tool.execution;
  if (tool.meta !== undefined) d._meta = tool.meta;
  return d;
}

export function definitionHash(tool: DiscoveredTool): string {
  return createHash("sha256").update(canonicalize(pinnedDefinition(tool))).digest("hex");
}

// Reference keywords ($ref/$dynamicRef/$recursiveRef) that do not start with
// "#" point outside the document, and an absolute $id re-bases the document;
// either would make hashing depend on remote content, so they are rejected
// outright. Depth, node and reference counts are bounded so a hostile
// definition cannot make the gateway's work unbounded.
const MAX_SCHEMA_DEPTH = 64;
const MAX_SCHEMA_NODES = 4096;
const MAX_SCHEMA_REFS = 512;
const MAX_DEFINITION_BYTES = 256 * 1024;
const REF_KEYS = new Set(["$ref", "$dynamicRef", "$recursiveRef"]);

export function schemaSafetyIssue(schema: unknown): string | null {
  let nodes = 0;
  let refs = 0;
  const walk = (value: unknown, depth: number): string | null => {
    if (depth > MAX_SCHEMA_DEPTH) return "schema nested too deeply";
    if (++nodes > MAX_SCHEMA_NODES) return "schema has too many nodes";
    if (typeof value === "string") return null;
    if (value === null || typeof value !== "object") return null;
    if (Array.isArray(value)) {
      for (const item of value) {
        const issue = walk(item, depth + 1);
        if (issue) return issue;
      }
      return null;
    }
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (REF_KEYS.has(key)) {
        if (++refs > MAX_SCHEMA_REFS) return "schema has too many $ref values";
        if (typeof item !== "string" || !item.startsWith("#")) {
          return `external ${key} values are not allowed`;
        }
      }
      if (
        key === "$id" && typeof item === "string" &&
        (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(item) || item.startsWith("//"))
      ) {
        return "absolute $id values are not allowed";
      }
      const issue = walk(item, depth + 1);
      if (issue) return issue;
    }
    return null;
  };
  return walk(schema, 0);
}

// One gate for the whole pinned definition: schema-safety of both schemas and
// a byte-size bound on the canonical form.
export function definitionIssue(tool: DiscoveredTool): string | null {
  const inputIssue = schemaSafetyIssue(tool.inputSchema ?? {});
  if (inputIssue) return `inputSchema: ${inputIssue}`;
  if (tool.outputSchema !== undefined) {
    const outputIssue = schemaSafetyIssue(tool.outputSchema);
    if (outputIssue) return `outputSchema: ${outputIssue}`;
  }
  const bytes = new TextEncoder().encode(canonicalize(pinnedDefinition(tool))).length;
  if (bytes > MAX_DEFINITION_BYTES) return "definition is too large to pin";
  return null;
}

// SSRF guard: http(s) only, no credentials in the URL, cloud metadata
// addresses never, and private hosts only when the operator opts in for
// local development. Discover and call re-run the resolved variant so a
// rebinding name cannot dodge the registration gate.
// Strict dotted quad: every octet 0-255, no shorthand. The URL parser
// normalizes the numeric forms it understands ("127.1", "2130706433") into
// quads before we ever see them, so anything still numeric-looking here is
// either a real quad or a form (127.0.0.256) that must not be resolved.
function strictIpv4(host: string): number[] | null {
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const octets = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  return octets.some((n) => n > 255) ? null : octets;
}

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
  const octets = strictIpv4(h);
  if (octets) {
    const [a, b, c] = octets;
    return (
      a === 0 || a === 10 || a === 127 || a >= 240 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 192 && b === 0 && (c === 0 || c === 2)) || // IETF assignments, TEST-NET-1
      (a === 198 && (b === 18 || b === 19)) || // benchmarking
      (a === 203 && b === 0 && c === 113) // TEST-NET-3
    );
  }
  // A numeric-looking host that is not a valid quad: some resolvers still
  // resolve these forms, so treat them as private rather than public.
  // checkUpstreamUrl refuses them outright before this matters.
  if (/^[0-9.]+$/.test(h)) return true;
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
  // Fail closed on numeric hosts the URL parser did not normalize into a
  // valid quad: "127.0.0.256" would otherwise skip both the private-range
  // classifier and the DNS revalidation below and go straight to the socket.
  if (/^[0-9.]+$/.test(host) && !strictIpv4(host)) {
    return { ok: false, reason: "numeric host is not a valid IP address" };
  }
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
// classified by checkUpstreamUrl. Every answer is checked, not just the first:
// a name that returns one public and one private address is a rebinding attempt,
// and taking whichever the resolver listed first would let it through.
export async function checkUpstreamUrlResolved(raw: string): Promise<{ ok: boolean; reason?: string }> {
  const sync = checkUpstreamUrl(raw);
  if (!sync.ok) return sync;
  if (process.env.ALLOW_PRIVATE_UPSTREAMS === "true") return { ok: true };
  const host = new URL(raw).hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (strictIpv4(host) || host.includes(":")) return { ok: true };
  const { lookup } = await import("node:dns/promises");
  let addresses: { address: string }[];
  try {
    addresses = await lookup(host, { all: true });
  } catch {
    return { ok: false, reason: "upstream host does not resolve" };
  }
  const priv = addresses.find((a) => isPrivateHost(a.address));
  if (priv) {
    return { ok: false, reason: `upstream host resolves to a private address (${priv.address})` };
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

// Operator-tunable ceiling on one upstream exchange (read per request so a
// test can shorten it). The MCP SDK's own 60s protocol default rejects the
// promise but never aborts the HTTP request, so a hung upstream would pin the
// socket and this server's pool slot. The signal is created per request, not
// per client: a signal made at connect time would expire 60s after the client
// was opened and then abort every later call.
function upstreamTimeoutMs(): number {
  return Math.max(1_000, Number(process.env.UPSTREAM_TIMEOUT_MS ?? 60_000));
}

// The last hop before the socket. Registration, discover, and call all resolve
// the name, but the transport resolves it again when it connects, so a name that
// answered publicly at those checks and privately a moment later would still be
// dialled. Re-checking here leaves only the gap between this resolve and the
// socket, and the timeout above stops a hung upstream from pinning the pool.
export async function guardedFetch(url: string | URL, init?: RequestInit): Promise<Response> {
  const allowed = await checkUpstreamUrlResolved(String(url));
  if (!allowed.ok) throw new Error(`upstream refused: ${allowed.reason}`);
  return fetch(url, { ...init, signal: AbortSignal.timeout(upstreamTimeoutMs()) });
}

function poolKey(baseUrl: string, authSecret: string | null): string {
  return sha256Hex(`${baseUrl}|${authSecret ?? ""}`);
}

async function openClient(baseUrl: string, authSecret: string | null): Promise<Client> {
  const headers = authSecret ? { Authorization: "Bearer " + authSecret } : undefined;
  const transport = new StreamableHTTPClientTransport(new URL(baseUrl), {
    requestInit: { headers },
    fetch: guardedFetch
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

// `_meta` keys covered by the pin (§7.5 allowlist), plus the mandatory
// executor path-confinement attestation (FR-010). The attestation is always
// pinned even when the operator's allowlist is empty: a path_within rule is
// only publishable against a definition that carries it, and the pin hash
// must cover it so it cannot change under an approval or after publication.
function pinnedMetaKeys(): string[] {
  const configured = (process.env.TOOL_PIN_META_ALLOWLIST ?? "")
    .split(",")
    .map((k) => k.trim())
    .filter(Boolean);
  return [...new Set([PATH_CONFINEMENT_META_KEY, ...configured])];
}

function pickMeta(meta: unknown): Record<string, unknown> | undefined {
  if (!meta || typeof meta !== "object" || Array.isArray(meta)) return undefined;
  const allowed = pinnedMetaKeys();
  if (allowed.length === 0) return undefined;
  const source = meta as Record<string, unknown>;
  const picked: Record<string, unknown> = {};
  for (const key of allowed) {
    if (source[key] !== undefined) picked[key] = source[key];
  }
  return Object.keys(picked).length > 0 ? picked : undefined;
}

export async function discoverTools(
  baseUrl: string,
  authSecret: string | null
): Promise<DiscoveredTool[]> {
  return withClient(baseUrl, authSecret, async (client) => {
    const res = await client.listTools();
    return res.tools.map((t) => {
      const tool: DiscoveredTool = {
        name: t.name,
        inputSchema: (t.inputSchema as Record<string, unknown>) ?? {}
      };
      if (t.title !== undefined) tool.title = t.title;
      if (t.description !== undefined) tool.description = t.description;
      if (t.outputSchema !== undefined) tool.outputSchema = t.outputSchema as Record<string, unknown>;
      if (t.annotations !== undefined) tool.annotations = t.annotations as Record<string, unknown>;
      if (t.icons !== undefined) tool.icons = t.icons as unknown[];
      if (t.execution !== undefined) tool.execution = t.execution as Record<string, unknown>;
      const meta = pickMeta(t._meta);
      if (meta) tool.meta = meta;
      return tool;
    });
  }, true);
}

export async function callUpstreamTool(
  baseUrl: string,
  authSecret: string | null,
  toolName: string,
  args: Record<string, unknown>
): Promise<unknown> {
  return withClient(baseUrl, authSecret, async (client) =>
    // The SDK's default request timeout is 60s and only rejects the promise;
    // pairing it with our own bound makes a hung server fail in bounded time.
    client.callTool({ name: toolName, arguments: args }, undefined, {
      timeout: upstreamTimeoutMs()
    })
  );
}
