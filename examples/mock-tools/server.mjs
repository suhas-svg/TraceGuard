// Mock upstream MCP tool server for local demos and gateway tests.
// Runs on the internal docker network only: the agent must have no route here.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createServer } from "node:http";
import { mkdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { z } from "zod";

const PORT = Number(process.env.MOCK_TOOLS_PORT ?? 8092);
// FR-010 reference executor: read_file confines itself to this root. The
// gateway's path_within check is only a pre-check; this is the enforcement
// boundary, and the confinement is what the pinned attestation promises.
const WORKSPACE_ROOT = process.env.MOCK_WORKSPACE_ROOT ?? "/tmp/traceguard-workspace";
const PATH_CONFINEMENT_META = "io.traceguard/path-confinement";
let hits = 0;
let escapeReady = false;

function prepareWorkspace() {
  try {
    rmSync(WORKSPACE_ROOT, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
  mkdirSync(WORKSPACE_ROOT, { recursive: true });
  writeFileSync(join(WORKSPACE_ROOT, "allowed.txt"), "allowed demo file\n");
  // A symlink the gateway's string check cannot detect: the path
  // "/tmp/traceguard-workspace/escape" is inside the root, but the resolved
  // target is not. The executor must refuse it. Creating symlinks can fail on
  // an unprivileged Windows host; the e2e test skips when it does.
  try {
    symlinkSync("/etc/passwd", join(WORKSPACE_ROOT, "escape"));
    escapeReady = true;
  } catch {
    escapeReady = false;
  }
}

// Resolves the real path (following symlinks) and refuses anything outside
// the root. Failure to resolve is a refusal too: a path that does not exist
// under the workspace has no file to read.
function resolveInRoot(rel) {
  let rootReal;
  try {
    rootReal = realpathSync(WORKSPACE_ROOT);
  } catch {
    return { ok: false, reason: "workspace root is unavailable" };
  }
  let real;
  try {
    real = realpathSync(resolve(WORKSPACE_ROOT, rel));
  } catch {
    return { ok: false, reason: "path does not resolve inside the workspace" };
  }
  const within = real === rootReal || real.startsWith(rootReal.endsWith(sep) ? rootReal : rootReal + sep);
  return within ? { ok: true, real } : { ok: false, reason: "path escapes the workspace root" };
}

// A fresh server per request: one Protocol instance cannot be connected to
// two transports, and two gateway calls can be in flight at once.
const newServer = () => {
const server = new McpServer({ name: "mock-tools", version: "0.1.0" });
server.registerTool("read_file", {
  description: "Read a file inside the workspace",
  inputSchema: { path: z.string() },
  // The executor-side attestation FR-010 requires before a path_within rule
  // may be published against this tool. Covered by the signed bundle's pin
  // hash, so it cannot be swapped after publication.
  _meta: { [PATH_CONFINEMENT_META]: { root: WORKSPACE_ROOT, enforcement: "executor" } }
}, async ({ path }) => {
  hits++;
  const inside = resolveInRoot(path);
  if (!inside.ok) {
    return { isError: true, content: [{ type: "text", text: `refused: ${inside.reason}` }] };
  }
  return { content: [{ type: "text", text: `contents of ${path}` }] };
});
// Deliberately unattested: a path_within rule against this tool must be
// refused by the publisher and denied by the gateway (negative test).
server.registerTool("read_file_unconfined", {
  description: "Read a file with no executor confinement (negative test only)",
  inputSchema: { path: z.string() }
}, async ({ path }) => {
  hits++;
  return { content: [{ type: "text", text: `contents of ${path}` }] };
});
server.registerTool("wipe_disk", {
  description: "DANGEROUS demo tool, always denied by policy",
  inputSchema: { target: z.string() }
}, async ({ target }) => {
  hits++;
  return { content: [{ type: "text", text: `wiped ${target} (mock, nothing happened)` }] };
});

return server;
};

prepareWorkspace();

const httpServer = createServer(async (req, res) => {
  if (req.url === "/hits") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ hits, escape_ready: escapeReady }));
    return;
  }
  if (req.method === "POST" && req.url === "/mcp") {
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => transport.close().catch(() => undefined));
    await newServer().connect(transport);
    await transport.handleRequest(req, res);
    return;
  }
  res.writeHead(404).end("not found");
});

httpServer.listen(PORT, () => console.log(`mock-tools on :${PORT}, hits endpoint at /hits`));
