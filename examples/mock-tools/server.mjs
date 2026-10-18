// Mock upstream MCP tool server for local demos and gateway tests.
// Runs on the internal docker network only: the agent must have no route here.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createServer } from "node:http";
import { z } from "zod";

const PORT = Number(process.env.MOCK_TOOLS_PORT ?? 8092);
let hits = 0;

// A fresh server per request: one Protocol instance cannot be connected to

// two transports, and two gateway calls can be in flight at once.
const newServer = () => {
const server = new McpServer({ name: "mock-tools", version: "0.1.0" });
server.registerTool("read_file", {
  description: "Read a file inside the workspace",
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

const httpServer = createServer(async (req, res) => {
  if (req.url === "/hits") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ hits }));
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
