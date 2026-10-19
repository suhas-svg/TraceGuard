import { createServer } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import {
  ApprovalClientRequiredError,
  ApprovalPendingError,
  ApprovalTerminalError,
  CertifiedClient,
  OutcomeUnknownError,
  ShimError
} from "../src/index.js";

// Upstream request bodies are JSON; the assertions read them field by field,
// so a shared alias keeps the casts honest and the rule quiet in one place.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type JsonBody = Record<string, any>;

interface Seen {
  headers: Record<string, string | string[] | undefined>;
  body: JsonBody;
}

type Reply = { status?: number; body: unknown } | "destroy";

async function start(handler: (seen: Seen, index: number) => Reply) {
  const seen: Seen[] = [];
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as JsonBody;
    const entry = { headers: req.headers, body };
    seen.push(entry);
    const reply = handler(entry, seen.length - 1);
    if (reply === "destroy") {
      req.socket.destroy();
      return;
    }
    res.writeHead(reply.status ?? 200, { "content-type": "application/json" });
    res.end(JSON.stringify(reply.body));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  return {
    url: `http://127.0.0.1:${port}/mcp`,
    seen,
    close: () => new Promise<void>((resolve) => server.close(() => resolve()))
  };
}

const pending = (logicalId: string) => ({
  jsonrpc: "2.0",
  id: "x",
  error: {
    code: -32002,
    message: "Approval pending",
    data: {
      error: "APPROVAL_PENDING",
      approval_id: "11111111-1111-1111-1111-111111111111",
      logical_request_id: logicalId,
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      status: "pending"
    }
  }
});

const result = { content: [{ type: "text", text: "done" }] };

describe("certified approval-retry client", () => {
  const cleanups: Array<() => Promise<void>> = [];
  afterEach(async () => {
    await Promise.all(cleanups.splice(0).map((fn) => fn()));
  });

  it("retries the same logical request id with fresh JSON-RPC ids", async () => {
    const srv = await start((_seen, i) =>
      i === 0 ? { body: pending("unused") } : { body: { jsonrpc: "2.0", id: "x", result } }
    );
    cleanups.push(srv.close);
    const client = new CertifiedClient({
      url: srv.url, token: "tg_test", retryIntervalMs: 5, deadlineMs: 5_000
    });
    const out = await client.callTool("mock__echo", { text: "hi" });
    expect(out).toEqual(result);
    expect(srv.seen).toHaveLength(2);
    // Same logical call across retries; a fresh JSON-RPC id per HTTP attempt.
    const logical = srv.seen.map((s) => s.body.params._meta["io.traceguard/logical_request_id"]);
    expect(logical[0]).toBeTruthy();
    expect(logical[1]).toBe(logical[0]);
    expect(srv.seen[0].body.id).not.toBe(srv.seen[1].body.id);
    // Headers bind the method and name to the body.
    for (const s of srv.seen) {
      expect(s.headers["mcp-method"]).toBe("tools/call");
      expect(s.headers["mcp-name"]).toBe("mock__echo");
      expect(s.headers["mcp-protocol-version"]).toBe("2026-07-28");
      expect(s.headers.authorization).toBe("Bearer tg_test");
      expect(s.body.params._meta["io.modelcontextprotocol/protocolVersion"]).toBe("2026-07-28");
    }
  });

  it("stops on a terminal approval state", async () => {
    const srv = await start(() => ({
      body: {
        jsonrpc: "2.0", id: "x",
        error: { code: -32004, message: "Approval terminal", data: { error: "approval_outcome_unknown", status: "outcome_unknown" } }
      }
    }));
    cleanups.push(srv.close);
    const client = new CertifiedClient({ url: srv.url, token: "t", retryIntervalMs: 5, deadlineMs: 1_000 });
    await expect(client.callTool("mock__hold")).rejects.toBeInstanceOf(ApprovalTerminalError);
    expect(srv.seen).toHaveLength(1);
  });

  it("reports APPROVAL_CLIENT_REQUIRED as its own error", async () => {
    const srv = await start(() => ({
      body: {
        jsonrpc: "2.0", id: "x",
        error: { code: -32005, message: "Approval client required", data: { error: "APPROVAL_CLIENT_REQUIRED" } }
      }
    }));
    cleanups.push(srv.close);
    const client = new CertifiedClient({ url: srv.url, token: "t", retryIntervalMs: 5, deadlineMs: 1_000 });
    await expect(client.callTool("mock__hold")).rejects.toBeInstanceOf(ApprovalClientRequiredError);
  });

  it("maps an OUTCOME_UNKNOWN result to the ambiguity error", async () => {
    const srv = await start(() => ({
      body: {
        jsonrpc: "2.0", id: "x",
        error: { code: -32007, message: "Outcome unknown", data: { error: "OUTCOME_UNKNOWN", approval_id: "a" } }
      }
    }));
    cleanups.push(srv.close);
    const client = new CertifiedClient({ url: srv.url, token: "t", retryIntervalMs: 5, deadlineMs: 1_000 });
    await expect(client.callTool("mock__hold")).rejects.toBeInstanceOf(OutcomeUnknownError);
  });

  it("gives up at the caller deadline while still pending", async () => {
    const srv = await start(() => ({ body: pending("unused") }));
    cleanups.push(srv.close);
    const client = new CertifiedClient({ url: srv.url, token: "t", retryIntervalMs: 10, deadlineMs: 60 });
    const failure = await client.callTool("mock__hold").catch((err) => err);
    expect(failure).toBeInstanceOf(ApprovalPendingError);
    expect(failure.approvalId).toBe("11111111-1111-1111-1111-111111111111");
    expect(failure.logicalRequestId).toBe(srv.seen[0].body.params._meta["io.traceguard/logical_request_id"]);
    expect(srv.seen.length).toBeGreaterThan(1);
  });

  it("never resubmits after a transport failure that may have executed", async () => {
    const srv = await start(() => "destroy");
    cleanups.push(srv.close);
    const client = new CertifiedClient({ url: srv.url, token: "t", retryIntervalMs: 5, deadlineMs: 1_000 });
    await expect(client.callTool("mock__hold")).rejects.toBeInstanceOf(OutcomeUnknownError);
    expect(srv.seen).toHaveLength(1);
  });

  it("distinguishes an unreachable gateway from an ambiguous outcome", async () => {
    const client = new CertifiedClient({ url: "http://127.0.0.1:59999/mcp", token: "t", retryIntervalMs: 5, deadlineMs: 1_000 });
    const failure = await client.callTool("mock__echo").catch((err) => err);
    expect(failure).toBeInstanceOf(ShimError);
    expect(failure.code).toBe("GATEWAY_UNREACHABLE");
  });
});
