import { createServer } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { buildApp } from "../src/index.js";
import { buildGateway, buildGatewayControl } from "../src/gateway.js";
import { pool } from "../src/db.js";
import { publishTestPolicy } from "./policy-helper.js";

// §9.2/§9.4 behaviours that the legacy approval flow did not have: queue
// caps, a creation rate limit, an ambiguous-outcome terminal state, MCP tool
// errors recorded as errors rather than success, and the recovery sweep.
describe("approval state machine v2", () => {
  const api = buildApp();
  const gw = buildGateway();
  // The human approval surface: queue + decisions, on its own listener.
  const ctl = buildGatewayControl();
  const key = { authorization: "Bearer test_key" };
  const approver = { authorization: "Bearer test_approver" };
  const tag = Date.now().toString(36);
  let serverId = "";
  let httpServer: ReturnType<typeof createServer>;

  // A fresh server per request: one Protocol instance cannot be connected to

  // two transports, and two gateway calls can be in flight at once.
  const newMock = () => {
  const mock = new McpServer({ name: "approval-tools", version: "0.1.0" });
  mock.registerTool("echo", { description: "echo", inputSchema: { text: z.string() } },
    async ({ text }) => ({ content: [{ type: "text", text: `echo:${text}` }] }));
  // Never resolves: the gateway must time out and refuse to guess the outcome.
  mock.registerTool("hang", { description: "hangs", inputSchema: { text: z.string() } },
    async () => new Promise(() => undefined));
  // A protocol-level tool error is an unambiguous response, not success.
  mock.registerTool("err", { description: "tool error", inputSchema: {} },
    async () => ({ content: [{ type: "text", text: "upstream refused" }], isError: true }));
  // Slow but successful: lets a sweep finalize the row while the upstream is
  // still working, for the late-response guard.
  mock.registerTool("slow", { description: "slow", inputSchema: { text: z.string() } },
    async ({ text }) => {
      await new Promise((r) => setTimeout(r, 3000));
      return { content: [{ type: "text", text: `slow:${text}` }] };
    });

  return mock;
  };

  beforeAll(async () => {
    httpServer = createServer(async (req, res) => {
      if (req.method === "POST") {
        const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
        res.on("close", () => transport.close().catch(() => undefined));
        await newMock().connect(transport);
        await transport.handleRequest(req, res);
        return;
      }
      res.writeHead(405).end();
    });
    await new Promise<void>((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
    const port = (httpServer.address() as { port: number }).port;
    const reg = await gw.inject({ method: "POST", url: "/v1/servers", headers: key,
      payload: { name: `approvals-${tag}`, base_url: `http://127.0.0.1:${port}/mcp` } });
    expect(reg.statusCode).toBe(201);
    serverId = reg.json().id as string;
    const disc = await gw.inject({ method: "POST", url: `/v1/servers/${serverId}/discover`, headers: key });
    expect(disc.statusCode).toBe(200);
    // Every tool in this file needs approval.
    const rule = await gw.inject({ method: "POST", url: "/v1/policies", headers: key,
      payload: { name: `approvals-hold-${tag}`, priority: 10, server_id: serverId,
        effect: "require_approval" } });
    expect(rule.statusCode).toBe(201);
    await publishTestPolicy(pool);
  });

  afterAll(async () => {
    httpServer.close();
    await api.close();
    await gw.close();
    await ctl.close();
    await pool.end();
  });

  const call = (caller: string, tool: string, args: Record<string, unknown> = {}) =>
    gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool, arguments: args, caller } });

  const decide = (id: string, approved = true) =>
    ctl.inject({ method: "POST", url: `/_control/v1/approvals/${id}/decision`, headers: approver,
      payload: { approved } });

  it("refuses more than N new approvals per caller per minute", async () => {
    const previous = process.env.APPROVAL_RATE_PER_MINUTE;
    process.env.APPROVAL_RATE_PER_MINUTE = "1";
    try {
      const caller = `rl-${tag}`;
      const first = await call(caller, "echo", { text: "one" });
      expect(first.statusCode).toBe(202);
      const second = await call(caller, "echo", { text: "two" });
      expect(second.statusCode).toBe(429);
      expect(second.json().error).toBe("approval_rate_limited");
    } finally {
      process.env.APPROVAL_RATE_PER_MINUTE = previous;
    }
  });

  it("refuses more than N active pending approvals for one caller", async () => {
    const previous = process.env.APPROVAL_MAX_PENDING_PER_CALLER;
    process.env.APPROVAL_MAX_PENDING_PER_CALLER = "1";
    try {
      const caller = `cap-${tag}`;
      const first = await call(caller, "echo", { text: "first" });
      expect(first.statusCode).toBe(202);
      const second = await call(caller, "echo", { text: "second" });
      expect(second.statusCode).toBe(429);
      expect(second.json().error).toBe("approval_limit");
    } finally {
      process.env.APPROVAL_MAX_PENDING_PER_CALLER = previous;
    }
  });

  it("marks a timeout after dispatch OUTCOME_UNKNOWN and never retries it", async () => {
    const caller = `unk-${tag}`;
    const held = await call(caller, "hang", { text: "x" });
    expect(held.statusCode).toBe(202);
    const id = held.json().approval_id as string;
    expect((await decide(id)).statusCode).toBe(200);

    const previousTimeout = process.env.UPSTREAM_TIMEOUT_MS;
    process.env.UPSTREAM_TIMEOUT_MS = "1500";
    let retry: Awaited<ReturnType<typeof gw.inject>>;
    try {
      retry = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
        payload: { server_id: serverId, tool: "hang", arguments: { text: "x" }, caller, approval_id: id } });
    } finally {
      if (previousTimeout === undefined) delete process.env.UPSTREAM_TIMEOUT_MS;
      else process.env.UPSTREAM_TIMEOUT_MS = previousTimeout;
    }
    expect(retry.statusCode).toBe(502);
    expect(retry.json().error).toBe("outcome_unknown");

    const row = (await pool.query(
      "SELECT status, outcome_summary FROM approvals WHERE id = $1", [id])).rows[0];
    expect(row.status).toBe("outcome_unknown");
    expect(row.outcome_summary).toContain("may have executed");

    const replay = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "hang", arguments: { text: "x" }, caller, approval_id: id } });
    expect(replay.statusCode).toBe(410);
    expect(replay.json().error).toBe("approval_outcome_unknown");
    expect(replay.json().note).toContain("may have executed");
  });

  it("records an MCP tool error as a received response with response_is_error", async () => {
    const caller = `err-${tag}`;
    const held = await call(caller, "err");
    const id = held.json().approval_id as string;
    expect((await decide(id)).statusCode).toBe(200);
    const retry = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "err", arguments: {}, caller, approval_id: id } });
    expect(retry.statusCode).toBe(200);
    expect(retry.json().result.isError).toBe(true);
    const row = (await pool.query(
      "SELECT status, response_is_error FROM approvals WHERE id = $1", [id])).rows[0];
    expect(row.status).toBe("response_received");
    expect(row.response_is_error).toBe(true);
  });

  it("sweeps a stuck EXECUTING row into OUTCOME_UNKNOWN", async () => {
    const caller = `sweep-${tag}`;
    const held = await call(caller, "echo", { text: "sweep" });
    const id = held.json().approval_id as string;
    await pool.query(
      `UPDATE approvals SET status='executing', execution_started_at=now() - interval '1 hour'
        WHERE id = $1`, [id]
    );
    const listed = await ctl.inject({ method: "GET", url: "/_control/v1/approvals?status=outcome_unknown", headers: approver });
    const row = listed.json().items.find((a: { id: string }) => a.id === id);
    expect(row).toBeDefined();
    expect(row.outcome_summary).toContain("may have executed");
  });

  it("returns the same approval for a repeated request id and refuses a conflicting reuse", async () => {
    const caller = `dedupe-${tag}`;
    const requestId = `dedupe-${tag}-1`;
    const first = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: "same" }, caller, request_id: requestId } });
    expect(first.statusCode).toBe(202);
    const repeated = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: "same" }, caller, request_id: requestId } });
    expect(repeated.statusCode).toBe(202);
    expect(repeated.json().approval_id).toBe(first.json().approval_id);
    const conflicting = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: "different" }, caller, request_id: requestId } });
    expect(conflicting.statusCode).toBe(409);
    expect(conflicting.json().error).toBe("request_id_conflict");
  });

  it("returns an expired claim lease to APPROVED and the sealed request still consumes", async () => {
    const caller = `lease-${tag}`;
    const held = await call(caller, "echo", { text: "lease" });
    expect(held.statusCode).toBe(202);
    const id = held.json().approval_id as string;
    // Simulate a crash after the CAS claim but before the execution intent:
    // the row is claimed with an already-expired lease and no intent audit.
    await pool.query(
      `UPDATE approvals SET status='claimed', claim_id=gen_random_uuid(),
         claim_lease_expires_at=now() - interval '1 second' WHERE id = $1`, [id]);
    const listed = await ctl.inject({ method: "GET", url: "/_control/v1/approvals?status=approved", headers: approver });
    expect(listed.json().items.find((a: { id: string }) => a.id === id)).toBeDefined();
    const after = (await pool.query("SELECT status, claim_id FROM approvals WHERE id = $1", [id])).rows[0];
    expect(after.status).toBe("approved");
    expect(after.claim_id).toBeNull();
    const audit = (await pool.query(
      "SELECT count(*)::int AS n FROM audit_events WHERE action = 'approval.claim_expired' AND resource_id = $1", [id])).rows[0];
    expect(audit.n).toBe(1);
    const retry = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: "lease" }, caller, approval_id: id } });
    expect(retry.statusCode).toBe(200);
    expect(retry.json().result.content[0].text).toBe("echo:lease");
  });

  it("keeps a late upstream response out of a finalized row and audits it", async () => {
    const caller = `late-${tag}`;
    const held = await call(caller, "slow", { text: "later" });
    expect(held.statusCode).toBe(202);
    const id = held.json().approval_id as string;
    expect((await decide(id)).statusCode).toBe(200);

    const previous = process.env.APPROVAL_EXECUTION_TIMEOUT_SECONDS;
    process.env.APPROVAL_EXECUTION_TIMEOUT_SECONDS = "1";
    try {
      const retryPromise = gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
        payload: { server_id: serverId, tool: "slow", arguments: { text: "later" }, caller, approval_id: id } });
      // Let the row enter EXECUTING, then sweep it while the upstream still works.
      await new Promise((r) => setTimeout(r, 1500));
      await ctl.inject({ method: "GET", url: "/_control/v1/approvals?status=outcome_unknown", headers: approver });
      const during = (await pool.query("SELECT status FROM approvals WHERE id = $1", [id])).rows[0];
      expect(during.status).toBe("outcome_unknown");
      const retry = await retryPromise;
      // The caller still receives the response that actually arrived...
      expect(retry.statusCode).toBe(200);
      expect(retry.json().result.content[0].text).toBe("slow:later");
    } finally {
      if (previous === undefined) delete process.env.APPROVAL_EXECUTION_TIMEOUT_SECONDS;
      else process.env.APPROVAL_EXECUTION_TIMEOUT_SECONDS = previous;
    }
    // ...but the finalized row is not rewritten, and the late arrival is audited.
    const after = (await pool.query("SELECT status FROM approvals WHERE id = $1", [id])).rows[0];
    expect(after.status).toBe("outcome_unknown");
    const audit = (await pool.query(
      "SELECT count(*)::int AS n FROM audit_events WHERE action = 'approval.response_late' AND resource_id = $1", [id])).rows[0];
    expect(audit.n).toBe(1);
  });

  it("serves approvals only on the control listener, never the agent port", async () => {
    const gone = await gw.inject({ method: "GET", url: "/v1/approvals", headers: key });
    expect(gone.statusCode).toBe(404);
    const goneWrite = await gw.inject({ method: "POST", url: "/v1/approvals/00000000-0000-0000-0000-000000000000/decision",
      headers: approver, payload: { approved: true } });
    // The approver key is scoped out by the default admin requirement before
    // routing; either way the agent-facing app does not serve the decision route.
    expect(goneWrite.statusCode).toBe(403);
    const anonymous = await ctl.inject({ method: "GET", url: "/_control/v1/approvals" });
    expect(anonymous.statusCode).toBe(401);
    // The admin/API key holds no approve scope, and admin does not shortcut
    // the control surface: only approver credentials may list or decide.
    const adminAtCtl = await ctl.inject({ method: "GET", url: "/_control/v1/approvals", headers: key });
    expect(adminAtCtl.statusCode).toBe(403);
  });

  it("refuses a transplanted approval whose arguments do not match the binding", async () => {
    const caller = `bind-${tag}`;
    const held = await call(caller, "echo", { text: "bound" });
    expect(held.statusCode).toBe(202);
    const id = held.json().approval_id as string;
    expect((await decide(id)).statusCode).toBe(200);

    // Same approval id, different arguments: the binding hash (caller +
    // server + tool + args + logical id + pin) must refuse the transplant,
    // and the row must not be burned by the attempt.
    const transplanted = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: "not-bound" }, caller, approval_id: id } });
    expect(transplanted.statusCode).toBe(403);
    expect(transplanted.json().error).toBe("approval_binding_mismatch");

    const decision = (await pool.query(
      "SELECT count(*)::int AS n FROM policy_decisions WHERE approval_id = $1 AND reason = 'approval binding mismatch'", [id])).rows[0];
    expect(decision.n).toBe(1);
    const audit = (await pool.query(
      "SELECT count(*)::int AS n FROM audit_events WHERE action = 'approval.binding_mismatch' AND resource_id = $1", [id])).rows[0];
    expect(audit.n).toBe(1);
    const row = (await pool.query("SELECT status FROM approvals WHERE id = $1", [id])).rows[0];
    expect(row.status).toBe("approved");

    // The genuine request still consumes afterwards.
    const ok = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
      payload: { server_id: serverId, tool: "echo", arguments: { text: "bound" }, caller, approval_id: id } });
    expect(ok.statusCode).toBe(200);
    expect(ok.json().result.content[0].text).toBe("echo:bound");
  });

  it("caps active approvals per workspace at the configured maximum", async () => {
    // Clear the rows earlier tests left live so the cap math starts at zero.
    const server = (await pool.query("SELECT workspace_id FROM mcp_servers WHERE id = $1", [serverId])).rows[0];
    await pool.query(
      "UPDATE approvals SET status='expired' WHERE workspace_id = $1 AND status IN ('pending','approved')",
      [server.workspace_id]);
    const previous = process.env.APPROVAL_MAX_PENDING_PER_WORKSPACE;
    process.env.APPROVAL_MAX_PENDING_PER_WORKSPACE = "1";
    try {
      const first = await call(`ws-cap-a-${tag}`, "echo", { text: "a" });
      expect(first.statusCode).toBe(202);
      const second = await call(`ws-cap-b-${tag}`, "echo", { text: "b" });
      expect(second.statusCode).toBe(429);
      expect(second.json().error).toBe("approval_limit");
      expect(second.json().pending_workspace).toBe(1);
    } finally {
      if (previous === undefined) delete process.env.APPROVAL_MAX_PENDING_PER_WORKSPACE;
      else process.env.APPROVAL_MAX_PENDING_PER_WORKSPACE = previous;
    }
  });

  it("marks approval responses as non-cacheable", async () => {
    const held = await call(`cache-${tag}`, "echo", { text: "c" });
    expect(held.statusCode).toBe(202);
    expect(held.headers["cache-control"]).toBe("no-store");
    const listed = await ctl.inject({ method: "GET", url: "/_control/v1/approvals", headers: approver });
    expect(listed.statusCode).toBe(200);
    expect(listed.headers["cache-control"]).toBe("no-store");
    const decided = await decide(held.json().approval_id as string, false);
    expect(decided.statusCode).toBe(200);
    expect(decided.headers["cache-control"]).toBe("no-store");
  });

  it("invalidates an approved call when the tool is quarantined before dispatch", async () => {
    const caller = `quar-${tag}`;
    const held = await call(caller, "err");
    expect(held.statusCode).toBe(202);
    const id = held.json().approval_id as string;
    expect((await decide(id)).statusCode).toBe(200);
    // A drift discovered after the human approved must still stop the call:
    // the human approved the old definition, not this one (§7.5, §9.2).
    await pool.query(
      "UPDATE server_tools SET quarantined = true, quarantine_reason = 'definition changed' WHERE server_id = $1 AND tool_name = 'err'",
      [serverId]
    );
    try {
      const retry = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
        payload: { server_id: serverId, tool: "err", arguments: {}, caller, approval_id: id } });
      expect(retry.statusCode).toBe(403);
      expect(retry.json().error).toBe("tool_blocked");
      expect(retry.json().reason).toBe("unknown or quarantined tool");
      const row = (await pool.query("SELECT status FROM approvals WHERE id = $1", [id])).rows[0];
      expect(row.status).toBe("tool_quarantined");
      const audit = (await pool.query(
        "SELECT count(*)::int AS n FROM audit_events WHERE action = 'approval.tool_quarantined' AND resource_id = $1", [id])).rows[0];
      expect(audit.n).toBe(1);
    } finally {
      await pool.query(
        "UPDATE server_tools SET quarantined = false, quarantine_reason = NULL WHERE server_id = $1 AND tool_name = 'err'",
        [serverId]
      );
    }
  });

  it("invalidates an approved call when a publish drops the pinned tool", async () => {
    const caller = `drop-${tag}`;
    const held = await call(caller, "err");
    expect(held.statusCode).toBe(202);
    const id = held.json().approval_id as string;
    expect((await decide(id)).statusCode).toBe(200);
    try {
      // Quarantine excludes the pin from the next signed bundle; clearing the
      // flag without a republish leaves a live tool with no approved pin —
      // the consume-time pin check must refuse rather than dispatch (§7.5).
      await pool.query(
        "UPDATE server_tools SET quarantined = true WHERE server_id = $1 AND tool_name = 'err'", [serverId]);
      await publishTestPolicy(pool);
      await pool.query(
        "UPDATE server_tools SET quarantined = false WHERE server_id = $1 AND tool_name = 'err'", [serverId]);
      const retry = await gw.inject({ method: "POST", url: "/v1/gateway/tools/call", headers: key,
        payload: { server_id: serverId, tool: "err", arguments: {}, caller, approval_id: id } });
      expect(retry.statusCode).toBe(403);
      // The manifest check runs before the approval branch: a pin the signed
      // bundle no longer carries blocks the call and invalidates the hold in
      // the same transaction (the later consume-time recheck covers the race
      // where policy changes mid-consume).
      expect(retry.json().error).toBe("tool_blocked");
      expect(String(retry.json().reason)).toContain("not in the active signed policy");
      const row = (await pool.query("SELECT status FROM approvals WHERE id = $1", [id])).rows[0];
      expect(row.status).toBe("policy_invalidated");
      const audit = (await pool.query(
        "SELECT count(*)::int AS n FROM audit_events WHERE action = 'approval.policy_invalidated' AND resource_id = $1", [id])).rows[0];
      expect(audit.n).toBe(1);
    } finally {
      await pool.query(
        "UPDATE server_tools SET quarantined = false WHERE server_id = $1 AND tool_name = 'err'", [serverId]);
      await publishTestPolicy(pool);
    }
  });
});
