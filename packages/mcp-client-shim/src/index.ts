import { randomUUID } from "node:crypto";

// Certified approval-retry client for the gateway's 2026-07-28 profile
// (`approval-client-profile: 1`). It is hand-rolled because the pinned official
// SDK (1.32.x) does not know that revision: it cannot send the Mcp-Method /
// Mcp-Name headers or the per-request _meta block the gateway requires.
//
// Contract:
// - one stable logical_request_id per logical call; a fresh JSON-RPC id per
//   HTTP attempt;
// - retry only on APPROVAL_PENDING, with bounded backoff until the caller's
//   deadline;
// - never resubmit after an ambiguous transport outcome: the action may have
//   executed on the gateway side.

export const APPROVAL_CLIENT_PROFILE = "approval-client-profile: 1";
const PROTOCOL_VERSION = "2026-07-28";
const META_PROTOCOL = "io.modelcontextprotocol/protocolVersion";
const META_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities";
const META_LOGICAL = "io.traceguard/logical_request_id";

export class ShimError extends Error {
  code?: string;
  constructor(message: string, code?: string) {
    super(message);
    this.name = new.target.name;
    this.code = code;
  }
}

export class ApprovalClientRequiredError extends ShimError {
  constructor(message: string) {
    super(message, "APPROVAL_CLIENT_REQUIRED");
  }
}

export class ApprovalPendingError extends ShimError {
  logicalRequestId: string;
  approvalId?: string;
  expiresAt?: string;
  constructor(message: string, logicalRequestId: string, approvalId?: string, expiresAt?: string) {
    super(message, "APPROVAL_PENDING");
    this.logicalRequestId = logicalRequestId;
    this.approvalId = approvalId;
    this.expiresAt = expiresAt;
  }
}

export class ApprovalTerminalError extends ShimError {
  status?: string;
  approvalId?: string;
  constructor(message: string, status?: string, approvalId?: string) {
    super(message, "APPROVAL_TERMINAL");
    this.status = status;
    this.approvalId = approvalId;
  }
}

export class OutcomeUnknownError extends ShimError {
  approvalId?: string;
  constructor(message: string, approvalId?: string) {
    super(message, "OUTCOME_UNKNOWN");
    this.approvalId = approvalId;
  }
}

export interface CertifiedClientOptions {
  /** Gateway MCP endpoint, e.g. http://localhost:8091/mcp */
  url: string;
  /** Gateway bearer token (dev profile: the static gateway key). */
  token: string;
  /** Backoff seed between APPROVAL_PENDING retries. Default 2s. */
  retryIntervalMs?: number;
  /** Overall deadline for one logical call. Default 15 minutes. */
  deadlineMs?: number;
  /** Per-HTTP-attempt timeout. Default 120s. */
  requestTimeoutMs?: number;
  fetchImpl?: typeof fetch;
}

interface JsonRpcResponse {
  jsonrpc?: "2.0";
  id?: unknown;
  result?: unknown;
  error?: { code?: number; message?: string; data?: Record<string, unknown> };
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export class CertifiedClient {
  private readonly url: string;
  private readonly token: string;
  private readonly retryIntervalMs: number;
  private readonly deadlineMs: number;
  private readonly requestTimeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: CertifiedClientOptions) {
    this.url = opts.url;
    this.token = opts.token;
    this.retryIntervalMs = opts.retryIntervalMs ?? 2_000;
    this.deadlineMs = opts.deadlineMs ?? 15 * 60_000;
    this.requestTimeoutMs = opts.requestTimeoutMs ?? 120_000;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  async callTool(
    name: string,
    args: Record<string, unknown> = {},
    opts: { logicalRequestId?: string; deadlineMs?: number } = {}
  ): Promise<unknown> {
    const logicalRequestId = opts.logicalRequestId ?? randomUUID();
    const deadline = Date.now() + (opts.deadlineMs ?? this.deadlineMs);
    let delay = this.retryIntervalMs;
    let approvalId: string | undefined;
    let expiresAt: string | undefined;

    for (;;) {
      const res = await this.post(name, args, logicalRequestId);
      if (res.status >= 500) {
        // The gateway may have dispatched before failing to answer.
        throw new OutcomeUnknownError(
          "gateway failed after accepting the call; the upstream action may have executed",
          approvalId
        );
      }
      if (res.status === 400 || res.status === 401 || res.status === 403) {
        throw new ShimError(`gateway rejected the request (HTTP ${res.status})`, "REQUEST_REJECTED");
      }
      const body = res.body;
      if (!body) throw new ShimError("gateway returned a non-JSON response", "BAD_RESPONSE");
      if (body.result !== undefined) return body.result;

      const err = body.error;
      if (!err) throw new ShimError("gateway response carried neither result nor error", "BAD_RESPONSE");
      const data = (err.data ?? {}) as Record<string, unknown>;

      if (err.code === -32002) {
        approvalId = (data.approval_id as string | undefined) ?? approvalId;
        expiresAt = (data.expires_at as string | undefined) ?? expiresAt;
        const remaining = deadline - Date.now();
        if (remaining <= 0) {
          throw new ApprovalPendingError(
            "approval was not granted before the deadline",
            logicalRequestId, approvalId, expiresAt
          );
        }
        await sleep(Math.min(delay, remaining));
        delay = Math.min(Math.round(delay * 1.5), 30_000);
        continue;
      }
      if (err.code === -32005) {
        throw new ApprovalClientRequiredError(
          String(data.detail ?? "the gateway requires the logical request metadata")
        );
      }
      if (err.code === -32007) {
        throw new OutcomeUnknownError(
          String(data.note ?? "the upstream action may have executed"),
          (data.approval_id as string | undefined) ?? approvalId
        );
      }
      if (err.code === -32001 || err.code === -32004) {
        throw new ApprovalTerminalError(
          err.message ?? "the approval is terminal",
          typeof data.status === "string" ? data.status : undefined,
          (data.approval_id as string | undefined) ?? approvalId
        );
      }
      throw new ShimError(err.message ?? "gateway error", typeof data.error === "string" ? data.error : undefined);
    }
  }

  private async post(
    name: string, args: Record<string, unknown>, logicalRequestId: string
  ): Promise<{ status: number; body: JsonRpcResponse | null }> {
    const payload = {
      jsonrpc: "2.0",
      id: randomUUID(),
      method: "tools/call",
      params: {
        name,
        arguments: args,
        _meta: {
          [META_PROTOCOL]: PROTOCOL_VERSION,
          [META_CAPABILITIES]: { tools: {} },
          [META_LOGICAL]: logicalRequestId
        }
      }
    };
    let res: Response;
    try {
      res = await this.fetchImpl(this.url, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.token}`,
          "content-type": "application/json",
          accept: "application/json",
          "mcp-protocol-version": PROTOCOL_VERSION,
          "mcp-method": "tools/call",
          "mcp-name": name
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(this.requestTimeoutMs)
      });
    } catch (err) {
      // A refused connection never reached the gateway; anything else after
      // the request left this process is ambiguous.
      const cause = (err as { cause?: { code?: string } }).cause;
      if (cause?.code === "ECONNREFUSED" || cause?.code === "ENOTFOUND") {
        throw new ShimError("gateway is unreachable", "GATEWAY_UNREACHABLE");
      }
      throw new OutcomeUnknownError(
        "transport failed after the request was sent; the upstream action may have executed"
      );
    }
    let body: JsonRpcResponse | null = null;
    try {
      body = (await res.json()) as JsonRpcResponse;
    } catch {
      body = null;
    }
    return { status: res.status, body };
  }
}
