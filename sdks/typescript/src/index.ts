// TypeScript mirror of the Python SDK. No runtime dependencies: the global
// fetch sends, a bounded queue sheds pressure, and telemetry never throws
// into the agent. Flush before process exit.

export interface ModelEventOptions {
  parentSpan?: string;
  status?: string;
  provider?: string;
  model?: string;
  inputTokens?: number;
  outputTokens?: number;
  usageSource?: string;
  errorType?: string;
  attributes?: Record<string, unknown>;
}

export function nowIso(): string {
  // toISOString is always Zulu, which is what the API schema accepts.
  return new Date().toISOString();
}

export class TraceGuardClient {
  private pending: Promise<unknown>[] = [];
  private inFlight = 0;
  private readonly maxQueue = 500;

  constructor(
    private baseUrl: string,
    private apiKey: string,
    private agentName = "demo-agent",
    private workspaceName = "default"
  ) {}

  private post(payload: unknown): void {
    // Serialising can throw (a circular reference, a BigInt attribute). Kept
    // inside the guarded path, like a network failure, so telemetry never
    // throws into the agent.
    let body: string;
    try {
      body = JSON.stringify(payload);
    } catch {
      return;
    }
    this.inFlight += 1;
    const task = fetch(`${this.baseUrl.replace(/\/$/, "")}/v1/ingest/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${this.apiKey}` },
      body,
      signal: AbortSignal.timeout(30000)
    }).catch(() => undefined) // telemetry fails open by design
      .finally(() => { this.inFlight -= 1; });
    this.pending.push(task);
  }

  emit(event: Record<string, unknown>): void {
    // Shed past the bound instead of growing without limit. The previous check
    // tested a queue that emit itself emptied on every call, so it never fired
    // and the real growth was one unsettled request per event.
    if (this.inFlight >= this.maxQueue) return;
    this.post({ events: [event] });
  }

  async flush(timeoutMs = 30000): Promise<void> {
    const waiting = this.pending;
    this.pending = [];
    await Promise.race([
      Promise.allSettled(waiting),
      new Promise((resolve) => setTimeout(resolve, timeoutMs))
    ]);
  }

  private envelope(over: Record<string, unknown>): Record<string, unknown> {
    return {
      schema_version: "1",
      event_id: `evt-${crypto.randomUUID()}`,
      workspace_name: this.workspaceName,
      agent_name: this.agentName,
      timestamp: nowIso(),
      status: "success",
      attributes: {},
      ...over
    };
  }

  startRun(runId?: string): string {
    const id = runId ?? crypto.randomUUID();
    this.emit(this.envelope({
      run_id: id, span_id: crypto.randomUUID(), parent_span_id: null, event_type: "run.started"
    }));
    return id;
  }

  modelEvent(runId: string, opts: ModelEventOptions = {}): string {
    const span = crypto.randomUUID();
    this.emit(this.envelope({
      run_id: runId, span_id: span, parent_span_id: opts.parentSpan ?? null,
      event_type: "model.request", status: opts.status ?? "success",
      provider: opts.provider ?? null, model: opts.model ?? null,
      input_tokens: opts.inputTokens ?? null, output_tokens: opts.outputTokens ?? null,
      usage_source: opts.usageSource ?? "provider_reported",
      error_type: opts.errorType ?? null, attributes: opts.attributes ?? {}
    }));
    return span;
  }

  endRun(runId: string, ok = true): void {
    this.emit(this.envelope({
      run_id: runId, span_id: crypto.randomUUID(), parent_span_id: null,
      event_type: ok ? "run.completed" : "run.failed",
      status: ok ? "success" : "failed"
    }));
  }
}

export class BudgetExceeded extends Error {}

export class BudgetGuard {
  constructor(private baseUrl: string, private apiKey: string, private budgetId: string) {}

  private async api(path: string, payload: Record<string, unknown>): Promise<{ status: number; body: Record<string, unknown> }> {
    const res = await fetch(`${this.baseUrl.replace(/\/$/, "")}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${this.apiKey}` },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(30000)
    });
    const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    return { status: res.status, body };
  }

  async reserve(maxCostMicro: number, ttlSeconds = 300): Promise<string> {
    const { status, body } = await this.api("/v1/budgets/check",
      { budget_id: this.budgetId, max_cost_micro: maxCostMicro, ttl_seconds: ttlSeconds });
    if (status !== 200 || typeof body.reservation_id !== "string") {
      throw new BudgetExceeded(String(body.error ?? `budget check failed: ${status}`));
    }
    return body.reservation_id;
  }

  async settle(reservationId: string, actualCostMicro?: number): Promise<void> {
    await this.api("/v1/budgets/settle",
      { reservation_id: reservationId, actual_cost_micro: actualCostMicro ?? null });
  }
}
