// FR-010 loop and usage diagnostics. Advisory only: these warnings never
// block execution, never alter policy decisions, and are computed on read.
//
// The thresholds are deliberately simple heuristics. An agent stuck in a
// loop looks like one of these signals, and a human reviewing the run can
// see the warning in the dashboard or via the API.

export interface DiagnosticThresholds {
  /** Warn when a run makes more tool calls than this. */
  maxCalls: number;
  /** Warn when a run lasts at least this long. */
  maxDurationMs: number;
  /** Warn when total token usage reaches this. */
  maxTokens: number;
  /** Warn when the same tool fails this many times in one run. */
  repeatedFailures: number;
}

export interface WarningSpan {
  operation_type: string;
  name: string | null;
  status: string | null;
  error_type?: string | null;
  started_at: Date | string;
  ended_at?: Date | string | null;
  input_tokens?: number | string | null;
  output_tokens?: number | string | null;
  attributes?: Record<string, unknown> | null;
}

export interface WarningRun {
  status: string;
  started_at: Date | string;
  ended_at?: Date | string | null;
}

export interface DiagnosticWarning {
  code: "high_call_count" | "repeated_tool_failures" | "long_running_run" | "high_token_usage";
  severity: "warning";
  message: string;
  details: Record<string, unknown>;
}

function intFromEnv(raw: string | undefined, fallback: number): number {
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

// Defaults are intentionally conservative: 50 calls, 30 minutes, 1M tokens,
// and 3 identical failures are unusual for a single healthy run.
export function thresholdsFromEnv(env: Record<string, string | undefined> = process.env): DiagnosticThresholds {
  return {
    maxCalls: intFromEnv(env.DIAG_MAX_CALLS, 50),
    maxDurationMs: intFromEnv(env.DIAG_MAX_DURATION_MS, 30 * 60 * 1000),
    maxTokens: intFromEnv(env.DIAG_MAX_TOKENS, 1_000_000),
    repeatedFailures: intFromEnv(env.DIAG_REPEATED_FAILURES, 3)
  };
}

const ms = (value: Date | string): number => new Date(value).getTime();

export function computeWarnings(
  run: WarningRun,
  spans: WarningSpan[],
  thresholds: DiagnosticThresholds = thresholdsFromEnv()
): DiagnosticWarning[] {
  const warnings: DiagnosticWarning[] = [];
  const toolSpans = spans.filter((s) => s.operation_type === "tool.invocation");

  if (toolSpans.length > thresholds.maxCalls) {
    warnings.push({
      code: "high_call_count",
      severity: "warning",
      message: `Run made ${toolSpans.length} tool calls (threshold ${thresholds.maxCalls}); possible loop.`,
      details: { tool_calls: toolSpans.length, threshold: thresholds.maxCalls }
    });
  }

  // Identical failure = same upstream (server_id when present, "-" otherwise)
  // and same tool name. Denials count too: hammering a tool the policy keeps
  // refusing is the same loop pattern.
  const failures = new Map<string, { server: string; tool: string; count: number }>();
  for (const span of toolSpans) {
    if (span.status !== "failed" && span.status !== "denied") continue;
    const attrs = span.attributes ?? {};
    const server = typeof attrs.server_id === "string" ? attrs.server_id : "-";
    const tool = typeof attrs.tool === "string" ? attrs.tool : (span.name ?? "unknown");
    const key = `${server}:${tool}`;
    const entry = failures.get(key) ?? { server, tool, count: 0 };
    entry.count += 1;
    failures.set(key, entry);
  }
  for (const { tool, count } of failures.values()) {
    if (count >= thresholds.repeatedFailures) {
      warnings.push({
        code: "repeated_tool_failures",
        severity: "warning",
        message: `Tool "${tool}" failed ${count} times in this run (threshold ${thresholds.repeatedFailures}); possible loop.`,
        details: { tool, failures: count, threshold: thresholds.repeatedFailures }
      });
    }
  }

  const started = ms(run.started_at);
  const ended = run.ended_at ? ms(run.ended_at) : Date.now();
  const durationMs = ended - started;
  if (Number.isFinite(durationMs) && durationMs >= thresholds.maxDurationMs) {
    const stillRunning = !run.ended_at && run.status === "running";
    warnings.push({
      code: "long_running_run",
      severity: "warning",
      message: `Run has lasted ${Math.round(durationMs / 1000)}s (threshold ${Math.round(thresholds.maxDurationMs / 1000)}s)${stillRunning ? " and is still running" : ""}.`,
      details: { duration_ms: durationMs, threshold_ms: thresholds.maxDurationMs, still_running: stillRunning }
    });
  }

  let totalTokens = 0;
  let tokensUnknown = 0;
  for (const span of spans) {
    const input = span.input_tokens == null ? null : Number(span.input_tokens);
    const output = span.output_tokens == null ? null : Number(span.output_tokens);
    if (input == null && output == null) {
      tokensUnknown += 1;
      continue;
    }
    totalTokens += input ?? 0;
    totalTokens += output ?? 0;
  }
  if (totalTokens >= thresholds.maxTokens) {
    warnings.push({
      code: "high_token_usage",
      severity: "warning",
      message: `Run used ${totalTokens} tokens (threshold ${thresholds.maxTokens}).`,
      details: {
        input_output_tokens: totalTokens,
        threshold: thresholds.maxTokens,
        spans_without_usage: tokensUnknown
      }
    });
  }

  return warnings;
}
