import { useState, type KeyboardEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  formatMicro, getDiagnostics, getTrace, getUsage, gwApi,
  type PolicyDecision, type Span
} from "./api";
import { buildTree, tokenTotal, type SpanNode } from "./tree";
import { relTime } from "./format";
import { Alert, NavIcon, Page, TableSkeleton } from "./components";

type SpanKind = "model" | "tool" | "policy" | "agent" | "other";
type InspectorTab = "overview" | "attributes" | "decisions";

function short(id: string) {
  return id.slice(0, 8);
}

function spanKind(operation: string): SpanKind {
  const o = operation.toLowerCase();
  if (o.includes("model")) return "model";
  if (o.includes("tool")) return "tool";
  if (o.includes("policy") || o.includes("decision") || o.includes("budget")) return "policy";
  if (o.includes("agent") || o.includes("run")) return "agent";
  return "other";
}

function spanIcon(kind: SpanKind) {
  if (kind === "model") return "model";
  if (kind === "tool") return "tool";
  if (kind === "policy") return "policy";
  return "runs";
}

function traceTone(status: string) {
  if (status === "success" || status === "approved") return "ok";
  if (status === "running" || status === "pending") return "warn";
  if (status === "failed" || status === "denied" || status === "cancelled") return "bad";
  return "mute";
}

function decisionTone(decision: string) {
  if (decision === "allow" || decision === "approved_retry") return "ok";
  if (decision === "need_approval") return "warn";
  return "bad";
}

function ruleLabel(decision: PolicyDecision) {
  return (decision.matched_rules ?? []).map((m) => m.name ?? m.id ?? "?").join(", ") || "—";
}

function runDuration(started: string, ended: string | null) {
  if (!ended) return "—";
  const ms = new Date(ended).getTime() - new Date(started).getTime();
  if (!Number.isFinite(ms) || ms < 0) return "—";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(ms < 10_000 ? 2 : 1)} s`;
}

function TraceStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="tg-trace-stat">
      <div className="tg-trace-stat-label">{label}</div>
      <div className="tg-trace-stat-value">{value}</div>
    </div>
  );
}

function SpanRow({ node, depth, selected, onSelect, base, maxEnd }: {
  node: SpanNode;
  depth: number;
  selected: string | null;
  onSelect: (id: string) => void;
  base: number;
  maxEnd: number;
}) {
  const s = node.span;
  const kind = spanKind(s.operation_type);
  const start = new Date(s.started_at).getTime() - base;
  const dur = s.duration_ms ?? 0;
  const left = maxEnd > 0 ? Math.min(96, (start / maxEnd) * 100) : 0;
  const width = maxEnd > 0 && dur > 0
    ? Math.max(1.5, Math.min(100 - left, (dur / maxEnd) * 100))
    : 1.5;
  const denied = s.status === "denied";
  return (
    <>
      <button
        type="button"
        data-span={s.id}
        className={`tg-span-row ${selected === s.id ? "is-selected" : ""}`}
        onClick={() => onSelect(s.id)}
        onKeyDown={(e) => {
          // Arrows walk the flattened visible tree in DOM order.
          if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
          e.preventDefault();
          const all = [...document.querySelectorAll<HTMLButtonElement>("[data-span]")];
          const next = all[all.indexOf(e.currentTarget) + (e.key === "ArrowDown" ? 1 : -1)];
          if (next?.dataset.span) {
            onSelect(next.dataset.span);
            next.focus();
          }
        }}
      >
        <span className="tg-span-label" style={{ paddingLeft: `${depth * 13}px` }}>
          <NavIcon name={spanIcon(kind)} className={`tg-span-icon ${kind}`} />
          <span className="tg-span-name">{s.operation_type}</span>
          {s.model && <span className="tg-span-model">{s.model}</span>}
          {(denied || s.error_type) && (
            <span className="tg-mini-badge bad">{denied ? "denied" : s.error_type}</span>
          )}
        </span>
        <span className="tg-span-track" aria-hidden="true">
          <span
            className={`tg-span-bar ${kind}${denied ? " denied" : ""}`}
            style={{ left: `${left}%`, width: `${width}%` }}
          />
        </span>
        <span className="tg-span-duration">
          {s.duration_ms != null ? `${s.duration_ms} ms` : "—"}
        </span>
      </button>
      {node.children.map((c) => (
        <SpanRow
          key={c.span.id}
          node={c}
          depth={depth + 1}
          selected={selected}
          onSelect={onSelect}
          base={base}
          maxEnd={maxEnd}
        />
      ))}
    </>
  );
}

function MetaCell({ label, value }: { label: string; value: string }) {
  return (
    <div className="tg-meta-cell">
      <div className="tg-meta-k">{label}</div>
      <div className="tg-meta-v">{value}</div>
    </div>
  );
}

function TraceInspector({ span, decision, costMicro, offsetMs, tab, onTab, onOpenPolicy }: {
  span: Span;
  decision: PolicyDecision | null;
  costMicro: number | null | undefined;
  offsetMs: number;
  tab: InspectorTab;
  onTab: (tab: InspectorTab) => void;
  onOpenPolicy: () => void;
}) {
  const tabs: { key: InspectorTab; label: string }[] = [
    { key: "overview", label: "Overview" },
    { key: "attributes", label: "Attributes" },
    { key: "decisions", label: "Decisions" }
  ];
  const kind = spanKind(span.operation_type);
  const targetLabel = kind === "model" ? "Model" : kind === "tool" ? "Tool" : kind === "agent" ? "Agent" : "Target";
  const targetValue =
    kind === "tool" ? String(span.attributes?.tool_name ?? span.attributes?.tool ?? "—")
    : kind === "agent" ? String(span.attributes?.agent_name ?? span.attributes?.agent ?? "—")
    : span.model ?? span.provider ?? "—";
  const hasUsage = span.input_tokens != null || span.output_tokens != null;
  const costText =
    costMicro === undefined ? "…" : !hasUsage ? "n/a"
    : costMicro === null ? "unpriced" : formatMicro(costMicro);
  const reason =
    (span.attributes?.reason as string | undefined) ?? decision?.reason ?? span.error_type ?? null;
  const showCallout = Boolean(decision || span.status === "denied");
  const allowed = decision
    ? decision.decision === "allow" || decision.decision === "approved_retry"
    : false;

  const moveTab = (e: KeyboardEvent<HTMLDivElement>) => {
    if (!["ArrowRight", "ArrowLeft", "Home", "End"].includes(e.key)) return;
    e.preventDefault();
    const index = tabs.findIndex((t) => t.key === tab);
    const nextIndex =
      e.key === "Home" ? 0
      : e.key === "End" ? tabs.length - 1
      : (index + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length;
    const next = tabs[nextIndex];
    onTab(next.key);
    (e.currentTarget.parentElement?.querySelector(`[data-itab="${next.key}"]`) as HTMLButtonElement | null)?.focus();
  };

  return (
    <>
      <div className="tg-inspector-head">
        <NavIcon name={spanIcon(kind)} className={`tg-span-icon ${kind} tg-inspector-icon`} />
        <div className="min-w-0">
          <div className="tg-inspector-title">{span.operation_type}</div>
          <div className="tg-inspector-sub">
            {kind} span · {span.status}
          </div>
        </div>
        <span className={`tg-mini-badge ${span.status === "denied" || span.error_type ? "bad" : "ok"} ml-auto`}>
          {span.status}
        </span>
      </div>

      <div className="tg-inspector-tabs" role="tablist" aria-label="Span detail" onKeyDown={moveTab}>
        {tabs.map((t) => (
          <button
            key={t.key}
            type="button"
            role="tab"
            id={`span-tab-${t.key}`}
            data-itab={t.key}
            aria-selected={tab === t.key}
            aria-controls={`span-panel-${t.key}`}
            tabIndex={tab === t.key ? 0 : -1}
            onClick={() => onTab(t.key)}
            className={`tg-inspector-tab ${tab === t.key ? "is-active" : ""}`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "overview" && (
        <div role="tabpanel" id="span-panel-overview" aria-labelledby="span-tab-overview">
          <div className="tg-meta-grid">
            <MetaCell label="Status" value={span.status} />
            <MetaCell label="Duration" value={span.duration_ms != null ? `${span.duration_ms} ms` : "n/a"} />
            <MetaCell label="Started" value={`+${Math.max(0, Math.round(offsetMs))} ms`} />
            <MetaCell label="Type" value={kind} />
            <MetaCell label="Provider" value={span.provider ?? "n/a"} />
            <MetaCell label={targetLabel} value={targetValue} />
            <MetaCell label="Usage source" value={span.usage_source ?? "n/a"} />
            <MetaCell label="Error" value={span.error_type ?? "none"} />
          </div>

          <div className="tg-inspector-section">
            <div className="tg-inspector-section-title">Tokens &amp; cost</div>
            <div className="tg-token-strip">
              <div className="tg-token-box">
                <div className="tg-token-box-label">Input</div>
                <div className="tg-token-box-value">
                  {span.input_tokens != null ? span.input_tokens.toLocaleString() : "—"}
                </div>
              </div>
              <div className="tg-token-box">
                <div className="tg-token-box-label">Output</div>
                <div className="tg-token-box-value">
                  {span.output_tokens != null ? span.output_tokens.toLocaleString() : "—"}
                </div>
              </div>
              <div className="tg-token-box">
                <div className="tg-token-box-label">Cost</div>
                <div className="tg-token-box-value">{costText}</div>
              </div>
            </div>
          </div>

          {showCallout ? (
            <div className={`tg-policy-callout ${allowed ? "ok" : ""}`}>
              <div className="tg-callout-head">
                <NavIcon name={allowed ? "check" : "policy"} className="h-3.5 w-3.5" />
                {allowed ? "Allowed by policy" : "Denied by policy"}
                <span className={`tg-mini-badge ${allowed ? "ok" : "bad"}`}>
                  {decision?.decision ?? span.status}
                </span>
              </div>
              <p>{reason ?? "No reason recorded."}</p>
              <div className="tg-callout-meta">
                <span>Rule <code>{decision ? ruleLabel(decision) : "—"}</code></span>
                <span>Effect <code>{decision?.decision ?? "block"}</code></span>
                <span>Policy <code>{decision?.policy_version ? `v${decision.policy_version}` : "—"}</code></span>
              </div>
              <button type="button" onClick={onOpenPolicy} className="tg-callout-link">
                Open policy <NavIcon name="arrowRight" className="h-3 w-3" />
              </button>
            </div>
          ) : (
            <p className="tg-inspector-empty">No policy decision was recorded for this span.</p>
          )}
        </div>
      )}

      {tab === "attributes" && (
        <div role="tabpanel" id="span-panel-attributes" aria-labelledby="span-tab-attributes">
          <pre className="tg-json-block">{JSON.stringify(span.attributes, null, 2)}</pre>
        </div>
      )}

      {tab === "decisions" && (
        <div role="tabpanel" id="span-panel-decisions" aria-labelledby="span-tab-decisions">
          {decision ? (
            <div className="tg-decision-mini">
              <div className="tg-decision-mini-row">
                <span className={`tg-decision-badge ${decisionTone(decision.decision)}`}>
                  {decision.decision}
                </span>
                <span>{ruleLabel(decision)}</span>
                <span className="tg-time">
                  {decision.policy_version ? `v${decision.policy_version}` : ""}
                </span>
              </div>
              <div className="tg-decision-mini-row">
                <span className="tg-muted">Reason</span>
                <span>{decision.reason}</span>
              </div>
              <div className="tg-decision-mini-row">
                <span className="tg-muted">Span</span>
                <span className="tg-mono">{span.id}</span>
                <span className="tg-time">+{Math.max(0, Math.round(offsetMs))} ms</span>
              </div>
            </div>
          ) : (
            <p className="tg-inspector-empty">No policy decision was recorded for this span.</p>
          )}
        </div>
      )}
    </>
  );
}

export default function TraceView({ runId, onBack, onOpenApproval, onOpenPolicy }: {
  runId: string;
  onBack: () => void;
  onOpenApproval: (approvalId: string) => void;
  onOpenPolicy: () => void;
}) {
  const [selected, setSelected] = useState<string | null>(null);
  const [inspectorTab, setInspectorTab] = useState<InspectorTab>("overview");
  const [copied, setCopied] = useState(false);
  const traceQuery = useQuery({ queryKey: ["trace", runId], queryFn: () => getTrace(runId) });
  const usageQuery = useQuery({ queryKey: ["usage", runId], queryFn: () => getUsage(runId) });
  const diagnosticsQuery = useQuery({
    queryKey: ["diagnostics", runId],
    queryFn: () => getDiagnostics(runId),
    retry: false
  });
  // FR-021: gateway decisions correlated to this trace by run_id.
  const decisionsQuery = useQuery({
    queryKey: ["decisions", runId],
    queryFn: () => gwApi.decisions(runId),
    retry: false
  });

  const error = traceQuery.error instanceof Error ? traceQuery.error.message : traceQuery.error ? "load failed" : "";
  const run = traceQuery.data?.run ?? null;
  const spans: Span[] = traceQuery.data?.spans ?? [];
  const costBySpan = new Map((usageQuery.data?.spans ?? []).map((u) => [u.id, u.cost_micro]));
  const warnings = diagnosticsQuery.data?.warnings ?? [];
  const decisions = decisionsQuery.data?.items ?? [];
  const cost = usageQuery.data
    ? `${formatMicro(usageQuery.data.estimated_cost_micro)}${usageQuery.data.cost_partial ? " (partial)" : ""}`
    : usageQuery.isError ? "n/a" : "…";

  if (error) {
    return (
      <Page eyebrow="Monitor" title="Trace">
        <Alert>{error}</Alert>
        <button type="button" onClick={onBack} className="text-sm font-medium text-brand-600 hover:underline">
          Back to runs
        </button>
      </Page>
    );
  }
  if (!run) {
    return (
      <Page eyebrow="Monitor" title="Trace">
        <TableSkeleton label="Loading trace..." />
      </Page>
    );
  }

  const roots = buildTree(spans);
  const totals = tokenTotal(spans);
  const selectedSpan = spans.find((s) => s.id === selected) ?? spans[0] ?? null;
  // Prefer the span id, then the request id the gateway stamps on denied
  // spans; older rows predate span correlation but still carry request_id.
  const selectedRequestId = selectedSpan?.attributes?.request_id;
  const selectedDecision = selectedSpan
    ? decisions.find((d) => d.span_id === selectedSpan.id)
      ?? decisions.find((d) => typeof selectedRequestId === "string" && d.request_id === selectedRequestId)
      ?? null
    : null;
  const base = spans.length
    ? Math.min(...spans.map((s) => new Date(s.started_at).getTime()))
    : 0;
  const maxEnd = spans.length
    ? Math.max(...spans.map((s) => new Date(s.started_at).getTime() + (s.duration_ms ?? 0))) - base
    : 0;
  const offsetMs = selectedSpan ? new Date(selectedSpan.started_at).getTime() - base : 0;
  const duration = runDuration(run.started_at, run.ended_at);
  const denialCount = spans.filter((s) => s.status === "denied").length;
  const modelCalls = spans.filter((s) => s.operation_type.toLowerCase().includes("model")).length;
  const policyVersion = decisions.reduce<number | null>(
    (max, d) => (d.policy_version != null && (max == null || d.policy_version > max) ? d.policy_version : max),
    null
  );

  const copyLink = async () => {
    try {
      await navigator.clipboard.writeText(window.location.href);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // Clipboard can be blocked by browser policy; the URL is still in the bar.
    }
  };

  return (
    <div className="mx-auto max-w-[1480px] px-4 py-5 lg:px-8 lg:py-6">
      <div className="tg-trace">
        <div className="tg-trace-top">
          <button type="button" onClick={onBack} className="tg-trace-back">
            <NavIcon name="arrowLeft" className="h-3.5 w-3.5" />
            Back to runs
          </button>

          <div className="mt-3.5 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`tg-chip ${traceTone(run.status)}`}>{run.status}</span>
                {run.error_type && <span className="tg-chip bad">{run.error_type}</span>}
                <span className="tg-focus-pill">
                  <NavIcon name="eye" className="h-3 w-3" />
                  Focus mode
                </span>
              </div>
              <h1 className="tg-trace-title">{run.id}</h1>
              <p className="tg-trace-sub">
                {run.agent_name} · started {new Date(run.started_at).toLocaleString()} · {duration}
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              <button type="button" onClick={() => void copyLink()} className="tg-dark-btn" aria-live="polite">
                <NavIcon name="copy" className="h-3.5 w-3.5" />
                {copied ? "Copied" : "Copy link"}
              </button>
              <button type="button" onClick={onBack} className="tg-dark-btn">
                <NavIcon name="runs" className="h-3.5 w-3.5" />
                All runs
              </button>
              <button
                type="button"
                onClick={onOpenPolicy}
                aria-label="Open policy"
                title="Open policy"
                className="tg-dark-icon"
              >
                <NavIcon name="policy" className="h-4 w-4" />
              </button>
            </div>
          </div>

          <div className="tg-trace-stats">
            <TraceStat label="Duration" value={duration} />
            <TraceStat label="Spans" value={String(spans.length)} />
            <TraceStat label="Tokens in / out" value={`${totals.input.toLocaleString()} / ${totals.output.toLocaleString()}`} />
            <TraceStat label="Est. cost" value={cost} />
            <TraceStat label="Policy" value={policyVersion != null ? `v${policyVersion}` : "—"} />
            <TraceStat label="Decisions" value={String(decisions.length)} />
          </div>

          {warnings.length > 0 && (
            <div role="status" className="tg-trace-warning">
              <span className="font-semibold">Diagnostics:</span>{" "}
              {warnings.map((w) => w.message).join(" · ")}
            </div>
          )}
        </div>

        <div className="tg-trace-grid">
          <section className="tg-waterfall" aria-label="Trace timeline">
            <div className="tg-wf-head">
              <div>
                <div className="tg-wf-title">Trace timeline</div>
                <div className="tg-wf-sub">
                  {spans.length} spans · {denialCount} policy denial{denialCount === 1 ? "" : "s"} ·{" "}
                  {modelCalls} model call{modelCalls === 1 ? "" : "s"}
                </div>
              </div>
            </div>

            <div className="tg-wf-ruler" aria-hidden="true">
              <span>Span</span>
              <span className="tg-ruler-track">
                <span>0 ms</span>
                <span>{Math.round(maxEnd * 0.25)}</span>
                <span>{Math.round(maxEnd * 0.5)}</span>
                <span>{Math.round(maxEnd * 0.75)}</span>
                <span>{Math.round(maxEnd)} ms</span>
              </span>
              <span />
            </div>

            <div className="tg-wf-body">
              {roots.map((n) => (
                <SpanRow
                  key={n.span.id}
                  node={n}
                  depth={0}
                  selected={selectedSpan?.id ?? null}
                  onSelect={setSelected}
                  base={base}
                  maxEnd={maxEnd}
                />
              ))}
              {roots.length === 0 && <p className="tg-inspector-empty">No spans recorded.</p>}
            </div>

            <div className="tg-wf-foot">
              <span>Click a span to inspect it · ↑↓ moves through spans</span>
              <span>{spans.length} spans</span>
            </div>
          </section>

          <aside className="tg-inspector" aria-label="Span inspector">
            {selectedSpan ? (
              <TraceInspector
                span={selectedSpan}
                decision={selectedDecision}
                costMicro={usageQuery.data ? costBySpan.get(selectedSpan.id) ?? null : undefined}
                offsetMs={offsetMs}
                tab={inspectorTab}
                onTab={setInspectorTab}
                onOpenPolicy={onOpenPolicy}
              />
            ) : (
              <p className="tg-inspector-empty">Select a span to inspect its timing, tokens, and error.</p>
            )}
          </aside>
        </div>

        <section className="tg-decisions">
          <div className="tg-decisions-head">
            <div>
              <h2 className="tg-decisions-title">Decisions</h2>
              <p className="tg-decisions-sub">
                Gateway policy decisions for this run, including blocked and approval-gated calls.
              </p>
            </div>
            <button type="button" onClick={onOpenPolicy} className="tg-dark-btn">
              <NavIcon name="policy" className="h-3.5 w-3.5" />
              Open policy
            </button>
          </div>

          {decisionsQuery.isError ? (
            <div className="tg-trace-warning" role="alert">
              {(decisionsQuery.error as Error)?.message ?? "decisions failed to load"}
            </div>
          ) : decisions.length === 0 ? (
            <p className="tg-decisions-empty">No gateway decisions recorded for this run.</p>
          ) : (
            <div className="tg-decisions-table-wrap">
              <table aria-label="Policy decisions" className="tg-decisions-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Target</th>
                    <th>Decision</th>
                    <th>Reason</th>
                    <th>Matched rule</th>
                    <th>Policy</th>
                    <th>Approval</th>
                  </tr>
                </thead>
                <tbody>
                  {decisions.map((d) => (
                    <tr key={d.id}>
                      <td className="tg-mono" title={new Date(d.timestamp).toLocaleString()}>
                        {relTime(d.timestamp)}
                      </td>
                      <td className="tg-mono">{d.tool_name}</td>
                      <td>
                        <span className={`tg-decision-badge ${decisionTone(d.decision)}`}>{d.decision}</span>
                      </td>
                      <td>{d.reason ?? "—"}</td>
                      <td className="tg-mono">{ruleLabel(d)}</td>
                      <td className="tg-mono">{d.policy_version ? `v${d.policy_version}` : "—"}</td>
                      <td>
                        {d.approval_id ? (
                          <button
                            type="button"
                            onClick={() => onOpenApproval(d.approval_id!)}
                            className="tg-dark-link"
                          >
                            open {short(d.approval_id)}
                          </button>
                        ) : (
                          "—"
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
