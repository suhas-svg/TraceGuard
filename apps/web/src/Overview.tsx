import { useQuery } from "@tanstack/react-query";
import { formatMicro, getOverview } from "./api";
import { Alert, Button, Page, Stat, TableSkeleton } from "./components";

// Fleet-level KPIs for the signed-in workspace: run totals, token usage,
// estimated spend with explicit partiality, latency percentiles, policy
// denials, and the live approval queue. One workspace-scoped API read backs
// the whole page, so the numbers can never disagree with each other.
function ms(v: number | null): string {
  if (v == null) return "n/a";
  return v >= 1000 ? `${(v / 1000).toFixed(1)} s` : `${Math.round(v)} ms`;
}

export default function OverviewView() {
  const overview = useQuery({
    queryKey: ["overview"],
    queryFn: getOverview,
    refetchInterval: 15_000
  });
  const o = overview.data;
  const error =
    overview.error instanceof Error ? overview.error.message : overview.error ? "load failed" : "";

  return (
    <Page
      title="Overview"
      sub="Runs, usage, spend, and policy posture across this workspace."
      actions={<Button onClick={() => overview.refetch()}>Refresh</Button>}
    >
      {error && <Alert>{error}</Alert>}
      {!o ? (
        <TableSkeleton label="Loading overview..." rows={3} />
      ) : (
        <>
          <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat
              label="Total runs"
              value={o.runs.total.toLocaleString()}
              hint={`${(o.runs.by_status.success ?? 0).toLocaleString()} success`}
            />
            <Stat
              label="Failed"
              value={o.runs.by_status.failed ?? 0}
              tone={(o.runs.by_status.failed ?? 0) > 0 ? "bad" : "default"}
              hint={`${o.runs.by_status.running ?? 0} running`}
            />
            <Stat
              label="Denied spans"
              value={o.denied_spans.toLocaleString()}
              tone={o.denied_spans > 0 ? "warn" : "default"}
              hint="policy or budget"
            />
            <Stat
              label="Pending approvals"
              value={o.pending_approvals.toLocaleString()}
              tone={o.pending_approvals > 0 ? "warn" : "default"}
              hint="unexpired"
            />
          </div>
          <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat
              label="Tokens in / out"
              value={`${o.tokens.input_tokens.toLocaleString()} / ${o.tokens.output_tokens.toLocaleString()}`}
              hint={
                o.tokens.spans_without_usage > 0
                  ? `${o.tokens.spans_without_usage.toLocaleString()} spans without usage`
                  : "usage complete"
              }
            />
            <Stat
              label="Estimated spend"
              value={formatMicro(o.cost.estimated_cost_micro)}
              tone={o.cost.cost_partial ? "warn" : "default"}
              hint={
                o.cost.cost_partial
                  ? `${o.cost.missing_pricing_spans.toLocaleString()} spans missing pricing`
                  : "fully priced"
              }
            />
            <Stat label="Latency median" value={ms(o.latency_ms.median)} hint="completed runs" />
            <Stat label="Latency p95" value={ms(o.latency_ms.p95)} hint="completed runs" />
          </div>
          <p className="text-xs text-ink-500">
            Estimates resolve against the pricing version in force when each span ran; unpriced
            usage is flagged, never billed as zero. Refreshes every 15 s.
          </p>
        </>
      )}
    </Page>
  );
}
