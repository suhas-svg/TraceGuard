import { useQuery } from "@tanstack/react-query";
import { formatMicro, getOverview, listRuns } from "./api";
import { Alert, Button, Page, Stat, TableSkeleton } from "./components";
import {
  ChartCard, Donut, Histogram, Legend, Meter, Sparkline, statusColor, type Slice
} from "./charts";

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
  const recent = useQuery({
    queryKey: ["overview-recent-runs"],
    queryFn: () => listRuns({ limit: 100 }),
    refetchInterval: 15_000
  });
  const o = overview.data;
  const error =
    overview.error instanceof Error ? overview.error.message : overview.error ? "load failed" : "";
  // Chart data derived from the same numbers the tiles show, plus the newest
  // 100 runs for the activity sparkline and duration histogram.
  const statusSlices: Slice[] = o
    ? Object.entries(o.runs.by_status)
        .filter(([, v]) => v > 0)
        .map(([k, v]) => ({ label: k, value: v, color: statusColor(k) }))
    : [];
  const runs = recent.data?.items ?? [];
  const perHour = new Map<string, number>();
  for (const r of runs) {
    const key = new Date(r.started_at).toISOString().slice(0, 13);
    perHour.set(key, (perHour.get(key) ?? 0) + 1);
  }
  const activity = [...perHour.keys()].sort().map((k) => perHour.get(k) ?? 0);
  const durations = runs
    .filter((r) => r.ended_at)
    .map((r) => (new Date(r.ended_at as string).getTime() - new Date(r.started_at).getTime()) / 1000);

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
          <div className="mb-4 grid gap-3 md:grid-cols-3">
            <ChartCard title="Run outcomes" sub={`${o.runs.total.toLocaleString()} runs in this view`}>
              <div className="flex items-center gap-5">
                <Donut slices={statusSlices}>
                  <div className="text-center">
                    <div className="tg-nums text-xl font-semibold text-ink-900">
                      {o.runs.total.toLocaleString()}
                    </div>
                    <div className="text-[11px] text-ink-500">runs</div>
                  </div>
                </Donut>
                <Legend slices={statusSlices} />
              </div>
            </ChartCard>
            <ChartCard title="Usage mix" sub="Tokens and spans across this view">
              <div className="flex flex-col gap-3">
                <Meter
                  label="Input tokens"
                  value={o.tokens.input_tokens}
                  max={Math.max(o.tokens.input_tokens, o.tokens.output_tokens, 1)}
                  color="var(--color-brand-500)"
                  valueText={o.tokens.input_tokens.toLocaleString()}
                />
                <Meter
                  label="Output tokens"
                  value={o.tokens.output_tokens}
                  max={Math.max(o.tokens.input_tokens, o.tokens.output_tokens, 1)}
                  color="var(--color-info-700)"
                  valueText={o.tokens.output_tokens.toLocaleString()}
                />
                <Meter
                  label="Spans with usage"
                  value={o.tokens.spans_with_usage}
                  max={Math.max(o.tokens.spans_with_usage + o.tokens.spans_without_usage, 1)}
                  color="var(--color-ok-700)"
                  valueText={`${o.tokens.spans_with_usage.toLocaleString()} / ${(
                    o.tokens.spans_with_usage + o.tokens.spans_without_usage
                  ).toLocaleString()}`}
                  hint={
                    o.tokens.spans_without_usage > 0
                      ? `${o.tokens.spans_without_usage.toLocaleString()} without usage`
                      : "every span reports usage"
                  }
                />
              </div>
            </ChartCard>
            <ChartCard title="Activity" sub="Runs per hour across the newest 100 runs">
              {activity.length > 1 ? (
                <Sparkline values={activity} className="h-24 w-full" />
              ) : (
                <p className="text-xs text-ink-500">Not enough runs for a trend yet.</p>
              )}
              {durations.length > 0 && (
                <>
                  <p className="mt-3 mb-1 text-xs font-medium text-ink-500">Run duration (s)</p>
                  <Histogram values={durations} className="w-full" />
                </>
              )}
            </ChartCard>
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
