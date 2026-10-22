import { useEffect, useMemo, useRef, useState, type ComponentProps } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  formatMicro,
  getOverview,
  gwApi,
  listRuns,
  type Approval,
  type RunItem
} from "./api";
import {
  Alert,
  Button,
  Card,
  Empty,
  LinkButton,
  NavIcon,
  Page,
  Stat,
  StatusBadge,
  TableSkeleton
} from "./components";
import { Donut, Legend, Sparkline, statusColor } from "./charts";
import { relTime } from "./format";
import type { Tab } from "./router";

type NavName = ComponentProps<typeof NavIcon>["name"];

type OverviewProps = {
  onNavigate?: (tab: Tab) => void;
  onOpenRun?: (runId: string) => void;
  onOpenApproval?: (approvalId: string) => void;
};

type StatusSlice = { label: string; value: number; color: string };

const STATUS_LABELS: Record<string, string> = {
  success: "Success",
  failed: "Failed",
  running: "Running",
  cancelled: "Cancelled",
  denied: "Denied"
};

function ms(value: number | null): string {
  if (value === null || !Number.isFinite(value)) return "n/a";
  if (value >= 1000) return `${(value / 1000).toFixed(2)} s`;
  return `${Math.round(value)} ms`;
}

function percentile(values: number[], p: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[index] ?? 0;
}

function runDuration(run: RunItem): string {
  if (!run.ended_at) return "running";
  const started = new Date(run.started_at).getTime();
  const ended = new Date(run.ended_at).getTime();
  const duration = ended - started;
  if (!Number.isFinite(duration) || duration < 0) return "—";
  return duration >= 1000 ? `${(duration / 1000).toFixed(2)} s` : `${duration} ms`;
}

function expiresLabel(iso: string): string {
  const remaining = new Date(iso).getTime() - Date.now();
  if (!Number.isFinite(remaining)) return "expiry unknown";
  if (remaining <= 0) return "expired";
  const minutes = Math.ceil(remaining / 60_000);
  return `expires in ${minutes} min`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function formatSpend(micro: number): string {
  const dollars = micro / 1_000_000;
  return dollars >= 1 ? `$${dollars.toFixed(2)}` : formatMicro(micro);
}

type ActivityBucket = { hour: string; runs: number; success: number; durations: number[] };

function smoothLine(points: ReadonlyArray<readonly [number, number]>): string {
  if (points.length === 0) return "";
  if (points.length === 1) return `M ${points[0][0]},${points[0][1]}`;
  let path = `M ${points[0][0]},${points[0][1]}`;
  for (let i = 0; i < points.length - 1; i += 1) {
    const p0 = points[i - 1] ?? points[i];
    const p1 = points[i];
    const p2 = points[i + 1];
    const p3 = points[i + 2] ?? p2;
    const cp1x = p1[0] + (p2[0] - p0[0]) / 6;
    const cp1y = p1[1] + (p2[1] - p0[1]) / 6;
    const cp2x = p2[0] - (p3[0] - p1[0]) / 6;
    const cp2y = p2[1] - (p3[1] - p1[1]) / 6;
    path += ` C ${cp1x},${cp1y} ${cp2x},${cp2y} ${p2[0]},${p2[1]}`;
  }
  return path;
}

function hourLabel(hour: string): string {
  const date = new Date(`${hour}:00:00Z`);
  if (Number.isNaN(date.getTime())) return hour.slice(11, 16);
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function activitySpanHours(buckets: ActivityBucket[]): number {
  if (buckets.length === 0) return 0;
  const first = new Date(`${buckets[0].hour}:00:00Z`).getTime();
  const last = new Date(`${buckets[buckets.length - 1].hour}:00:00Z`).getTime();
  if (!Number.isFinite(first) || !Number.isFinite(last)) return buckets.length;
  return Math.max(1, Math.round((last - first) / 3_600_000) + 1);
}

function ActivityChart({ buckets }: { buckets: ActivityBucket[] }) {
  const hostRef = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ width: 820, height: 320 });

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    const observer = new ResizeObserver((entries) => {
      const rect = entries[0]?.contentRect;
      if (!rect) return;
      setSize({
        width: Math.max(280, Math.round(rect.width)),
        height: Math.max(220, Math.round(rect.height))
      });
    });
    observer.observe(host);
    return () => observer.disconnect();
  }, []);

  const { width: W, height: H } = size;
  const values = buckets.map((bucket) => bucket.runs);
  const max = Math.max(...values, 1) * 1.18;
  const left = W < 520 ? 30 : 38;
  const right = 10;
  const top = 14;
  const bottom = 26;
  const x = (index: number) => left + (index / Math.max(1, values.length - 1)) * (W - left - right);
  const y = (value: number) => top + (1 - value / max) * (H - top - bottom);
  const points = values.map((value, index) => [x(index), y(value)] as const);
  const line = smoothLine(points);
  const area = `${line} L ${x(values.length - 1)},${H - bottom} L ${x(0)},${H - bottom} Z`;
  const ticks = [...new Set(
    max <= 4
      ? Array.from({ length: Math.floor(max) + 1 }, (_, i) => i)
      : [0, Math.round(max / 3), Math.round((max / 3) * 2), Math.round(max)]
  )];
  const labelStep = Math.max(1, Math.ceil(buckets.length / (W < 520 ? 4 : 6)));
  const labelIndexes = buckets
    .map((_, index) => index)
    .filter((index) => index % labelStep === 0 || index === buckets.length - 1);
  const last = points[points.length - 1];

  return (
    <div ref={hostRef} className="h-full min-h-[240px] w-full sm:min-h-[300px]">
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="h-full w-full overflow-visible"
        role="img"
        aria-label={`Run activity across ${buckets.length} hours`}
      >
        <defs>
          <linearGradient id="overview-activity-area" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--color-brand-500)" stopOpacity="0.2" />
            <stop offset="100%" stopColor="var(--color-brand-500)" stopOpacity="0" />
          </linearGradient>
        </defs>
        {ticks.map((tick) => (
          <g key={tick}>
            <line
              x1={left}
              y1={y(tick)}
              x2={W - right}
              y2={y(tick)}
              stroke="var(--color-ink-200)"
              strokeDasharray="3 4"
            />
            <text x={left - 8} y={y(tick) + 3} textAnchor="end" fontSize={10} fill="var(--color-ink-400)">
              {Math.round(tick)}
            </text>
          </g>
        ))}
        <path d={area} fill="url(#overview-activity-area)" />
        <path
          d={line}
          fill="none"
          stroke="var(--color-brand-500)"
          strokeWidth={2.2}
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        {points.map(([px, py], index) => (
          <circle key={buckets[index]?.hour ?? index} cx={px} cy={py} r={2.4} fill="var(--color-brand-500)" />
        ))}
        {last ? (
          <circle
            cx={last[0]}
            cy={last[1]}
            r={4}
            fill="var(--color-brand-500)"
            stroke="var(--color-surface)"
            strokeWidth={2}
          />
        ) : null}
        {labelIndexes.map((index) => (
          <text
            key={buckets[index]?.hour ?? index}
            x={x(index)}
            y={H - 7}
            textAnchor={index === 0 ? "start" : index === buckets.length - 1 ? "end" : "middle"}
            fontSize={10}
            fill="var(--color-ink-400)"
          >
            {hourLabel(buckets[index]?.hour ?? "")}
          </text>
        ))}
      </svg>
    </div>
  );
}

export function Overview({ onNavigate, onOpenRun, onOpenApproval }: OverviewProps) {
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
  const approvals = useQuery({
    queryKey: ["overview-pending-approvals"],
    queryFn: () => gwApi.approvals("pending"),
    refetchInterval: 15_000,
    retry: false
  });

  const o = overview.data;
  const runs = recent.data?.items ?? [];
  const pending = approvals.data?.items ?? [];

  const success = o?.runs.by_status.success ?? 0;
  const failed = o?.runs.by_status.failed ?? 0;
  const running = o?.runs.by_status.running ?? 0;
  const total = o?.runs.total ?? 0;
  const successRate = total > 0 ? (success / total) * 100 : null;

  const statusSlices = useMemo<StatusSlice[]>(() => {
    if (!o) return [];
    return Object.entries(o.runs.by_status)
      .filter(([, value]) => value > 0)
      .map(([status, value]) => ({
        label: STATUS_LABELS[status] ?? status,
        value,
        color: statusColor(status)
      }));
  }, [o]);

  const hourly = useMemo(() => {
    const buckets = new Map<string, { runs: number; success: number; durations: number[] }>();
    for (const run of runs) {
      const started = new Date(run.started_at);
      if (Number.isNaN(started.getTime())) continue;
      const key = started.toISOString().slice(0, 13);
      const bucket = buckets.get(key) ?? { runs: 0, success: 0, durations: [] };
      bucket.runs += 1;
      if (run.status === "success") bucket.success += 1;
      if (run.ended_at) {
        const ended = new Date(run.ended_at).getTime();
        const duration = ended - started.getTime();
        if (Number.isFinite(duration) && duration >= 0) bucket.durations.push(duration);
      }
      buckets.set(key, bucket);
    }
    return [...buckets.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([hour, bucket]) => ({ hour, ...bucket }));
  }, [runs]);

  const activity = hourly.map((bucket) => bucket.runs);
  const successSeries = hourly.map((bucket) => (bucket.runs > 0 ? (bucket.success / bucket.runs) * 100 : 0));
  const latencySeries = hourly
    .filter((bucket) => bucket.durations.length > 0)
    .map((bucket) => percentile(bucket.durations, 95));

  const topAgents = useMemo(() => {
    const agents = new Map<string, { runs: number; success: number }>();
    for (const run of runs) {
      const entry = agents.get(run.agent_name) ?? { runs: 0, success: 0 };
      entry.runs += 1;
      if (run.status === "success") entry.success += 1;
      agents.set(run.agent_name, entry);
    }
    return [...agents.entries()]
      .map(([name, entry]) => ({
        name,
        runs: entry.runs,
        success: entry.runs > 0 ? Math.round((entry.success / entry.runs) * 100) : 0
      }))
      .sort((a, b) => b.runs - a.runs)
      .slice(0, 4);
  }, [runs]);

  const maxAgentRuns = topAgents[0]?.runs ?? 1;

  const attention: Array<{
    key: string;
    tone: "warn" | "bad" | "ok";
    icon: NavName;
    title: string;
    detail: string;
    action?: () => void;
  }> = [];

  if (o && o.pending_approvals > 0) {
    attention.push({
      key: "approvals",
      tone: "warn",
      icon: "clock",
      title: `${o.pending_approvals} approval${o.pending_approvals === 1 ? "" : "s"} waiting`,
      detail: "Held tool calls are blocked until reviewed.",
      action: () => onNavigate?.("approvals")
    });
  }
  if (failed > 0) {
    attention.push({
      key: "failed",
      tone: "bad",
      icon: "alert",
      title: `${failed} failed run${failed === 1 ? "" : "s"}`,
      detail: "Open the run list to review errors.",
      action: () => onNavigate?.("runs")
    });
  }
  if (o && o.denied_spans > 0) {
    attention.push({
      key: "denied",
      tone: "warn",
      icon: "shield",
      title: `${o.denied_spans} denied span${o.denied_spans === 1 ? "" : "s"}`,
      detail: "Policy or budget blocked a tool call.",
      action: () => onNavigate?.("policy")
    });
  }
  if (attention.length === 0 && o) {
    attention.push({
      key: "clear",
      tone: "ok",
      icon: "check",
      title: "No urgent items",
      detail: "Approvals and policy are clear in this view."
    });
  }

  const body = overview.error ? (
    <Alert>Could not load the workspace overview: {errorMessage(overview.error)}</Alert>
  ) : !o ? (
    <TableSkeleton rows={4} />
  ) : (
    <>
      {attention.length > 0 && (
        <div className="mb-4 grid gap-1.5 rounded-xl border border-ink-200 bg-surface p-1.5 shadow-[0_1px_2px_rgba(20,22,18,0.04)] md:grid-cols-3">
          {attention.map((item) => {
            const toneClasses =
              item.tone === "bad"
                ? "bg-bad-100 text-bad-700"
                : item.tone === "warn"
                  ? "bg-warn-100 text-warn-700"
                  : "bg-ok-100 text-ok-700";
            return (
              <button
                key={item.key}
                type="button"
                onClick={item.action}
                disabled={!item.action}
                className="group flex items-center gap-3 rounded-lg border border-transparent bg-surface-2 px-3.5 py-2.5 text-left transition-colors hover:border-ink-200 hover:bg-surface disabled:cursor-default disabled:hover:border-transparent disabled:hover:bg-surface-2"
              >
                <span className={`grid h-8 w-8 shrink-0 place-items-center rounded-lg ${toneClasses}`}>
                  <NavIcon name={item.icon} className="h-4 w-4" />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-[12.5px] font-semibold text-ink-800">{item.title}</span>
                  <span className="mt-0.5 block truncate text-[10.5px] text-ink-500">{item.detail}</span>
                </span>
                {item.action && (
                  <NavIcon
                    name="chevronRight"
                    className="h-4 w-4 shrink-0 text-ink-300 transition-colors group-hover:text-ink-500"
                  />
                )}
              </button>
            );
          })}
        </div>
      )}

      <div className="mb-3.5 grid grid-cols-2 gap-2.5 sm:gap-3 xl:grid-cols-4">
        <Stat
          label="Total runs"
          value={total.toLocaleString()}
          hint={`${success.toLocaleString()} succeeded · ${running.toLocaleString()} running`}
        >
          {activity.length > 1 ? (
            <Sparkline values={activity} width={140} height={32} className="h-8 w-full" />
          ) : (
            <span className="text-[10.5px] text-ink-400">No hourly trend yet</span>
          )}
        </Stat>
        <Stat
          label="Success rate"
          value={successRate === null ? "—" : `${successRate.toFixed(1)}%`}
          hint={`${failed.toLocaleString()} failed · ${total.toLocaleString()} total`}
        >
          {successSeries.length > 1 ? (
            <Sparkline
              values={successSeries}
              width={140}
              height={32}
              className="h-8 w-full"
              color="var(--color-ok-700)"
            />
          ) : (
            <span className="text-[10.5px] text-ink-400">No hourly trend yet</span>
          )}
        </Stat>
        <Stat
          label="Estimated spend"
          value={formatSpend(o.cost.estimated_cost_micro)}
          hint={o.cost.cost_partial ? `${o.cost.missing_pricing_spans} span(s) missing pricing` : "Fully priced in this view"}
          tone={o.cost.cost_partial ? "warn" : "default"}
        >
          <span
            className={`inline-flex w-fit items-center rounded-md px-1.5 py-0.5 text-[10px] font-medium ${
              o.cost.cost_partial ? "bg-warn-100 text-warn-700" : "bg-ok-100 text-ok-700"
            }`}
          >
            {o.cost.cost_partial ? "Partial estimate" : "Complete estimate"}
          </span>
        </Stat>
        <Stat
          label="p95 latency"
          value={ms(o.latency_ms.p95)}
          hint={`median ${ms(o.latency_ms.median)}`}
        >
          {latencySeries.length > 1 ? (
            <Sparkline
              values={latencySeries}
              width={140}
              height={32}
              className="h-8 w-full"
              color="var(--color-info-700)"
            />
          ) : (
            <span className="text-[10.5px] text-ink-400">No hourly trend yet</span>
          )}
        </Stat>
      </div>

      <div className="mb-3.5 grid gap-3.5 xl:grid-cols-[minmax(0,1.7fr)_minmax(300px,1fr)]">
        <Card className="flex flex-col">
          <div className="flex items-start justify-between gap-3 p-4 pb-0">
            <div>
              <h2 className="text-[13px] font-semibold tracking-tight text-ink-900">Run activity</h2>
              <p className="mt-0.5 text-[11.5px] text-ink-500">
                Hourly volume across the newest {runs.length.toLocaleString()} runs
              </p>
            </div>
            <span className="rounded-md border border-ink-200 bg-surface-2 px-2 py-1 text-[10px] font-medium text-ink-500">
              Last {activitySpanHours(hourly)} h
            </span>
          </div>
          <div className="flex flex-1 flex-col px-4 pb-3 pt-3">
            {hourly.length > 1 ? (
              <ActivityChart buckets={hourly} />
            ) : (
              <div className="flex min-h-[220px] flex-1 items-center justify-center rounded-lg border border-dashed border-ink-200 bg-surface-2 text-xs text-ink-400">
                Not enough completed runs to draw a trend yet.
              </div>
            )}
          </div>
          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-ink-200 px-4 py-2.5 text-[10.5px] text-ink-500">
            <span>
              Peak <span className="font-semibold text-ink-700">{activity.length > 0 ? Math.max(...activity) : 0}</span> runs in an hour
            </span>
            <span>Refreshes every 15 s</span>
          </div>
        </Card>

        <div className="flex flex-col gap-3.5">
          <Card>
            <div className="p-4 pb-0">
              <h2 className="text-[13px] font-semibold tracking-tight text-ink-900">Run outcomes</h2>
              <p className="mt-0.5 text-[11.5px] text-ink-500">Status mix for {total.toLocaleString()} runs</p>
            </div>
            {statusSlices.length > 0 ? (
              <div className="flex items-center gap-5 p-4">
                <Donut slices={statusSlices} size={132} thickness={12}>
                  <div className="text-center">
                    <div className="tg-nums text-[22px] font-semibold leading-none tracking-[-0.04em] text-ink-900">
                      {total.toLocaleString()}
                    </div>
                    <div className="mt-1 text-[9px] uppercase tracking-[0.08em] text-ink-500">runs</div>
                  </div>
                </Donut>
                <div className="min-w-0 flex-1">
                  <Legend slices={statusSlices} />
                </div>
              </div>
            ) : (
              <div className="p-4 text-xs text-ink-500">No run outcomes in this view.</div>
            )}
          </Card>

          <Card>
            <div className="flex items-start justify-between gap-3 p-4 pb-0">
              <div>
                <h2 className="text-[13px] font-semibold tracking-tight text-ink-900">Top agents</h2>
                <p className="mt-0.5 text-[11.5px] text-ink-500">By run volume in this window</p>
              </div>
            </div>
            <div className="space-y-3 p-4">
              {topAgents.length > 0 ? (
                topAgents.map((agent) => (
                  <div key={agent.name}>
                    <div className="mb-1 flex items-baseline justify-between gap-3">
                      <span className="truncate text-[11.5px] font-semibold text-ink-700">{agent.name}</span>
                      <span className="shrink-0 text-[10px] text-ink-500">
                        {agent.runs.toLocaleString()} runs · {agent.success}%
                      </span>
                    </div>
                    <div className="h-[5px] overflow-hidden rounded-full bg-ink-100">
                      <div
                        className="h-full rounded-full bg-brand-500"
                        style={{ width: `${Math.max(4, (agent.runs / maxAgentRuns) * 100)}%` }}
                      />
                    </div>
                  </div>
                ))
              ) : (
                <div className="py-3 text-center text-xs text-ink-400">Agent activity will appear here.</div>
              )}
            </div>
          </Card>
        </div>
      </div>

      <div className="grid items-start gap-3.5 xl:grid-cols-[minmax(0,1.6fr)_minmax(300px,1fr)]">
        <Card className="overflow-hidden">
          <div className="flex items-start justify-between gap-3 p-4">
            <div>
              <h2 className="text-[13px] font-semibold tracking-tight text-ink-900">Recent runs</h2>
              <p className="mt-0.5 text-[11.5px] text-ink-500">Newest executions across all agents</p>
            </div>
            <Button size="sm" onClick={() => onNavigate?.("runs")}>
              View all runs
              <NavIcon name="chevronRight" className="h-3 w-3" />
            </Button>
          </div>
          {runs.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[600px] border-collapse text-[12.5px]">
                <thead>
                  <tr>
                    {["Run", "Agent", "Status", "Started", "Duration"].map((label) => (
                      <th
                        key={label}
                        className={`border-b border-ink-200 bg-surface-2 px-3 py-2 text-[10.5px] font-semibold uppercase tracking-[0.07em] text-ink-500 ${
                          label === "Duration" ? "text-right" : "text-left"
                        }`}
                      >
                        {label}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {runs.slice(0, 6).map((run) => (
                    <tr
                      key={run.id}
                      className="cursor-pointer transition-colors hover:bg-ink-50/70"
                      onClick={() => onOpenRun?.(run.id)}
                    >
                      <td className="border-b border-ink-100 px-3 py-2.5">
                        <LinkButton onClick={() => onOpenRun?.(run.id)}>
                          {run.id.slice(0, 8)}
                        </LinkButton>
                      </td>
                      <td className="border-b border-ink-100 px-3 py-2.5 text-ink-700">{run.agent_name}</td>
                      <td className="border-b border-ink-100 px-3 py-2.5">
                        <StatusBadge status={run.status} />
                      </td>
                      <td className="border-b border-ink-100 px-3 py-2.5 text-ink-500">
                        <span title={new Date(run.started_at).toLocaleString()}>{relTime(run.started_at)}</span>
                      </td>
                      <td className="border-b border-ink-100 px-3 py-2.5 text-right text-ink-500">{runDuration(run)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="px-4 pb-4">
              <Empty hint="Runs will appear here as agents execute." />
            </div>
          )}
        </Card>

        <Card className="flex flex-col">
          <div className="flex items-start justify-between gap-3 p-4 pb-0">
            <div>
              <h2 className="text-[13px] font-semibold tracking-tight text-ink-900">
                Pending approvals <span className="ml-1 text-[11px] font-medium text-ink-400">{o.pending_approvals}</span>
              </h2>
              <p className="mt-0.5 text-[11.5px] text-ink-500">Nothing executes until a human decides</p>
            </div>
            <Button size="sm" onClick={() => onNavigate?.("approvals")}>
              Open queue
            </Button>
          </div>

          <div className="mt-3 flex-1 border-t border-ink-200">
            {approvals.isError ? (
              <div className="p-4 text-[11.5px] text-ink-500">
                Approval queue unavailable.{" "}
                <button
                  type="button"
                  className="font-medium text-brand-600 hover:underline"
                  onClick={() => approvals.refetch()}
                >
                  Retry
                </button>
              </div>
            ) : pending.length > 0 ? (
              pending.slice(0, 2).map((approval: Approval) => (
                <button
                  key={approval.id}
                  type="button"
                  onClick={() => onOpenApproval?.(approval.id)}
                  className="flex w-full items-center gap-3 border-b border-ink-100 px-4 py-3 text-left transition-colors last:border-0 hover:bg-ink-50/70"
                >
                  <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-brand-50 text-brand-600">
                    <NavIcon name="tool" className="h-4 w-4" />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[12px] font-semibold text-ink-800">
                      <span className="font-mono">{approval.tool_name}</span>{" "}
                      <span className="font-normal text-ink-500">from {approval.caller}</span>
                    </span>
                    <span className="mt-0.5 block text-[10px] text-ink-500">{expiresLabel(approval.expires_at)}</span>
                  </span>
                  <span className="shrink-0 text-[10px] font-semibold text-brand-600">Review</span>
                </button>
              ))
            ) : (
              <div className="flex items-center gap-3 p-4">
                <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-ok-100 text-ok-700">
                  <NavIcon name="check" className="h-4 w-4" />
                </span>
                <div>
                  <div className="text-[12px] font-semibold text-ink-800">No pending approvals</div>
                  <div className="mt-0.5 text-[10.5px] text-ink-500">New holds will appear here.</div>
                </div>
              </div>
            )}
          </div>

          {o.pending_approvals > 0 && (
            <div className="border-t border-ink-200 px-4 py-2.5 text-[10.5px] text-ink-500">
              Held calls expire after 15 minutes.
            </div>
          )}
        </Card>
      </div>

      <p className="mt-4 text-[11px] text-ink-400">
        Estimates resolve against the pricing version in force when each span ran. Unpriced usage is flagged, never billed
        as zero. Refreshes every 15 s.
      </p>
    </>
  );

  return (
    <Page
      title="Overview"
      sub="Runs, usage, spend, and policy posture across this workspace."
      actions={
        <Button
          onClick={() => {
            overview.refetch();
            recent.refetch();
            approvals.refetch();
          }}
        >
          <NavIcon name="refresh" className="h-3.5 w-3.5" />
          Refresh
        </Button>
      }
    >
      {body}
    </Page>
  );
}

export const OverviewView = Overview;
export default Overview;
