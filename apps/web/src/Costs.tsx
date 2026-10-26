import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { budgetRemainingHint, formatMicro, listBudgets, opsApi, type CompareRow } from "./api";
import {
  Alert, Badge, Button, Card, Empty, Field, Input, Select,
  Page, Table, Td, Th
} from "./components";
import { ChartCard, Donut, Legend, Meter, type Slice } from "./charts";

function fmtPct(v: number | null): string {
  if (v === null) return "n/a";
  return `${(v * 100).toFixed(1)}%`;
}

// Estimated versus billed as paired bars, no chart dependency. Widths scale
// to the larger of the two so over- and under-estimates read instantly.
function CostBars({ estimated, actual }: { estimated: number; actual: number | null }) {
  const max = Math.max(estimated, actual ?? 0, 1);
  return (
    <div className="flex min-w-40 flex-col gap-1">
      <div className="tg-track h-1.5 w-full">
        <div className="tg-bar h-1.5 bg-brand-500/80" style={{ width: `${(estimated / max) * 100}%` }} />
      </div>
      {actual !== null && (
        <div className="tg-track h-1.5 w-full">
          <div className="tg-bar h-1.5 bg-ok-700/70" style={{ width: `${(actual / max) * 100}%` }} />
        </div>
      )}
    </div>
  );
}

// Share-of-window bar list for the same rows the table shows: the "where did
// the money go" answer at a glance, above the per-model detail.
function SpendByModel({ rows, dimension }: { rows: CompareRow[]; dimension: string }) {
  const total = rows.reduce((sum, r) => sum + r.estimated_micro, 0);
  if (total <= 0) return null;
  const top = [...rows].sort((a, b) => b.estimated_micro - a.estimated_micro).slice(0, 8);
  const max = top[0].estimated_micro;
  return (
    <Card className="mb-5 p-4">
      <h3 className="text-sm font-semibold text-ink-900">Estimated spend by {dimension}</h3>
      <p className="mb-3 text-xs text-ink-500">
        Share of this window's estimate; bar width is relative to the largest {dimension}.
      </p>
      <ul className="space-y-2">
        {top.map((r) => (
          <li key={`${r.provider}/${r.model}`} className="grid grid-cols-[minmax(0,12rem)_1fr_auto] items-center gap-3 text-xs">
            <span className="truncate font-mono text-ink-800" title={`${r.provider}/${r.model}`}>
              {r.provider}/{r.model}
            </span>
            <span className="tg-track block h-2">
              <span className="tg-bar block h-2 bg-brand-500/80" style={{ width: `${(r.estimated_micro / max) * 100}%` }} />
            </span>
            <span className="tg-nums whitespace-nowrap text-ink-500">
              {formatMicro(r.estimated_micro)} · {Math.round((r.estimated_micro / total) * 100)}%
            </span>
          </li>
        ))}
      </ul>
    </Card>
  );
}

// Budget health belongs next to spend: spent plus reserved against each
// limit, with the traffic-light colors the gateway's block effect deserves.
function BudgetUtilization() {
  const q = useQuery({ queryKey: ["budgets"], queryFn: listBudgets, refetchInterval: 30_000 });
  const items = q.data?.items ?? [];
  if (items.length === 0) return null;
  return (
    <ChartCard
      title="Budget utilization"
      sub="Spent plus reserved against each limit; block budgets stop calls at 100%."
      className="mb-5"
    >
      <div className="flex flex-col gap-3">
        {items.map((b) => {
          const used = Number(b.spent_micro) + Number(b.reserved_micro);
          const pct = b.limit_micro > 0 ? used / b.limit_micro : 0;
          const color = pct >= 1 ? "var(--color-bad-700)" : pct >= 0.8 ? "var(--color-warn-700)" : "var(--color-ok-700)";
          return (
            <Meter
              key={b.id}
              label={`${b.scope} · ${b.ref_id.slice(0, 8)} · ${b.effect}`}
              value={used}
              max={Math.max(b.limit_micro, 1)}
              color={color}
              valueText={`${formatMicro(used)} / ${formatMicro(b.limit_micro)}`}
              hint={budgetRemainingHint(b, "remaining unknown: unpriced usage")}
            />
          );
        })}
      </div>
    </ChartCard>
  );
}

export default function CostsView() {
  const [provider, setProvider] = useState("");
  const [days, setDays] = useState("30");
  // Section 12.1 names agent, project, and reporting period alongside model.
  const [groupBy, setGroupBy] = useState("model");
  const [rows, setRows] = useState<CompareRow[] | null>(null);
  const [error, setError] = useState("");

  const load = () => {
    setError("");
    // Number("") is 0 and Number("x") is NaN, and an Invalid Date throws on
    // toISOString: the Compare button used to do nothing at all.
    const span = Number(days);
    if (!Number.isFinite(span) || span <= 0) {
      setError("days must be a positive number");
      return;
    }
    const end = new Date();
    const start = new Date(end.getTime() - span * 86400000);
    opsApi
      .compareCosts(start.toISOString(), end.toISOString(), provider || undefined, groupBy)
      .then((r) => setRows(r.rows))
      .catch((e) => setError(e instanceof Error ? e.message : "load failed"));
  };

  const estTotal = rows?.reduce((sum, r) => sum + r.estimated_micro, 0) ?? 0;
  const actTotal = rows?.reduce((sum, r) => sum + (r.actual_micro ?? 0), 0) ?? 0;
  const splitSlices: Slice[] = [
    { label: "Estimated", value: estTotal, color: "var(--color-brand-500)" },
    { label: "Billed", value: actTotal, color: "var(--color-ok-700)" }
  ].filter((s) => s.value > 0);

  return (
    <Page
      title="Costs: estimated vs billed"
      sub="Indigo is our estimate, green is the provider invoice. Import actuals to compare. Estimates are best-effort from reported tokens and configured prices; unknown usage never counts as zero."
    >
      {error && <Alert>{error}</Alert>}
      <Card className="mb-5 max-w-2xl p-4">
        <form
          className="flex flex-wrap items-end gap-3 text-sm"
          onSubmit={(e) => {
            e.preventDefault();
            load();
          }}
        >
          <Field label="Provider (blank = all)">
            <Input className="w-44" value={provider} onChange={(e) => setProvider(e.target.value)} />
          </Field>
          <Field label="Past days">
            <Input className="w-24" value={days} onChange={(e) => setDays(e.target.value)} />
          </Field>
          <Field label="Group by">
            <Select value={groupBy} onChange={(e) => setGroupBy(e.target.value)}>
              <option value="model">model</option>
              <option value="agent">agent</option>
              <option value="project">project</option>
              <option value="period">period (day)</option>
            </Select>
          </Field>
          <Button variant="primary" type="submit">Compare</Button>
        </form>
      </Card>
      <BudgetUtilization />
      {rows === null ? (
        <Empty hint="Pick a window and compare." action={<Button variant="primary" onClick={load}>Compare</Button>} />
      ) : rows.filter((r) => r.provider || r.model).length === 0 ? (
        <Empty hint="No usage in this window. Import actuals to compare against estimates." />
      ) : (
        <>
          {groupBy === "model" && estTotal + actTotal > 0 && (
            <ChartCard
              title="Estimate vs billed"
              sub="Indigo is our estimate, green is the provider invoice for this window."
              className="mb-5"
            >
              <div className="flex flex-wrap items-center gap-6">
                <Donut slices={splitSlices}>
                  <span className="tg-nums text-lg font-semibold tracking-tight text-ink-900">
                    {actTotal > 0 ? fmtPct((estTotal - actTotal) / actTotal) : "no actuals"}
                  </span>
                  <span className="text-[10px] uppercase tracking-wide text-ink-500">variance</span>
                </Donut>
                <div className="min-w-0 flex-1">
                  <Legend slices={splitSlices} />
                </div>
              </div>
            </ChartCard>
          )}
          <SpendByModel rows={rows.filter((r) => r.provider || r.model)} dimension={groupBy} />
          <Table>
            <thead>
              <tr>
                <Th>{groupBy}</Th>
                <Th>Tokens in/out</Th>
                <Th>Split</Th>
                <Th>Estimated</Th>
                {/* Actuals are recorded per provider and model, so no other
                    grouping can be compared against them. */}
                {groupBy === "model" && <Th>Billed</Th>}
                {groupBy === "model" && <Th>Variance</Th>}
              </tr>
            </thead>
            <tbody>
              {rows.filter((r) => r.provider || r.model).map((r) => (
                <tr key={`${r.provider}/${r.model}`} className="transition-colors hover:bg-ink-50/70">
                  <Td className="font-mono text-[13px]">
                    {groupBy === "model" ? `${r.provider}/${r.model}` : r.model}
                    {r.missing_pricing && <Badge tone="warn">partial</Badge>}
                  </Td>
                  <Td className="whitespace-nowrap">{r.input_tokens}/{r.output_tokens}</Td>
                  <Td><CostBars estimated={r.estimated_micro} actual={r.actual_micro} /></Td>
                  <Td className="whitespace-nowrap">{formatMicro(r.estimated_micro)}</Td>
                  {groupBy === "model" && (
                    <Td className="whitespace-nowrap">
                      {r.actual_micro === null ? <span className="text-ink-500">no actuals</span> : formatMicro(r.actual_micro)}
                    </Td>
                  )}
                  {groupBy === "model" && (
                    <Td className="whitespace-nowrap">
                      {r.variance_micro === null
                        ? <span className="text-ink-500">n/a</span>
                        : `${formatMicro(r.variance_micro)} (${fmtPct(r.variance_pct)})`}
                    </Td>
                  )}
                </tr>
              ))}
            </tbody>
          </Table>
        </>
      )}
    </Page>
  );
}
