import { useState } from "react";
import { formatMicro, opsApi, type CompareRow } from "./api";
import {
  Alert, Badge, Button, Card, Empty, Field, Input,
  Page, Table, Td, Th
} from "./components";

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
function SpendByModel({ rows }: { rows: CompareRow[] }) {
  const total = rows.reduce((sum, r) => sum + r.estimated_micro, 0);
  if (total <= 0) return null;
  const top = [...rows].sort((a, b) => b.estimated_micro - a.estimated_micro).slice(0, 8);
  const max = top[0].estimated_micro;
  return (
    <Card className="mb-5 p-4">
      <h3 className="text-sm font-semibold text-ink-900">Estimated spend by model</h3>
      <p className="mb-3 text-xs text-ink-500">
        Share of this window's estimate; bar width is relative to the largest model.
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

export default function CostsView() {
  const [provider, setProvider] = useState("");
  const [days, setDays] = useState("30");
  const [rows, setRows] = useState<CompareRow[] | null>(null);
  const [error, setError] = useState("");

  const load = () => {
    setError("");
    const end = new Date();
    const start = new Date(end.getTime() - Number(days || 30) * 86400000);
    opsApi
      .compareCosts(start.toISOString(), end.toISOString(), provider || undefined)
      .then((r) => setRows(r.rows))
      .catch((e) => setError(e instanceof Error ? e.message : "load failed"));
  };

  return (
    <Page
      title="Costs: estimated vs billed"
      sub="Indigo is our estimate, green is the provider invoice. Import actuals to compare."
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
          <Button variant="primary" type="submit">Compare</Button>
        </form>
      </Card>
      {rows === null ? (
        <Empty hint="Pick a window and compare." action={<Button variant="primary" onClick={load}>Compare</Button>} />
      ) : rows.length === 0 ? (
        <Empty hint="No usage in this window. Import actuals to compare against estimates." />
      ) : (
        <>
          <SpendByModel rows={rows} />
          <Table>
            <thead>
              <tr>
                <Th>Model</Th>
                <Th>Tokens in/out</Th>
                <Th>Split</Th>
                <Th>Estimated</Th>
                <Th>Billed</Th>
                <Th>Variance</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={`${r.provider}/${r.model}`} className="transition-colors hover:bg-ink-50/70">
                  <Td className="font-mono text-[13px]">
                    {r.provider}/{r.model}
                    {r.missing_pricing && <Badge tone="warn">partial</Badge>}
                  </Td>
                  <Td className="whitespace-nowrap">{r.input_tokens}/{r.output_tokens}</Td>
                  <Td><CostBars estimated={r.estimated_micro} actual={r.actual_micro} /></Td>
                  <Td className="whitespace-nowrap">{formatMicro(r.estimated_micro)}</Td>
                  <Td className="whitespace-nowrap">
                    {r.actual_micro === null ? <span className="text-ink-500">no actuals</span> : formatMicro(r.actual_micro)}
                  </Td>
                  <Td className="whitespace-nowrap">
                    {r.variance_micro === null
                      ? <span className="text-ink-500">n/a</span>
                      : `${formatMicro(r.variance_micro)} (${fmtPct(r.variance_pct)})`}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </>
      )}
    </Page>
  );
}
