import { useState } from "react";
import { formatMicro, opsApi, type CompareRow } from "./api";

function fmtPct(v: number | null): string {
  if (v === null) return "n/a";
  return `${(v * 100).toFixed(1)}%`;
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
    <div className="p-4">
      <h2 className="mb-3 text-lg font-semibold">Costs: estimated vs billed</h2>
      {error && <p className="mb-2 text-sm text-red-700">{error}</p>}
      <form
        className="mb-3 flex items-end gap-2 text-sm"
        onSubmit={(e) => {
          e.preventDefault();
          load();
        }}
      >
        <label className="flex flex-col">
          <span className="text-xs text-gray-500">Provider (blank = all)</span>
          <input
            className="w-44 rounded border px-2 py-1"
            value={provider}
            onChange={(e) => setProvider(e.target.value)}
          />
        </label>
        <label className="flex flex-col">
          <span className="text-xs text-gray-500">Past days</span>
          <input
            className="w-24 rounded border px-2 py-1"
            value={days}
            onChange={(e) => setDays(e.target.value)}
          />
        </label>
        <button className="rounded bg-gray-800 px-3 py-1 text-white" type="submit">
          Compare
        </button>
      </form>
      {rows && rows.length === 0 && (
        <p className="text-sm text-gray-500">No usage in this window. Import actuals to compare against estimates.</p>
      )}
      {rows && rows.length > 0 && (
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b text-left text-gray-500">
              <th className="py-1 pr-2">Model</th>
              <th className="py-1 pr-2">Tokens in/out</th>
              <th className="py-1 pr-2">Estimated</th>
              <th className="py-1 pr-2">Billed</th>
              <th className="py-1 pr-2">Variance</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={`${r.provider}/${r.model}`} className="border-b">
                <td className="py-1 pr-2 font-mono">
                  {r.provider}/{r.model}
                  {r.missing_pricing && <span className="ml-1 text-amber-600">(partial)</span>}
                </td>
                <td className="py-1 pr-2">
                  {r.input_tokens}/{r.output_tokens}
                </td>
                <td className="py-1 pr-2">{formatMicro(r.estimated_micro)}</td>
                <td className="py-1 pr-2">
                  {r.actual_micro === null ? "no actuals" : formatMicro(r.actual_micro)}
                </td>
                <td className="py-1 pr-2">
                  {r.variance_micro === null
                    ? "n/a"
                    : `${formatMicro(r.variance_micro)} (${fmtPct(r.variance_pct)})`}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
