import { useEffect, useState } from "react";
import {
  compareEvalRuns,
  formatMicro,
  getEvalRun,
  listSuites,
  type EvalResult,
  type EvalSuite
} from "./api";

function ResultRow({ r, onOpenRun }: { r: EvalResult; onOpenRun: (id: string) => void }) {
  return (
    <tr className="border-b">
      <td className="py-1 pr-2">{r.case_name}</td>
      <td className="py-1 pr-2">t{r.trial}</td>
      <td className="py-1 pr-2">
        <span
          className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${
            r.passed ? "bg-green-100 text-green-800" : "bg-red-100 text-red-800"
          }`}
        >
          {r.passed ? "pass" : "fail"}
        </span>
      </td>
      <td className="py-1 pr-2">{r.latency_ms}ms</td>
      <td className="py-1 pr-2">{formatMicro(Number(r.cost_micro))}</td>
      <td className="py-1 pr-2 text-gray-600">
        {r.passed ? "" : (r.error_summary ?? "")}
        {!r.passed &&
          r.assertion_results
            .filter((a) => !a.passed)
            .map((a) => (
              <div key={a.type} className="text-xs">
                {a.type}: {a.message}
              </div>
            ))}
      </td>
      <td className="py-1 pr-2">
        {r.agent_run_id && (
          <button className="text-blue-700 underline" onClick={() => onOpenRun(r.agent_run_id!)}>
            trace
          </button>
        )}
      </td>
    </tr>
  );
}

function EvalRunView({ runId, onOpenRun }: { runId: string; onOpenRun: (id: string) => void }) {
  const [run, setRun] = useState<{ agent_name: string; config_fingerprint: string; status: string } | null>(null);
  const [results, setResults] = useState<EvalResult[]>([]);
  useEffect(() => {
    getEvalRun(runId).then((t) => {
      setRun(t.eval_run);
      setResults(t.results);
    });
  }, [runId]);
  if (!run) return <p className="text-sm text-gray-500">Loading...</p>;
  const passed = results.filter((r) => r.passed).length;
  return (
    <div className="mt-3 rounded border p-3">
      <div className="mb-2 flex flex-wrap gap-3 text-sm">
        <span className="font-mono">{runId.slice(0, 8)}</span>
        <span className="text-gray-600">{run.agent_name} / {run.config_fingerprint || "default"}</span>
        <span className="font-medium">
          {passed}/{results.length} passed
        </span>
      </div>
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b text-left text-gray-500">
            <th className="py-1 pr-2">Case</th>
            <th className="py-1 pr-2">Trial</th>
            <th className="py-1 pr-2">Result</th>
            <th className="py-1 pr-2">Latency</th>
            <th className="py-1 pr-2">Cost</th>
            <th className="py-1 pr-2">Why</th>
            <th className="py-1 pr-2">Run</th>
          </tr>
        </thead>
        <tbody>
          {results.map((r) => (
            <ResultRow key={r.id} r={r} onOpenRun={onOpenRun} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function EvalsView({ onOpenRun }: { onOpenRun: (id: string) => void }) {
  const [suites, setSuites] = useState<EvalSuite[]>([]);
  const [openRun, setOpenRun] = useState("");
  const [compareIds, setCompareIds] = useState("");
  const [compare, setCompare] = useState<Record<string, unknown>[] | null>(null);

  useEffect(() => {
    listSuites().then((s) => setSuites(s.items));
  }, []);

  return (
    <div className="p-4">
      <h2 className="mb-3 text-lg font-semibold">Evaluation suites</h2>
      {suites.length === 0 && <p className="text-sm text-gray-500">No suites yet.</p>}
      {suites.map((s) => (
        <div key={s.id} className="mb-2 rounded border px-3 py-2 text-sm">
          <span className="font-medium">{s.name}</span>
          <span className="ml-2 text-gray-500">v{s.version}</span>
          <span className="ml-2 text-gray-500">
            {s.case_count} cases, {s.run_count} runs{s.locked ? ", locked" : ""}
          </span>
          <span className="ml-2 font-mono text-gray-400">{s.id.slice(0, 8)}</span>
        </div>
      ))}
      <div className="mt-4">
        <h3 className="mb-2 font-semibold">Open an evaluation run</h3>
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            const input = (e.currentTarget.elements.namedItem("runId") as HTMLInputElement).value.trim();
            if (input) setOpenRun(input);
          }}
        >
          <input
            name="runId"
            placeholder="evaluation run id"
            className="w-72 rounded border px-2 py-1 font-mono text-sm"
          />
          <button className="rounded bg-gray-800 px-3 py-1 text-sm text-white" type="submit">
            Open
          </button>
        </form>
        {openRun && <EvalRunView runId={openRun} onOpenRun={onOpenRun} />}
      </div>
      <div className="mt-4">
        <h3 className="mb-2 font-semibold">Compare two runs</h3>
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            const ids = compareIds.split(",").map((s) => s.trim()).filter(Boolean);
            if (ids.length >= 2) compareEvalRuns(ids).then((c) => setCompare(c.runs));
          }}
        >
          <input
            value={compareIds}
            onChange={(e) => setCompareIds(e.target.value)}
            placeholder="run-id-1, run-id-2"
            className="w-96 rounded border px-2 py-1 font-mono text-sm"
          />
          <button className="rounded bg-gray-800 px-3 py-1 text-sm text-white" type="submit">
            Compare
          </button>
        </form>
        {compare && (
          <table className="mt-2 w-full border-collapse text-sm">
            <thead>
              <tr className="border-b text-left text-gray-500">
                <th className="py-1 pr-2">Config</th>
                <th className="py-1 pr-2">Passed</th>
                <th className="py-1 pr-2">Rate</th>
                <th className="py-1 pr-2">Latency mean</th>
                <th className="py-1 pr-2">Cost</th>
                <th className="py-1 pr-2">Violations</th>
              </tr>
            </thead>
            <tbody>
              {compare.map((r) => (
                <tr key={String(r.eval_run_id)} className="border-b">
                  <td className="py-1 pr-2 font-mono">{String(r.config_fingerprint || "default")}</td>
                  <td className="py-1 pr-2">
                    {String(r.passed)}/{String((r as { cases: number }).cases)}
                  </td>
                  <td className="py-1 pr-2">{r.pass_rate == null ? "n/a" : `${Math.round(Number(r.pass_rate) * 100)}%`}</td>
                  <td className="py-1 pr-2">{r.latency_ms ? `${(r.latency_ms as { mean: number }).mean}ms` : "n/a"}</td>
                  <td className="py-1 pr-2">{formatMicro(Number(r.cost_micro))}</td>
                  <td className="py-1 pr-2">{String(r.violations)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
