import { useEffect, useState } from "react";
import {
  compareEvalRuns,
  formatMicro,
  getEvalRun,
  listSuites,
  type EvalResult,
  type EvalSuite
} from "./api";
import {
  Alert, Badge, Button, Card, Empty, Input, LinkButton,
  Page, Stat, Table, Td, Th
} from "./components";

function ResultRow({ r, onOpenRun }: { r: EvalResult; onOpenRun: (id: string) => void }) {
  return (
    <tr className="transition-colors hover:bg-ink-50/70">
      <Td>{r.case_name}</Td>
      <Td>t{r.trial}</Td>
      <Td>
        <Badge tone={r.passed ? "ok" : "bad"}>{r.passed ? "pass" : "fail"}</Badge>
      </Td>
      <Td className="whitespace-nowrap">{r.latency_ms}ms</Td>
      <Td className="whitespace-nowrap">{r.cost_micro == null ? "n/a" : formatMicro(Number(r.cost_micro))}</Td>
      <Td className="max-w-xs text-ink-500">
        {r.passed ? "" : (r.error_summary ?? "")}
        {!r.passed &&
          r.assertion_results
            .filter((a) => !a.passed)
            .map((a) => (
              <div key={a.type} className="font-mono text-xs">
                {a.type}: {a.message}
              </div>
            ))}
      </Td>
      <Td>
        {r.agent_run_id && (
          <LinkButton onClick={() => onOpenRun(r.agent_run_id!)}>trace</LinkButton>
        )}
      </Td>
    </tr>
  );
}

function EvalRunView({ runId, onOpenRun }: { runId: string; onOpenRun: (id: string) => void }) {
  const [run, setRun] = useState<{ agent_name: string; config_fingerprint: string; status: string } | null>(null);
  const [results, setResults] = useState<EvalResult[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    getEvalRun(runId)
      .then((t) => {
        setRun(t.eval_run);
        setResults(t.results);
      })
      .catch((e) => setError(e instanceof Error ? e.message : "load failed"));
  }, [runId]);
  if (error) return <Alert>{error}</Alert>;
  if (!run) return <p className="text-sm text-ink-500">Loading...</p>;
  const passed = results.filter((r) => r.passed).length;
  return (
    <Card className="mt-3 p-4">
      <div className="mb-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Passed" value={`${passed}/${results.length}`} />
        <Stat label="Agent" value={<span className="truncate text-base">{run.agent_name}</span>} />
        <Stat label="Config" value={<span className="truncate font-mono text-base">{run.config_fingerprint || "default"}</span>} />
        <Stat label="Status" value={<span className="text-base">{run.status}</span>} />
      </div>
      <Table>
        <thead>
          <tr>
            <Th>Case</Th>
            <Th>Trial</Th>
            <Th>Result</Th>
            <Th>Latency</Th>
            <Th>Cost</Th>
            <Th>Why</Th>
            <Th>Run</Th>
          </tr>
        </thead>
        <tbody>
          {results.map((r) => (
            <ResultRow key={r.id} r={r} onOpenRun={onOpenRun} />
          ))}
        </tbody>
      </Table>
    </Card>
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
    <Page
      title="Evaluation suites"
      sub="Versioned datasets replayed against agent configs, with pass rate, latency, and cost."
    >
      {suites.length === 0 ? (
        <Empty hint="No suites yet. Create one through the API to start comparing configs." />
      ) : (
        <Card className="divide-y divide-ink-100">
          {suites.map((s) => (
            <div key={s.id} className="flex flex-wrap items-center gap-2 px-4 py-2.5 text-sm">
              <span className="font-medium text-ink-900">{s.name}</span>
              <Badge tone="mute">v{s.version}</Badge>
              {s.locked && <Badge tone="info">locked</Badge>}
              <span className="text-ink-500">{s.case_count} cases · {s.run_count} runs</span>
              <span className="ml-auto font-mono text-xs text-ink-300">{s.id.slice(0, 8)}</span>
            </div>
          ))}
        </Card>
      )}
      <div className="mt-6">
        <h3 className="mb-2 text-sm font-semibold text-ink-700">Open an evaluation run</h3>
        <form
          className="flex flex-wrap gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            const input = (e.currentTarget.elements.namedItem("runId") as HTMLInputElement).value.trim();
            if (input) setOpenRun(input);
          }}
        >
          <Input name="runId" placeholder="evaluation run id" className="w-72 font-mono" />
          <Button variant="primary" type="submit">Open</Button>
        </form>
        {openRun && <EvalRunView runId={openRun} onOpenRun={onOpenRun} />}
      </div>
      <div className="mt-6">
        <h3 className="mb-2 text-sm font-semibold text-ink-700">Compare two runs</h3>
        <form
          className="flex flex-wrap gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            const ids = compareIds.split(",").map((s) => s.trim()).filter(Boolean);
            if (ids.length >= 2) compareEvalRuns(ids).then((c) => setCompare(c.runs));
          }}
        >
          <Input
            value={compareIds}
            onChange={(e) => setCompareIds(e.target.value)}
            placeholder="run-id-1, run-id-2"
            className="w-96 font-mono"
          />
          <Button variant="primary" type="submit">Compare</Button>
        </form>
        {compare && (
          <div className="mt-3">
            <Table>
              <thead>
                <tr>
                  <Th>Config</Th>
                  <Th>Passed</Th>
                  <Th>Rate</Th>
                  <Th>Latency mean</Th>
                  <Th>Cost</Th>
                  <Th>Tokens</Th>
                  <Th>Violations</Th>
                </tr>
              </thead>
              <tbody>
                {compare.map((r) => (
                  <tr key={String(r.eval_run_id)} className="transition-colors hover:bg-ink-50/70">
                    <Td className="font-mono text-[13px]">{String(r.config_fingerprint || "default")}</Td>
                    <Td>{String(r.passed)}/{String((r as { cases: number }).cases)}</Td>
                    <Td>{r.pass_rate == null ? "n/a" : `${Math.round(Number(r.pass_rate) * 100)}%`}</Td>
                    <Td>{r.latency_ms ? `${(r.latency_ms as { mean: number }).mean}ms` : "n/a"}</Td>
                    <Td>{r.cost_micro == null ? "n/a" : formatMicro(Number(r.cost_micro))}</Td>
                    <Td>{r.input_tokens == null && r.output_tokens == null ? "n/a" : `${r.input_tokens ?? "?"}/${r.output_tokens ?? "?"}`}</Td>
                    <Td>{String(r.violations)}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        )}
      </div>
    </Page>
  );
}
