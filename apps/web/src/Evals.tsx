import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  addCase,
  compareEvalRuns,
  createSuite,
  formatMicro,
  getEvalRun,
  listSuites,
  runSuite,
  type EvalResult,
  type EvalSuite
} from "./api";
import {
  Alert, Badge, Button, Card, Empty, Field, Input, LinkButton,
  Page, Select, Stat, Table, Td, Th
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
  const runQuery = useQuery({ queryKey: ["eval-run", runId], queryFn: () => getEvalRun(runId) });
  const error = runQuery.error instanceof Error ? runQuery.error.message : "";
  if (error) return <Alert>{error}</Alert>;
  if (!runQuery.data) return <p className="text-sm text-ink-500">Loading...</p>;
  const run = runQuery.data.eval_run;
  const results = runQuery.data.results;
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

function SuitePicker({
  suites, value, onChange
}: { suites: EvalSuite[]; value: string; onChange: (v: string) => void }) {
  return (
    <Field label="Suite">
      <Select value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">Pick a suite</option>
        {suites.map((s) => (
          <option key={s.id} value={s.id}>
            {s.name} v{s.version}
          </option>
        ))}
      </Select>
    </Field>
  );
}

function NewSuiteForm({ onDone, onError }: { onDone: () => void; onError: (m: string) => void }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <Card className="mb-5 p-4">
      <h3 className="text-sm font-semibold text-ink-900">New suite</h3>
      <p className="mb-3 text-xs text-ink-500">
        Suites are versioned datasets. Editing one after its first run creates a new version.
      </p>
      <form
        className="flex flex-wrap items-end gap-2 text-sm"
        onSubmit={(e) => {
          e.preventDefault();
          if (!name.trim()) return;
          setBusy(true);
          onError("");
          createSuite({ name: name.trim(), description: description.trim() || undefined })
            .then(() => {
              setName("");
              setDescription("");
              onDone();
            })
            .catch((err) => onError(err instanceof Error ? err.message : "create failed"))
            .finally(() => setBusy(false));
        }}
      >
        <Field label="Name">
          <Input className="w-48" value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Description">
          <Input className="w-72" value={description} onChange={(e) => setDescription(e.target.value)} />
        </Field>
        <Button variant="primary" type="submit" disabled={busy || !name.trim()}>
          {busy ? "Creating..." : "Create suite"}
        </Button>
      </form>
    </Card>
  );
}

function AddCaseForm({
  suites, onDone, onError
}: { suites: EvalSuite[]; onDone: () => void; onError: (m: string) => void }) {
  const [suiteId, setSuiteId] = useState("");
  const [name, setName] = useState("");
  const [assertions, setAssertions] = useState('[{"type": "contains", "value": "hello"}]');
  const [execConfig, setExecConfig] = useState('{"output": "hello world"}');
  const [expected, setExpected] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <div className="mt-6">
      <h3 className="mb-2 text-sm font-semibold text-ink-700">Add a case</h3>
      <Card className="p-4">
        <form
          className="flex flex-col gap-3 text-sm"
          onSubmit={(e) => {
            e.preventDefault();
            if (!suiteId || !name.trim()) return;
            let parsedAssertions: unknown;
            let parsedExec: unknown;
            try {
              parsedAssertions = JSON.parse(assertions);
            } catch {
              onError("assertions must be valid JSON");
              return;
            }
            try {
              parsedExec = JSON.parse(execConfig);
            } catch {
              onError("exec config must be valid JSON");
              return;
            }
            const body: Record<string, unknown> = {
              name: name.trim(),
              assertions: parsedAssertions,
              exec_config: parsedExec
            };
            if (expected.trim()) body.expected = expected.trim();
            setBusy(true);
            onError("");
            addCase(suiteId, body)
              .then(() => {
                setName("");
                onDone();
              })
              .catch((err) => onError(err instanceof Error ? err.message : "add case failed"))
              .finally(() => setBusy(false));
          }}
        >
          <div className="flex flex-wrap items-end gap-2">
            <SuitePicker suites={suites} value={suiteId} onChange={setSuiteId} />
            <Field label="Case name">
              <Input className="w-44" value={name} onChange={(e) => setName(e.target.value)} />
            </Field>
            <Field label="Expected (optional, used when exec config has no output)">
              <Input className="w-64" value={expected} onChange={(e) => setExpected(e.target.value)} />
            </Field>
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            <Field label="Assertions (JSON)">
              <textarea
                aria-label="Assertions JSON"
                className="h-24 w-full rounded-md border border-ink-200 bg-surface px-2.5 py-1.5 font-mono text-xs text-ink-800"
                value={assertions}
                onChange={(e) => setAssertions(e.target.value)}
              />
            </Field>
            <Field label="Execution config (JSON)">
              <textarea
                aria-label="Execution config JSON"
                className="h-24 w-full rounded-md border border-ink-200 bg-surface px-2.5 py-1.5 font-mono text-xs text-ink-800"
                value={execConfig}
                onChange={(e) => setExecConfig(e.target.value)}
              />
            </Field>
          </div>
          <div>
            <Button variant="primary" type="submit" disabled={busy || !suiteId || !name.trim()}>
              {busy ? "Adding..." : "Add case"}
            </Button>
          </div>
        </form>
      </Card>
    </div>
  );
}

function RunSuiteForm({
  suites, onStarted, onError
}: { suites: EvalSuite[]; onStarted: (evalRunId: string) => void; onError: (m: string) => void }) {
  const [suiteId, setSuiteId] = useState("");
  const [agentName, setAgentName] = useState("eval-agent");
  const [model, setModel] = useState("scripted-1");
  const [trials, setTrials] = useState("1");
  const [fingerprint, setFingerprint] = useState("");
  const [costCap, setCostCap] = useState("");
  // FR-021: the adapter decides whether a case replays its declared behavior or
  // runs against a live endpoint. The API is the authority on the URL being
  // required; this just avoids offering a run that cannot start.
  const [adapterType, setAdapterType] = useState("scripted");
  const [adapterUrl, setAdapterUrl] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <div className="mt-6">
      <h3 className="mb-2 text-sm font-semibold text-ink-700">Run a suite</h3>
      <Card className="p-4">
        <form
          className="flex flex-wrap items-end gap-2 text-sm"
          onSubmit={(e) => {
            e.preventDefault();
            if (!suiteId) return;
            setBusy(true);
            onError("");
            runSuite(suiteId, {
              agent_name: agentName.trim() || "eval-agent",
              model: model.trim() || "scripted-1",
              trials: Math.min(Math.max(Number(trials) || 1, 1), 5),
              config_fingerprint: fingerprint.trim() || undefined,
              cost_cap_micro: costCap.trim() ? Math.round(Number(costCap) * 1_000_000) : undefined,
              adapter: adapterType === "http"
                ? { type: "http", url: adapterUrl.trim() }
                : { type: "scripted" }
            })
              .then((r) => onStarted(r.eval_run.id))
              .catch((err) => onError(err instanceof Error ? err.message : "run failed"))
              .finally(() => setBusy(false));
          }}
        >
          <SuitePicker suites={suites} value={suiteId} onChange={setSuiteId} />
          <Field label="Agent name">
            <Input className="w-36" value={agentName} onChange={(e) => setAgentName(e.target.value)} />
          </Field>
          <Field label="Model">
            <Input className="w-32" value={model} onChange={(e) => setModel(e.target.value)} />
          </Field>
          <Field label="Fingerprint">
            <Input className="w-32" value={fingerprint} onChange={(e) => setFingerprint(e.target.value)} />
          </Field>
          <Field label="Trials">
            <Input className="w-16" value={trials} onChange={(e) => setTrials(e.target.value)} />
          </Field>
          <Field label="Cost cap ($)">
            <Input className="w-24" value={costCap} onChange={(e) => setCostCap(e.target.value)} />
          </Field>
          <Field label="Adapter">
            <Select value={adapterType} onChange={(e) => setAdapterType(e.target.value)}>
              <option value="scripted">scripted</option>
              <option value="http">http</option>
            </Select>
          </Field>
          {adapterType === "http" && (
            <Field label="Adapter URL">
              <Input className="w-64" value={adapterUrl}
                onChange={(e) => setAdapterUrl(e.target.value)}
                placeholder="https://agent.example.com/invoke" />
            </Field>
          )}
          <Button variant="primary" type="submit"
            disabled={busy || !suiteId || (adapterType === "http" && !adapterUrl.trim())}>
            {busy ? "Running..." : "Run suite"}
          </Button>
        </form>
      </Card>
    </div>
  );
}

export default function EvalsView({ onOpenRun }: { onOpenRun: (id: string) => void }) {
  const [openRun, setOpenRun] = useState("");
  const [compareIds, setCompareIds] = useState("");
  const [compare, setCompare] = useState<Record<string, unknown>[] | null>(null);
  const [compareError, setCompareError] = useState("");
  const [error, setError] = useState("");
  const queryClient = useQueryClient();
  const suitesQuery = useQuery({ queryKey: ["eval-suites"], queryFn: () => listSuites() });
  const suites = suitesQuery.data?.items ?? [];
  const reload = () => queryClient.invalidateQueries({ queryKey: ["eval-suites"] });

  return (
    <Page
      title="Evaluation suites"
      sub="Versioned datasets replayed against agent configs, with pass rate, latency, and cost."
    >
      {error && <Alert>{error}</Alert>}
      <NewSuiteForm onDone={reload} onError={setError} />
      {suites.length === 0 ? (
        <Empty hint="No suites yet. Create one above to start comparing configs." />
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
      <AddCaseForm suites={suites} onDone={reload} onError={setError} />
      <RunSuiteForm
        suites={suites}
        onStarted={(id) => {
          setOpenRun(id);
          reload();
        }}
        onError={setError}
      />
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
            if (ids.length >= 2) {
              // Without the catch a failed compare left the panel blank, which
              // reads the same as "no results".
              setCompareError("");
              compareEvalRuns(ids)
                .then((c) => setCompare(c.runs))
                .catch((e) => setCompareError(e instanceof Error ? e.message : "compare failed"));
            }
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
        {compareError && <div className="mt-2"><Alert>{compareError}</Alert></div>}
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
                    <Td>{r.violations == null ? "n/a" : String(r.violations)}</Td>
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
