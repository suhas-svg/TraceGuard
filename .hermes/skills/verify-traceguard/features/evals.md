# Evaluations

Evaluation suites hold versioned datasets replayed against agent configs. The screen lists
suites (name, version, lock state, case/run counts), opens a single evaluation run by id
(stats + per-case results), and compares two or more evaluation runs side by side.

## Sub-features

- `evals-suites` lists suites with version, `locked`, case count, and run count.
- `evals-open-run` opens one evaluation run by id: `Passed x/y`, agent, config, status, and a per-case table (result, latency, cost, why, `trace` link).
- `evals-compare` compares two or more evaluation runs on one table: config, passed, rate, latency mean, cost, tokens, violations.
- `evals-trace-link` jumps from a result row to the underlying agent run's trace.

## How to get to it (user POV)

- Click `Evaluations` in the sidebar (`#/evals`).
- `Open an evaluation run` takes an evaluation run id; `Compare two runs` takes a comma-separated list.

## Driving it with browser_exec

Preconditions:

- Baseline met. Run ids come from `eval_runs` — there is no list endpoint, so query the
  database: `docker exec traceguard-postgres-1 psql -U traceguard -d traceguard -t \
  -c "SELECT id, status FROM eval_runs ORDER BY started_at DESC LIMIT 4;"`.

- **Load.** Open `#/evals`; the suites card lists every suite (a dev database accumulates
  many from prior test runs — read the top rows, do not count them).
- **Open a run.** Fill `input[name="runId"]` with a real eval run id (native value setter +
  `input` event, then `el.form.requestSubmit()`). The view renders four stats and a results
  table; assert `Passed x/y` and the row count.
- **Compare.** Fill `input[placeholder="run-id-1, run-id-2"]` with two comma-separated ids
  and submit; assert a table containing `LATENCY MEAN` with one row per run.
- **Trace link.** Click `trace` on a result row; the hash becomes `#/runs/<agent_run_id>`
  and the trace view renders span buttons (`[data-span]`).
- **Proof.** `checks.txt` records the suite list head, the opened run's stats string, the
  compare rows, and the hash after the trace click.

## Gotchas

- Suites are read-only here (no per-suite Open button); the `Open` button belongs to the
  "Open an evaluation run" form, so clicking it with an empty input is a no-op by design.
- The compare input wants evaluation run ids, not agent run ids — feeding it agent run ids
  renders an empty or error part instead of the table.
- Both forms are proper `<form>` elements: drive them with `requestSubmit()` rather than
  hunting a submit button.
- A dev database's suites are mostly other tests' leftovers; `locked` suites cannot accept
  new cases, which is expected.
