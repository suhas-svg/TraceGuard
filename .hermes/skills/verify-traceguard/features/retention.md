# Retention

Retention ages out runs, terminal approvals, and delivery logs: rules carry a target and an
older-than window, `Run now` executes every enabled rule at once, and every run appends to
`Run history` with the per-rule deleted counts. Policies, decisions, audit, and money are
never targets.

## Sub-features

- `retention-create` adds a rule (name, target, older-than days).
- `retention-toggle` enables or disables a rule.
- `retention-delete` removes a rule.
- `retention-run` executes all enabled rules and records a run with deleted counts.

## How to get to it (user POV)

- Click `Retention` in the sidebar (`#/retention`).
- Form at the top: `Rule name`, `Target`, `Older than (days)`, `Add rule`.
- `Run now` sits in the page header; `Disable` / `Delete` sit on each rule card.

## Driving it with browser_exec

Preconditions:

- Baseline met. `Run now` is destructive by design — only drive it with a rule window nothing
  can match (e.g. `3650` days) so the proof deletes nothing.

- **Create.** Fill the two inputs and the target select in the top form (React-controlled:
  set `value` via the native setter then dispatch `input`/`change`), click `Add rule`.
  The rule card renders `name | target older than Nd | status | Disable | Delete`.
- **Run.** Click `Run now`; `Run history` gains a row `timestamp | success | name: 0`.
  Ground-truth the same run through `GET /v1/retention/runs` and compare `deleted_counts`.
- **Delete.** Click `Delete` on the rule card; `GET /v1/retention/rules` no longer lists it.
  Assert the API, not the page text — the run history also contains the rule name.
- **Proof.** `checks.txt` records rule name, target, window, the run's deleted counts, and the
  post-delete rule list.

## Gotchas

- The rule list and run history are cards, not tables (`tbody tr` is always 0 here).
- `Run now` runs every enabled rule in the workspace, including ones created by other tests;
  read `deleted_counts` per rule instead of assuming only your rule participated.
- Deleting a rule leaves its history rows behind — that is expected.
- The target select's change event must be dispatched manually; setting `.value` alone does not
  update React state.
