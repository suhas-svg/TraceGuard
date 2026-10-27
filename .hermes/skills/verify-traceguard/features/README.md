# TraceGuard web verification map

Maintained source for verifying the user-facing behavior of the TraceGuard web
dashboard (`apps/web`). Read this index before driving the app, then use the matching
feature file as the recipe. Harness: `browser_exec` (see `../SKILL.md` → Drive for the
helper list and the stable-handle table).

## Baseline preconditions

- Full stack up per `../SKILL.md` → Launch; `Doctor` returns all 200.
- At least two runs seeded (`pnpm --filter demo-agent-ts start`, run twice or more).
- Dashboard at `http://localhost:5173`, default keys (no localStorage overrides).
- One `browser_exec` session named `traceguard` per verification run; start every
  recipe from `http://localhost:5173/#/runs` unless its preconditions say otherwise.

## Driving conventions

- Prefer ARIA roles and accessible names (`aria-label`, `aria-current`, `role="group"`)
  over CSS classes or DOM position; the handle table in `../SKILL.md` lists the stable ones.
- Hash routing is user-visible contract: assert `location.hash` after every navigation,
  including `history.back()`.
- Read state with `js(...)`; click with `js("...click()")` on a queried element.
- Treat every command as literal; keep quoted names and flags unchanged.

## Proof and skip reporting

- Capture the user action and the resulting state, not only the final screen.
- UI proof: `checks.txt` lines (`check: <what> => <value>`) plus screenshots in
  `.hermes/skills/verify-traceguard/evidence/<ts>/`.
- Mutation proof (approval decision, policy create) includes a read-only second view of
  the stored result (re-list the queue/rules).
- Record the feature ID with every artifact. Report an unreachable path with the
  attempted command and the unmet precondition; never report a skipped entry point as
  verified through another path.

## Feature entry contract

Each feature file starts with an H1 and one paragraph of user-visible behavior, then
exactly four H2 sections in this order: `Sub-features`, `How to get to it (user POV)`,
`Driving it with browser_exec` (starts with `Preconditions:`, then labeled bullets
pairing user action → exact command → observable result), `Gotchas`.

## Features

- [Runs list](./runs-list.md) — status filtering, cursor pagination, live refresh, opening a run.
- [Trace explorer](./trace-explorer.md) — span timeline, span detail panel, deep links, back navigation.
- [Approvals queue](./approvals-queue.md) — filter tabs, decision actions, pending vs terminal states.
- [Policy center](./policy-center.md) — upstream servers, versioned rules, create/edit flow.
- [Costs comparison](./costs-comparison.md) — window form, estimate-vs-billed bars, variance table.
- [Webhooks](./webhooks.md) — subscriptions, delivery log, retry.
- [Retention](./retention.md) — rules, run history, destructive-window discipline.
- [Users](./users.md) — accounts, scoped keys (mint/revoke), workspace membership.
- [Evaluations](./evals.md) — suites, open an evaluation run, compare runs.
