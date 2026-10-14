# TraceGuard

Self-hosted control plane for AI agents: execution tracing, cost control
with budgets, MCP tool policy enforcement with human approvals, and
scripted evaluation workbench.

## Run it

Dev ports: API 8090, gateway 8091, mock tools 8092 (internal only), web 5173.

1. Copy `.env.example` to `.env` and set `API_KEY` and `APPROVER_KEY`.
2. `docker compose up --build`
3. Apply migrations in order: `for f in apps/api/migrations/*.sql; do psql $DATABASE_URL -f "$f"; done`
4. Install the SDK and run the demo: `python -m pip install ./sdks/python`
   then `TRACEGUARD_URL=http://localhost:8090 python examples/demo-agent/main.py`
5. Open http://localhost:5173, set the API URL and key in the header, browse runs.

## What works now

- `POST /v1/ingest/events` validates with Zod, dedupes on `event_id`, auto-creates workspace, agent, and run records.
- `GET /v1/runs`, `GET /v1/runs/:id`, `GET /v1/runs/:id/trace`, `GET /v1/runs/:id/usage` read stored runs with token and cost breakdowns.
- Gateway on :8091: upstream registry, tool discovery with definition pinning, allow/deny/approval policies, single-use bound approvals, hash-chained audit.
- Budgets with atomic reserve-and-settle plus a Python `BudgetGuard` wrapper.
- Evaluations: versioned suites, scripted replay, deterministic assertions, run comparison.
- The dashboard has Runs, Evaluations, Policy, Approvals, Webhooks, and
  Retention tabs: run search and traces, suite results with comparison,
  rule editing, the approval queue, webhook subscriptions with delivery
  log, and retention rules with run history.
- `POST /v1/traces` accepts OpenTelemetry OTLP/HTTP JSON with GenAI
  conventions, so instrumented frameworks land without a new SDK. Set
  `OTEL_EXPORTER_OTLP_PROTOCOL=http/json` on the exporter. Spans in one
  trace share a run, retries upsert by stable ids, and
  `POST /v1/admin/finalize-stale-runs` closes runs orphaned by crashes.
- Webhooks report denials, approvals, budget breaches, and finished
  evaluations to operator URLs with an HMAC signature. Delivery never
  blocks the decision, every attempt is logged, and failures retry from
  `POST /v1/webhooks/deliveries/:id/retry`.
- Retention rules age out runs, terminal approvals, and delivery logs on a
  cron-driven run endpoint. Policies, decisions, pending approvals, audit
  history, and money tables are never deletion targets.
- Reconciliation imports provider actuals and compares them against
  estimates per model and period, with a Costs tab showing variance.
- Users with scoped keys: first registration bootstraps the admin, then
  member keys ingest and call tools while approver keys decide. Memberships
  confine member writes and reads to their workspaces; foreign ids read as
  missing.
- `GET /healthz`, `GET /readyz` report liveness and database state.
- Python SDK sends events over HTTP with a bounded queue and never raises into the agent.
- TypeScript SDK (`@traceguard/sdk`, zero dependencies) mirrors it: events, budget guard, flush.
- `examples/demo-agent` submits a sample run and fetches its trace.
- `examples/mock-tools` is a two-tool upstream for gateway demos.
- `infra/k8s` holds Kubernetes manifests with a migrate job; see `docs/kubernetes.md`.

## Phase 4: cost and budgets

- `POST /v1/pricing` versions model prices, old versions stay so past
  estimates keep meaning. Money is integer micro-dollars, never floats.
- `GET /v1/runs/:id/usage` breaks tokens and cost down per span against the
  price in force at the time. Spans with no matching price report NULL and
  list under `missing_pricing`, never zero.
- `POST /v1/budgets` sets run or agent limits with block or warn effects.
  The managed path reserves before the call in one atomic UPDATE, then
  settles to the measured cost. A blocked call gets 409 and the SDK raises
  `BudgetExceeded` instead of calling the provider.
- The Python SDK gained `BudgetGuard` plus `flush`, and now stamps Zulu
  timestamps the API accepts.
- The trace header shows the estimated run cost from the usage endpoint.

## Phase 5: evaluation workbench

- Suites version on creation and lock on first use. Cases carry scripted
  behavior plus deterministic assertions: exact, contains, regex, a small
  JSON schema subset, tool sequence, and final status.
- Starting a run replays every case for N trials, writes real runs you can
  open in the dashboard, and records pass state, latency, cost, and the
  config fingerprint. Per-run overrides let a second version run the same
  locked dataset differently.
- The compare endpoint reports pass rate, latency spread, cost, and denied
  tool violations side by side, with missing data shown as missing.
- The dashboard has an Evaluations tab: suite list, per-case results with
  failure reasons, links back to traces, and a two-run comparison.

Unit checks: `npm install && npm test`.

## Phase 3: trace dashboard

- `apps/web` is a read-only React dashboard: run list with status filter and
  Load more pagination, plus a trace view with a nested span tree, per-span
  detail, token totals, and denied-by-policy shown apart from failures.
- API URL and key are editable in the page header and kept in localStorage.
  The dashboard never writes: policy and approval actions stay in API clients.
- Run it: `npm run dev --workspace=@traceguard/web` (port 5173) against the
  API on 8090, or `docker compose up web` for the built bundle.

## Phase 2: gateway and policy

- `POST /v1/servers`, `POST /v1/servers/:id/discover` register Streamable HTTP
  upstreams and pin each tool definition hash. Changed definitions quarantine
  until re-approved. Upstream credentials stay in the gateway and are never
  returned by reads.
- Policy effects are allow, deny, and require_approval. Deny overrides
  everything, priority only orders rules with the same effect, and unmatched
  calls are denied. Conditions use a fixed operator set: required fields plus
  `path_within`, `regex`, `enum`, and `max_length` per argument.
- A call needing approval returns 202 with an approval id and the gateway
  makes no upstream contact. The client retries with the approval id after a
  human decides with the separate approver key. Approvals are single-use and
  bound to caller, server, tool, canonical args, and request id. Agent keys
  get 401 on the decision endpoint.
- Every decision lands in `policy_decisions` citing the exact policy version,
  and every admin or execution outcome lands in the hash-chained `audit_events`
  table. Policies are immutable versions: an update supersedes, never edits.
- Try it: `node examples/mock-tools/server.mjs`, register
  `http://localhost:8092/mcp` (needs `ALLOW_PRIVATE_UPSTREAMS=true` locally),
  discover, add an allow rule, and call through
  `POST /v1/gateway/tools/call` on port 8091.

## Deferred to later phases

Pricing and budgets, evaluation, dashboard. Gateway, policy, approvals, and
audit are done in Phase 2. Each remaining piece lands as its own phase with
its own exit test.

## Scope decisions from the review

- Streamable HTTP only for MCP upstreams. No stdio process spawning in the gateway.
- Pending approval arguments stay encrypted with a TTL, then only a redacted summary and hash remain.
- Deny overrides allow. Priority breaks ties within the same effect only.
- Money uses NUMERIC or integer micro-dollars, never floats. Unknown model means NULL cost, not zero.
- Gateway fails closed. SDK telemetry fails open. Budget wrapper fails closed.
