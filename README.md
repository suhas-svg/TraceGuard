# TraceGuard

Self-hosted control plane for AI agents: execution tracing, cost control
with budgets, MCP tool policy enforcement with human approvals, and
scripted evaluation workbench.

## What it looks like

| | |
|---|---|
| ![Overview](docs/images/overview.png) | ![Runs](docs/images/runs.png) |
| Overview: runs by status, tokens, spend, latency percentiles, denied calls, pending approvals | Runs: search, sort, filters by agent, status, date, provider, model, and eval run |
| ![Trace](docs/images/trace.png) | ![Costs](docs/images/costs.png) |
| Trace: nested spans with per-span usage, cost, and the error class apart from policy denials | Costs: spend by model, budget utilization, estimates against imported provider actuals |
| ![Policy](docs/images/policy.png) | ![Evaluations](docs/images/evaluations.png) |
| Policy: server registration with tool quarantine, rules, budgets, and audit history | Evaluations: suites, per-case results, and a two-run comparison |

Regenerate these from the current build with `node scripts/screenshots.mjs`
against a running stack; see the file header for the commands.

## Run it

One command from a clean checkout:

```bash
pnpm install
pnpm demo
```

`pnpm demo` creates `.env` from `.env.example` if it is missing, generates
the approval seal key and an ed25519 audit-checkpoint key pair under
`.demo-keys/` (gitignored), builds and starts the compose stack, waits for the
api, gateway, approval control listener, and dashboard, then runs the demo agent
through the boundary and prints the live trace URL. No key is committed and no
key is printed.

```bash
pnpm demo:audit   # signed checkpoint -> export -> offline verify -> refused prune
pnpm demo:reset   # remove demo/bench fixtures, keep history
```

`demo:audit` exercises §21.16 directly: it invokes the operator CLI to create
and sign a checkpoint over the exact current prefix, verifies the artifact
offline with `scripts/verify-audit.mts`, then proves the CLI refuses a tampered
artifact and prints the operator-only prune command. It never deletes audit
events. The gateway receives only the public key and can verify, not sign or
prune. Artifacts produced after a prune carry the prior signed checkpoint as
their `anchor`; the offline verifier checks it before using its workspace heads.

Dev ports: API 8090, gateway 8091, approval control listener 8093, mock tools
8092 (internal only), web 5173. The demo agent runs as the `agent` container
on `agent_edge`: the gateway is the only container it can reach, and
`pnpm test:security` proves that from inside it (upstream, api and postgres
must all refuse the agent). Agent telemetry goes to the gateway's fixed
`/v1/ingest/events` path, which forwards it to the API; the agent never talks
to the API directly.

### Manual path

1. Copy `.env.example` to `.env`, set `API_KEY` and `APPROVER_KEY`, and set
   `APPROVAL_ARGS_KEY` to 32 random bytes as hex.
2. `docker compose up --build`
3. The `db-roles` service applies the migrations and enables the
   least-privilege role logins (`api_runtime`, `gateway_runtime`,
   `retention_job`, `policy_publisher`) before the api and gateway start;
   watch it with `docker compose logs db-roles`. Running outside compose,
   apply `apps/api/migrations/*.sql` yourself and run the `ALTER ROLE` lines
   in `docs/operations.md`.
4. Run the demo through the boundary: `docker compose exec agent python main.py`
   — the agent container can only reach the gateway, so the demo also
   demonstrates FR-004. (On the host instead: `python -m pip install
   ./sdks/python` then `TRACEGUARD_URL=http://localhost:8090 python
   examples/demo-agent/main.py`.)
5. Open http://localhost:5173, set the API URL and key in the header, browse runs.

Starting compose by hand does not set `AUDIT_CHECKPOINT_PUBLIC_KEY`; export it
yourself (or use `pnpm demo`) if you want the gateway to verify anchored
history. The private key stays on the operator host and is used only by
`pnpm audit:checkpoint`.

## Signed policy: the operator flow

The control surface edits **drafts** — rules in `policies`, server registrations, and reviewed tool pins. Nothing enforces a draft. Enforcement reads the active signed bundle, and only the operator's key can sign one:

```bash
# 1. Create the signing key pair (once). Keep the private key on this host.
pnpm policy:keygen                      # writes ./policy-keys/{signing-key.pem,.pub.pem}

# 2. Trust the public key for a workspace (once; audited).
pnpm policy:trust -- --workspace default

# 3. Sign and publish a project's current drafts as its new active version.
#    --project accepts a name or id and defaults to the workspace's "default"
#    project. Inside the compose deployment the publisher connects with its
#    own least-privilege role (the password is PUBLISHER_DB_PASSWORD in .env):
pnpm policy:publish -- --workspace default --project default \
  --database-url postgres://policy_publisher:publisher_dev_pw@localhost:5432/traceguard

# What would be published, without publishing:
pnpm policy:publish -- --workspace default --project default --dry-run
```

Every publish is a new immutable `policy_versions` row carrying the rule set, the server manifest, the tool-pin manifest, the protocol profile, the version, and the previous version's hash, with an Ed25519 signature. The gateway refuses to enforce anything if the content hash, signature, key id, version, project/workspace binding, or history does not check out. It remembers the highest version it accepted for each project (the `gateway_state` volume in compose), so pointing the database back at an older signed bundle is detected as a rollback.

Consequences worth knowing:

- A tool call before the first publish fails closed (`503 policy_unavailable`), and `tools/list` reports `POLICY_UNAVAILABLE` rather than an empty catalog.
- A registered server or a discovered tool that the active bundle does not carry is not callable; discovery creates candidates, review and publication activate them.
- A tool whose definition changed after publication is quarantined; re-approval creates a new pin version, and a **new publish** is what makes it executable again.
- Rotating the signing key retires the old one: the gateway then refuses versions signed by it until a new bundle is published under the replacement.
- Approval retries are bound to the exact tool pin: an approval issued for one definition cannot consume another.

The dashboard's Policy tab shows the active signed version and its history, and says which state the drafts are in.

## What works now

- `POST /v1/ingest/events` validates with Zod, dedupes on `event_id`, auto-creates workspace, agent, and run records.
- `GET /v1/runs`, `GET /v1/runs/:id`, `GET /v1/runs/:id/trace`, `GET /v1/runs/:id/usage` read stored runs with token and cost breakdowns.
- Gateway on :8091: upstream registry, tool discovery with complete definition pinning, and **enforcement that reads only a signed, immutable policy bundle**. The rule set, the upstream server manifest, and the tool-pin manifest are assembled by `tools/policy-publisher`, signed with an operator-held Ed25519 key, and published as a monotonic version. The gateway verifies content hash, signature, key, and history, and fails closed on anything else — including a rolled-back or forked pointer. See "Signed policy" below.
- The gateway exposes the MCP Streamable HTTP profile at `POST /mcp` (`server/discover`, `tools/list`, `tools/call`) with namespaced `alias__tool` names, header/body binding, and the approval retry contract keyed on a stable logical request id; unsupported methods are rejected and never forwarded. See `docs/compatibility.md`.
- Approvals are a ten-state machine: `pending` → `approved` → `executing` → `response_received` / `outcome_unknown`, plus terminal `rejected`, `expired`, `policy_invalidated` and `tool_quarantined`. A timeout or crash after dispatch is recorded as **outcome unknown** ("the upstream action may have executed") and is never retried. TTL defaults to 15 minutes (hard max 60), with per-caller pending caps and a creation rate limit.
- The certified client shim (`packages/mcp-client-shim`) drives that contract: one stable logical request id per logical call, fresh JSON-RPC ids per attempt, bounded backoff while pending, and explicit terminal / outcome-unknown errors instead of resubmission. Its `oauth:` option makes it discover the gateway's protected-resource metadata and the issuer's metadata, request a token for that resource (RFC 8707) and refresh it — so a deployment on OAuth needs no static key in the agent. Headless agents use `client_credentials`; interactive clients use Authorization Code + PKCE through `beginAuthorization()` and `authorizationCode`, and static tokens require the explicit `authProfile: "development"` shim option.
- Budgets with atomic reserve-and-settle plus a Python `BudgetGuard` wrapper.
- Evaluations: versioned suites, scripted or live replay, deterministic assertions, run comparison.
- The dashboard has Overview, Runs, Evaluations, Policy, Approvals, Webhooks,
  Retention, Costs, and Users tabs: KPI tiles with usage and spend charts, run
  search and traces, suite creation and runs with comparison, server
  registration with tool quarantine, budget management and audit history,
  the approval queue, webhook subscriptions with delivery log, retention
  rules with run history, cost variance, and team, key, and workspace
  management.
- `POST /v1/traces` accepts OpenTelemetry OTLP/HTTP in protobuf
  (preferred) and JSON with GenAI conventions, so instrumented frameworks
  land without a new SDK. Spans in one trace share a run, retries upsert by
  stable ids, child spans that arrive before their parent are linked when
  the parent shows up, and `POST /v1/admin/finalize-orphan-spans` flags
  parents that never arrive. Rejections are reported as OTLP partial
  success — the good spans land and the rest come back with reasons — and
  a per-caller span rate limit answers 429.
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
- `POST /v1/budgets` sets run, agent, or project limits with block or warn
  effects, and a reporting `period` of `lifetime` (default), `day`, `week`,
  or `month`. Windowed spend is summed from the append-only ledger, so no
  counter is reset on a schedule and past windows stay explainable.
- A **project** budget (`scope: "project"`, `ref_id` = a project id; a legacy
  workspace id still resolves to that workspace's default project) caps
  what the whole project spends over its period. It is measured from the
  project's priced spans rather than from its own ledger, because a ledger
  only counts calls that checked that specific budget — measuring it would
  report headroom that is not there and never block. A span with usage but no
  matching price has unknown cost, not zero: a block budget refuses with 409
  `budget_unknown_usage`, and the list reports `spend_complete: false` with
  `remaining_micro: null` instead of claiming headroom.
- A hold that is abandoned (a caller that dies between reserve and settle)
  is settled at its reserved maximum by the next check against that budget,
  and the settlement is audited. Unknown usage is charged conservatively
  rather than returned to the budget.
- `GET /v1/runs/:id/usage` breaks tokens and cost down per span against the
  price in force at the time. Cached input tokens bill once at the cached
  rate, never on top of the full input rate; spans with no matching price
  report NULL and list under `missing_pricing`, never zero.
- The managed path reserves before the call under a row lock, then settles
  to the measured cost. A blocked call gets 409 and the SDK raises
  `BudgetExceeded` instead of calling the provider.
- Tool calls can hold budget too. With `TOOL_CALL_RESERVATION_MICRO` above
  zero, the gateway reserves that amount against every covering run or agent
  block budget before dispatch and releases it when the call finishes. The
  hold is all-or-nothing across covering budgets and is audited as
  `budget.reserved`; a crash leaves a held row that the expiry sweep settles
  at the reserved maximum. `TOOL_CALL_RESERVATION_TTL_SECONDS` bounds the
  hold (default 300). The default amount is 0 because tool calls do not
  themselves spend provider money; enable it when a tool call needs to
  consume budget headroom while it is in flight.
- The Python SDK gained `BudgetGuard` plus `flush`, and now stamps Zulu
  timestamps the API accepts.
- The trace header shows the estimated run cost from the usage endpoint.

## Phase 5: evaluation workbench

- Suites version on creation and lock on first use. Cases carry scripted
  behavior plus deterministic assertions: exact, contains, regex, a JSON
  schema subset with nested objects, arrays, and enums, tool names or an
  ordered sequence, and final status. A case with an `expected` value and
  no scripted output replays it, and `input_payload` rides the run's first
  span for provenance.
- Starting a run replays every case for N trials, writes real runs you can
  open in the dashboard, and records pass state, latency, cost, and the
  config fingerprint. Per-run overrides let a second version run the same
  locked dataset differently.
- The compare endpoint reports pass rate, latency spread, cost, and denied
  tool violations side by side, with missing data shown as missing.
- A run executes through a registered adapter. `scripted` replays the case's
  declared behavior; `http` posts the case to a live endpoint and records what
  it answers, so the case exercises the agent rather than a description of it.
  Both write through the same run contract, so assertions, latency, cost, and
  the per-case run link behave identically either way. The call goes through
  the same SSRF guard as every other outbound request, and an unreachable
  endpoint fails its own case rather than discarding the whole run.
- The dashboard has an Evaluations tab: suite list, per-case results with
  failure reasons, links back to traces, and a two-run comparison.

Unit checks: `pnpm install && pnpm test`. The Python SDK suite runs separately
(`pip install "./sdks/python[dev]" && python -m pytest sdks/python`), the
browser scenarios with `pnpm test:e2e`, the Kubernetes manifests with
`python infra/k8s/check.py`, and the performance table with
`node scripts/bench.mjs`.

## Documentation

| File | What is in it |
|---|---|
| `docs/architecture.md` | components, request flow, and where enforcement lives |
| `docs/security.md` | what the platform guarantees, what it does not, and the sensitive-data inventory |
| `docs/configuration.md` | every environment variable and the scoping rules |
| `docs/operations.md` | backups, restores, migrations, and the cron endpoints |
| `docs/PERFORMANCE.md` | how to measure, and one recorded run of the targets |
| `docs/kubernetes.md` | the manifests and how to deploy them |

## Phase 3: trace dashboard

- `apps/web` is a read-only React dashboard: run list with status filter and
  Load more pagination, plus a trace view with a nested span tree, per-span
  detail, token totals, and denied-by-policy shown apart from failures.
- API and gateway URLs are editable in the page header; privileged keys are
  exchanged for short-lived HttpOnly sessions and are never stored in
  localStorage. Policy and approval actions live on their own tabs; run views
  stay read-only.
- Run it: `pnpm --filter @traceguard/web dev` (port 5173) against the
  API on 8090, or `docker compose up web` for the built bundle.

## Phase 2: gateway and policy

- `POST /v1/servers`, `POST /v1/servers/:id/discover` register Streamable HTTP
  upstreams and pin each tool definition hash. Changed definitions quarantine
  until re-approved. Upstream credentials stay in the gateway and are never
  returned by reads. Upstream URLs are validated at registration, discovery,
  and call time; private ranges need `ALLOW_PRIVATE_UPSTREAMS=true` and cloud
  metadata addresses are always refused.
- Policy effects are allow, deny, and require_approval. Deny overrides
  everything, priority only orders rules with the same effect, and unmatched
  calls are denied. Conditions use a fixed operator set: required fields plus
  `path_within`, `regex`, `enum`, and `max_length` per argument. `path_within`
  is not a gateway-only check: the rule must be server- and tool-scoped, the
  pinned tool definition must attest `io.traceguard/path-confinement` with
  `enforcement: "executor"`, and the executor itself resolves real paths and
  refuses traversal and symlink escapes. The publisher refuses to sign a
  `path_within` rule whose executor attestation is missing or out of root.
- A call needing approval returns 202 with an approval id and the gateway
  makes no upstream contact. The client retries with the approval id after a
  human decides with the separate approver key. Approvals are single-use and
  bound to caller, server, tool, canonical args, request id, and the pinned
  tool definition. The queue and decisions live on the gateway's control
  listener (`GATEWAY_CONTROL_PORT`, default 8093): only approver credentials —
  the approver key or a token carrying the approve scope — may list or decide;
  agent, read-scope, and admin keys get 403 there (admin does not shortcut the
  queue), and the agent-facing port no longer serves the route at all.
  Consuming an approval claims it under a short lease before any dispatch, so
  a crash between claim and execution returns it to approved, while anything
  ambiguous after dispatch ends in outcome_unknown and is never auto-retried.
  Expired holds flip to expired on the next list, so queues never show dead
  entries.
- Every decision lands in `policy_decisions` citing the exact policy version,
  and every admin or execution outcome lands in the hash-chained `audit_events`
  table. Policies are immutable versions: an update supersedes, never edits.
- Try it: `node examples/mock-tools/server.mjs`, register
  `http://localhost:8092/mcp` (needs `ALLOW_PRIVATE_UPSTREAMS=true` locally),
  discover, add an allow rule, and call through
  `POST /v1/gateway/tools/call` on port 8091.

## Status

Every roadmap phase above is implemented: ingestion and the trace dashboard,
the gateway with policy, approvals, and audit, budgets and pricing, and the
evaluation workbench. Webhooks, retention, reconciliation, users and
memberships, and OTLP ingestion landed on top; their sections are under
"What works now".

## Scope decisions from the review

- Streamable HTTP only for MCP upstreams. No stdio process spawning in the gateway.
- Approval arguments are sealed (AES-256-GCM) while a request is pending. Once it is denied, expires, or executes, the sealed arguments are cleared and only a redacted summary and the argument hash remain.
- Deny overrides allow. Priority breaks ties within the same effect only.
- Money uses NUMERIC or integer micro-dollars, never floats. Unknown model means NULL cost, not zero.
- Gateway fails closed. SDK telemetry fails open. Budget wrapper fails closed.

## Roadmap: next integrations

- Cost explorer drill-downs: an input-vs-output cost split on the group-by view.
- OTLP export from TraceGuard, plus log ingestion alongside traces.
- A deployment that has actually been rolled out. The manifests are rendered and
  checked by `infra/k8s/check.py`, never applied to a cluster, and the §14
  numbers in `docs/PERFORMANCE.md` come from one Windows dev box.
- SSO/OIDC for the dashboard, replacing bearer-token login.
- Alerting integrations (Slack, PagerDuty) on top of the existing webhook events.
