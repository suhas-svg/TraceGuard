# TraceGuard (Phase 1 scaffold)

Self-hosted control plane for AI agents. Phase 1 covers the smallest testable slice: event ingestion plus run and trace reads.

## What works now

- `POST /v1/ingest/events` validates with Zod, dedupes on `event_id`, auto-creates workspace, agent, and run records.
- `GET /v1/runs`, `GET /v1/runs/:id`, `GET /v1/runs/:id/trace` read stored runs.
- `GET /healthz`, `GET /readyz` report liveness and database state.
- Python SDK sends events over HTTP with a bounded queue and never raises into the agent.
- `examples/demo-agent` submits a sample run and fetches its trace.

## Run it

1. Copy `.env.example` to `.env` and set `API_KEY`.
2. `docker compose up --build`
3. `psql $DATABASE_URL -f apps/api/migrations/001_init.sql` (first boot only, later handled by a migrate step)
4. `cd examples/demo-agent && TRACEGUARD_URL=http://localhost:8080 python main.py`

Unit checks: `npm install && npm test`.

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
