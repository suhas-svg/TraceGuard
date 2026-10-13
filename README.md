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

## Deferred to later phases

Gateway, policy engine, approvals, audit log, pricing and budgets, evaluation, dashboard. Directories for those exist in the spec but contain no code yet on purpose. Each lands as its own phase with its own exit test.

## Scope decisions from the review

- Streamable HTTP only for MCP upstreams. No stdio process spawning in the gateway.
- Pending approval arguments stay encrypted with a TTL, then only a redacted summary and hash remain.
- Deny overrides allow. Priority breaks ties within the same effect only.
- Money uses NUMERIC or integer micro-dollars, never floats. Unknown model means NULL cost, not zero.
- Gateway fails closed. SDK telemetry fails open. Budget wrapper fails closed.
