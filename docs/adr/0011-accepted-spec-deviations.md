# ADR-0011: Accepted deviations from spec v3.0 found in the 2026-10-29 scan

- Status: Accepted
- Date: 2026-10-29
- Deciders: TraceGuard maintainers
- Related: spec §5.2, §6.1, §8.2, §9.3, §11.3, §13, §14; ADR-0007, ADR-0009;
  `docs/spec-conformance.md`

## Context

A line-by-line comparison of the repository against the v3.0 specification
found a short list of places where the implementation differs from the text.
Most are intentional and were never written down. A deviation nobody recorded
reads as an oversight to an auditor, so each is stated here with its reason
and the condition that would reopen it. None of them weakens a Must-level
security property; the enforcement boundary is unchanged.

## Decisions

### 1. Gateway budget checks (spec §8.2, §3 "Could")

The spec keeps budget state out of policy evaluation and defers tool-call
budgets so MCP policy has no hidden dependency on budget accounting.

Policy evaluation (`policy.ts`) still takes no budget input. What the gateway
adds is a separate, opt-in step *after* a call is allowed: a block-budget
pre-check, and an optional hold of `TOOL_CALL_RESERVATION_MICRO` (default `0`,
so off) against covering run/agent budgets, released in `finally`. It fails
closed, is all-or-nothing, and runs through `budget_owner` procedures
(migration 048). It is kept because an operator who wants a tool call to
consume budget headroom has no other enforcement point. Revisit if it ever
needs to influence the allow/deny decision itself; that would need a spec
change first.

### 2. Local identity plane (spec §9.3, §14)

The spec says the control API has no endpoint that can grant a trusted role.
`/v1/users`, `/v1/users/:id/keys` and `/v1/users/:id/memberships` exist for the
development profile only. With `OAUTH_ISSUER`/`OAUTH_AUDIENCE` set they answer
`403 external_identity_required`, local keys are refused by principal
resolution, and a production start without an issuer is refused. In OAuth mode
roles come only from the issuer, as the spec requires. Revisit by removing the
routes once SSO/OIDC for the dashboard replaces bearer-key login.

### 3. Network names (spec §6.1)

Compose uses `front`, `tools` (internal) and `agent_edge`, not the spec's four
names, and has no `model_egress` network because the managed model-call path is
an HTTP call from the caller's own process to `/v1/budgets/*`, not a proxy the
platform runs. The properties §6.1 requires (no published upstream ports, the
agent only on `agent_edge`, the upstream network internal) hold and are proven
by `pnpm test:security`. Add `model_egress` if the platform ever proxies
provider traffic.

### 4. Raw `pg` instead of a typed ORM (spec §5.2)

The spec says "Drizzle or a comparable typed layer". Queries are hand-written
SQL over `pg` with checked-in migrations. The security model depends on
`SECURITY DEFINER` procedures and per-role grants, which an ORM would sit
beside rather than express. Not reopened unless query volume makes it a
maintenance cost.

### 5. Hand-written MCP surface (spec §5.2)

`@modelcontextprotocol/sdk` is used as the upstream client. The agent-facing
endpoint is `apps/api/src/mcp.ts`, because the SDK's server classes would
forward capabilities the spec forbids and the allowlist has to be explicit.
Already stated in `docs/compatibility.md`; recorded here for completeness.

### 6. UUIDv4 identifiers (spec §13)

The spec says UUIDv7 "where available". PostgreSQL 17 has no built-in
`uuidv7()`, so ids use `gen_random_uuid()`. No behavior depends on ordering.
Switch when the supported PostgreSQL baseline provides it.

### 7. Idempotency keys (spec §14, API conventions)

Not implemented as a generic `Idempotency-Key` mechanism, deliberately. Replaying
a stored response would persist it, and some state-changing routes return a
secret exactly once (an ingest key is shown on creation and only its hash is
kept, §13.5). A response cache would put that plaintext in the database.
Retry-safety is instead provided by natural keys on the routes where it
matters: span and event ids, the approval `(project, caller, logical_request_id)`
key, reconciliation line keys, and idempotent session logout. Revisit with a
design that excludes secret-bearing routes or stores only a request hash and
status.

### 8. Scheduled sweeps (spec §11.3)

The orphan, stale-run, budget-hold and retention sweeps are endpoints invoked
by cron, by design (`docs/operations.md`). They were previously documented but
not scheduled by either reference deployment. `scripts/maintenance.mjs` now
runs them from a Compose `maintenance` service, and
`infra/k8s/maintenance-cronjob.yaml` does the same every five minutes.

## Not decided here

- The product name remains open ([ADR-0007](0007-product-name.md)).
- Dashboard SSO/OIDC is roadmap work, not a deviation to accept.
- A second independent audit of the post-2026-10-21 work is a human task.
