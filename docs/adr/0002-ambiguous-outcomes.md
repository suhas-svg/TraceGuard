# ADR-0002: Ambiguous dispatch outcomes are terminal and never auto-retried

- Status: Accepted
- Date: 2026-10-23
- Deciders: TraceGuard maintainers
- Related: spec §9.2–§9.4, FR-015; `apps/api/src/gateway.ts`,
  `apps/api/tests/approvals.test.ts`

## Context

Once a gateway has committed `executing` and sent an upstream request, a
timeout, connection reset, or missing response does not prove the tool did not
run. Treating that case as a failure and retrying can execute a side effect
twice. Treating it as success can report a result that was never observed.

## Decision

Any post-dispatch ambiguity moves the approval to `outcome_unknown` and stops.
The gateway never re-dispatches an `outcome_unknown` approval automatically.
The HTTP response is `502` with `{ error: "outcome_unknown", approval_id }`.

If the upstream response arrives after the row was finalized, the gateway
records an `approval.response_late` audit event and does not overwrite the
terminal row. Operators see these rows through
`GET /_control/v1/approvals?status=outcome_unknown` and reconcile them with the
upstream system. The recovery sweep applies the same rule to rows stuck in
`executing`: they become `outcome_unknown`, not `failed` and not `approved`.

## Consequences

- Automatic execution is at-most-once. A human may still choose to re-run a
  reconciled action, which creates a new approval and a new decision.
- The system can under-report successful calls during an outage; it must not
  claim success it cannot prove.
- Clients must surface `outcome_unknown` distinctly. The MCP shim does so and
  does not silently retry.
- The audit trail must retain the claim id, policy version, matched rules, and
  timing needed for reconciliation.

## Alternatives considered

- **Retry after a timeout.** Rejected: duplicate side effects are exactly the
  failure mode the boundary exists to prevent.
- **Mark as failed.** Rejected: the upstream may have executed the call.
- **Mark as success.** Rejected: no response was observed.
- **Best-effort idempotency keys only.** Rejected: upstream tools are not
  required to support them; the gateway cannot assume it.
