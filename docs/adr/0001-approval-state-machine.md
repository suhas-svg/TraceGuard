# ADR-0001: Explicit, single-use approval state machine

- Status: Accepted
- Date: 2026-10-23
- Deciders: TraceGuard maintainers
- Related: spec §9, FR-011, FR-015; migration `019_approval_state_machine.sql`,
  migration `035_approval_procedures.sql`, `apps/api/src/gateway.ts`

## Context

A tool call that needs human approval crosses three failure domains: the
approval decision, the policy that authorized it, and the upstream side effect.
A boolean `approved` flag cannot express expiry, a decision that raced another
decision, a policy publish that invalidated the approval, a claimed call that
crashed before dispatch, or a dispatch whose result is unknown. Retrying such a
call without a state machine duplicates side effects.

## Decision

Approvals use an explicit state machine enforced by the database:

- `pending` → `approved`, `rejected`, or `expired`.
- `approved` is consumed by an atomic claim: `claimed` → `executing`.
- A dispatched call ends in `response_received` (success or upstream error) or
  `outcome_unknown`.
- `policy_invalidated` and `tool_quarantined` are terminal states produced when
  the consume-time re-evaluation refuses the call.
- Approval is single-use. A second decision, a replay after execution, or a
  claim that loses the compare-and-set returns a conflict instead of executing.

The transition logic lives in `approval_transition(...)`, a `SECURITY DEFINER`
procedure owned by `approval_owner`. Runtime roles cannot update the approvals
table directly. Only the separate control listener can decide an approval;
agent credentials are refused there. Arguments are sealed at rest, and a
decision keeps only a redacted summary.

## Consequences

- Every transition has one linearization point and can be audited with the
  policy version and matched rules that existed at that point.
- Recovery sweeps can find stray claims and stuck `executing` rows without
  guessing whether a side effect happened.
- A caller may receive `409 approval_decided_elsewhere` or
  `410 approval_expired`; clients must treat those as terminal, not retryable.
- Adding a state requires a migration, procedure change, audit taxonomy
  update, and a test that proves the denied path has no upstream contact.

## Alternatives considered

- **Boolean `approved` column.** Rejected: cannot represent expiry, claims,
  invalidation, or unknown outcomes.
- **Approval state in application memory.** Rejected: the API and gateway are
  separate processes and can restart independently.
- **Retry on any non-success response.** Rejected: duplicates side effects and
  violates the at-most-once execution guarantee.
