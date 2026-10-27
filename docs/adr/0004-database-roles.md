# ADR-0004: Least-privilege PostgreSQL roles and procedure-based writes

- Status: Accepted
- Date: 2026-10-23
- Deciders: TraceGuard maintainers
- Related: spec §5.3, §13.4, NFR-008; migrations `023`, `033`, `035`–`037`,
  `040`, `042`, `045`; `apps/api/tests/db-roles.test.ts`

## Context

The API, gateway, publisher, retention job, and identity plane have different
trust levels. A single database user makes every application bug a potential
policy, audit, or approval rewrite. The specification requires the running API
to be unable to alter signed policy, audit history, or decision state.

## Decision

PostgreSQL roles are separated by capability:

| Role | Purpose | Key limits |
|---|---|---|
| `api_runtime` | control-plane HTTP API | drafts and server/pin administration; no signing, audit DML, or approval transitions |
| `gateway_runtime` | tool-call enforcement | read trusted config; narrow state-transition functions; no trusted-config writes |
| `policy_publisher` | operator CLI | execute publisher procedures only; no direct broad table writes |
| `approval_owner` | owns approval tables/procedures | NOLOGIN; owns `approval_transition` |
| `policy_owner` | owns policy/trust/activation procedures | NOLOGIN; stamps signed server versions |
| `audit_owner` | owns `audit_events` and append function | NOLOGIN; no runtime traffic |
| `retention_job` | span/run retention and checkpoint-gated audit prune | no approval or policy deletes |
| `identity_owner` | owns local identity procedures | NOLOGIN |
| `migration_owner` | schema migrations | not used by runtime services |

Writes that cross a trust boundary go through `SECURITY DEFINER` functions with
a fixed `search_path`, an explicit owner, and grants only to the role that needs
them. The audit table rejects `UPDATE` and `DELETE` at the trigger and privilege
layers. Signed policy versions, signing keys, active pointers, and stamped
server configuration are immutable to runtime roles.

## Consequences

- Every new table or write path needs an explicit grant and a denial test in
  `db-roles.test.ts`; default privileges must not be widened casually.
- A privileged function is security-critical code: review its owner, search
  path, input validation, and return shape like an API endpoint.
- Local development connects as an owner to run migrations, then tests use
  `SET ROLE` to prove the production role matrix.
- Operational break-glass access is a database-owner action, not an API route.

## Alternatives considered

- **One application role with SQL-level checks.** Rejected: an application bug
  or injection becomes a full trust-boundary breach.
- **Row-level security only.** Rejected: RLS does not separate signing,
  retention, and audit ownership.
- **Separate databases per service.** Rejected for v1: transactionally coupling
  approval transitions and audit appends is more valuable than physical
  isolation at this scale.
