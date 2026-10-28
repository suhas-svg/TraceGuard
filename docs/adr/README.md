# Architecture decision records

These ADRs record the security and architecture decisions the specification
requires for Phase 0. They are intentionally short: each one states the
decision, the forces behind it, and the consequences an operator or contributor
must know. Implementation detail lives in the linked code and runbooks.

| ADR | Decision |
|---|---|
| [0001](0001-approval-state-machine.md) | Explicit, single-use approval state machine |
| [0002](0002-ambiguous-outcomes.md) | Ambiguous dispatch outcomes are terminal and never auto-retried |
| [0003](0003-policy-signing.md) | Operator-signed policy bundles with an out-of-process private key |
| [0004](0004-database-roles.md) | Least-privilege PostgreSQL roles and procedure-based writes |
| [0005](0005-audit-checkpoints.md) | Externally anchored audit checkpoints before any pruning |
| [0006](0006-network-topology.md) | The gateway is the only path from the agent to an upstream |
| [0007](0007-product-name.md) | TraceGuard is a provisional name pending a clearance search |
| [0008](0008-workspace-tooling.md) | pnpm workspaces and a committed frozen lockfile |
| [0009](0009-repository-layout.md) | Gateway entrypoint and policy engine stay inside `apps/api` for 1.0 |

An ADR is superseded by editing its status and linking the replacement; old
records are not deleted.
