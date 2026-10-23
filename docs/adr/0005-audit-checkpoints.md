# ADR-0005: Externally anchored audit checkpoints before any pruning

- Status: Accepted
- Date: 2026-10-23
- Deciders: TraceGuard maintainers
- Related: spec §10.1–§10.3, FR-019; migrations `022`, `023`, `033`;
  `packages/audit-chain`, `scripts/audit-checkpoint.mts`

## Context

The audit chain is tamper-evident, not tamper-proof. A database owner can
rewrite rows and recompute hashes. Deletion of a prefix is indistinguishable
from corruption unless an independently held artifact anchors what was there.
Pruning therefore cannot be a normal API operation.

## Decision

- Each event hash covers the event id, per-workspace sequence, timestamp,
  actor, action/resource, result, policy version and matched rules, sanitized
  metadata, project attribution, and `previous_hash` (v3/v4 formats).
- A checkpoint is an Ed25519-signed statement over an exact prefix:
  `up_to_event_id`, `up_to_hash`, and per-workspace segment heads. The private
  key exists only on the operator host; the gateway holds only the public key
  for verification.
- `pnpm audit:checkpoint -- create` exports the segment, signs the artifact,
  and records the checkpoint. `prune` re-verifies the artifact, requires an
  external receipt (for example an object-store URI), and calls the
  `retention_job`-only prune function for the exact cutoff. The delete and the
  `audit.segment.pruned` event commit atomically.
- A chain whose first link is broken but is covered by a valid checkpoint
  reports `anchored`, not corrupt. Gaps after the checkpoint remain broken.

## Consequences

- Pruning is a two-party operational process: an operator creates and stores
  the artifact; a retention credential performs the delete.
- Losing the checkpoint private key stops new checkpoints but does not
  invalidate existing anchors. Key rotation follows the same trust-then-retire
  discipline as policy signing.
- The external artifact and its receipt are part of the recovery plan, not
  disposable logs.
- Verification must be run against an export before pruning; a failed check
  refuses the operation.

## Alternatives considered

- **Gateway-held checkpoint key.** Rejected: a gateway compromise could forge
  history.
- **Unsigned checkpoints.** Rejected: the database owner could replace them.
- **Normal retention delete of audit rows.** Rejected: destroys the evidence
  the retention policy is supposed to preserve.
- **No pruning ever.** Safe but operationally unbounded; the signed-checkpoint
  path exists so retention can be enabled deliberately.
