# ADR-0007: TraceGuard is a provisional name pending a clearance search

- Status: Accepted (risk accepted; release gate remains open)
- Date: 2026-10-23
- Deciders: TraceGuard maintainers and product owner
- Related: spec §19 Phase 0; `docs/independent-spec-audit-2026-10-21.md`

## Context

The specification warns that "TraceGuard" may collide with existing products
and asks for a repository/package/domain/trademark search before public
branding. The independent audit also records the collision as unresolved and
notes that the repository accepts the risk as a user decision. The codebase,
package scope (`@traceguard/*`), container names, environment variables, and
documentation all use the name today.

## Decision

Keep **TraceGuard** as the provisional internal project name. Do not present it
as a cleared trademark or reserve public brand assets under it. Before any
public release, a maintainer must record a name-clearance search covering at
least:

- trademark registers in the target jurisdictions;
- the package scope and npm registry;
- the primary domain and relevant social handles;
- container/image names used in published artifacts.

If the search finds a conflict, the rename is a deliberate migration that
updates the package scope, image names, environment variables, documentation,
and deployment manifests together. A partial rename is worse than a documented
provisional name.

## Consequences

- Public branding and marketing spend wait for the search; engineering can
  continue under the provisional name.
- The name remains a known release-gate item, not a silently accepted legal
  conclusion.
- A future rename has a known blast radius and must ship with a compatibility
  note for operators.

## Alternatives considered

- **Rename immediately.** Rejected for now: high churn across packages, images,
  environment variables, and tests without a search result to justify a
  particular replacement.
- **Treat the name as cleared without a search.** Rejected: the specification
  explicitly warns against it.
- **Use a generic placeholder everywhere.** Not necessary for an internal
  build; the provisional-name record is sufficient until release planning.
