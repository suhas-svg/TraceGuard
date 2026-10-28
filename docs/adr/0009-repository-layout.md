# ADR-0009: Repository layout keeps the gateway entrypoint and policy engine inside `apps/api`

- Status: Accepted
- Date: 2026-10-28
- Deciders: TraceGuard maintainers
- Related: spec §5.4, §6; `docs/architecture.md`, `docs/spec-conformance.md`,
  `docker-compose.yml`, `apps/api/Dockerfile`, `infra/k8s/`

## Context

The specification's §5.4 repository tree is illustrative: it shows `apps/api`
and `apps/gateway` as separate applications, `packages/policy-engine` and
`packages/contracts` as packages, and read and write mock upstreams as separate
`examples/`. This repository diverges in three places:

1. The gateway entrypoint is `apps/api/src/gateway.ts`, built to
   `apps/api/dist/gateway.js`. It is a separate process in a separate container
   (`docker-compose.yml` service `gateway`, command `node
   apps/api/dist/gateway.js`), on its own ports (8091 agent-facing, 8093
   control), with its own `gateway_runtime` database role and the `agent_edge`
   (agent side) and `tools` (upstream side) network legs. It shares the
   `traceguard-api` image so the two services cannot drift between builds.
2. Policy evaluation is `apps/api/src/policy.ts` (pure: no database or network
   access; it imports `@traceguard/canonical-json`, `@traceguard/schemas`, and
   `./schema-check`) plus `policy-bundle.ts` (database-backed loading used by
   the gateway). Both are exercised directly by `apps/api/tests/policy.test.ts`,
   `policy-bundle.test.ts`, and `regex-bound.test.ts`.
3. `examples/mock-tools/server.mjs` is one upstream that exposes both read and
   write tools, including the reference path-confinement executor. It is the
   upstream used by compose, the e2e suite, the security bypass test, and the
   demo.

The spec's tree is a recommendation about where code lives, not a control. The
trust boundary is enforced by the network topology (§6, ADR-0006), the database
roles and procedures (ADR-0004), separate listeners, and separate credentials —
none of which depend on a directory name. The independent audit nevertheless
recorded the deviation, so it needs an explicit decision rather than an
implicit one.

## Decision

Keep the current layout for the 1.0 release and record it as an accepted
deviation from §5.4:

- The gateway remains a second entrypoint in `apps/api` with a separate
  container, process, ports, database role, and network position. It is not
  merged into the API process.
- Policy evaluation remains a pure module inside `apps/api/src` rather than a
  workspace package.
- `examples/mock-tools` remains a combined read/write upstream.
- `packages/schemas` keeps its name instead of becoming `packages/contracts`.

## Revisit triggers

Extract `apps/gateway` and/or `packages/policy-engine` when any of these
becomes true:

- the gateway needs an independent release cadence or a different runtime
  image from the API;
- policy evaluation is reused outside the API and gateway (for example by an
  external policy simulator);
- a deployment needs distinct upstream credentials per read and write demo
  server, which the combined `mock-tools` fixture cannot express.

Any extraction is mechanical but touches the image build, the compose command,
the k8s manifests, CI, and the tests, so it ships as its own change with the
full verification matrix.

## Consequences

- `docs/spec-conformance.md` lists the §5.4 tree as an accepted deviation with
  this ADR as the rationale, so an auditor does not read it as an oversight.
- No security claim rests on the directory layout; the §6 network guarantees
  and the ADR-0004 role matrix are the evidence.
- Contributors must not move the gateway into the API process without
  superseding this ADR: the separate container and role are the boundary, and
  `apps/api/src/gateway.ts` is only where the code lives.

## Alternatives considered

- **Extract `apps/gateway` and `packages/policy-engine` now.** Rejected for
  1.0: it is a large mechanical change immediately before release, with no
  change to the runtime trust boundary, and every step would need the full
  database and e2e matrix. The revisit triggers above keep it on the table.
- **Move the gateway into the API process to match the single `apps/api`
  entry.** Rejected: it would collapse the network and credential separation
  that §6 and ADR-0006 require.
- **Leave the deviation undocumented.** Rejected: the audit already flags it,
  and §5.4 conformance claims would be ambiguous.
