# ADR-0003: Operator-signed policy bundles with an out-of-process private key

- Status: Accepted
- Date: 2026-10-23
- Deciders: TraceGuard maintainers
- Related: spec §8, §13.3, FR-018; `packages/policy-signing`,
  `tools/policy-publisher`, migrations `020`, `036`, `039`, `042`, `045`

## Context

The gateway must enforce the policy an operator reviewed, not a row an API
process or a database administrator could rewrite. The API needs to edit
drafts; the gateway needs to read the active, approved policy. Those two
capabilities must not imply the ability to sign a new policy.

## Decision

The operator publishes with `tools/policy-publisher`, which:

1. reads policy drafts, server configuration, and approved tool pins;
2. builds a canonical JSON bundle (`@traceguard/canonical-json`);
3. signs the RFC 8785 canonical bytes with an Ed25519 key that never enters the
   API or gateway containers;
4. writes an immutable `policy_versions` row with the signature, content hash,
   signing key id, and previous-version hash;
5. activates the version for one project in `active_config`;
6. activates approved pins and stamps the project's server rows with the same
   signed bundle version in the same transaction.

The gateway verifies the signature against a trusted `policy_signing_keys` row
and validates the bundle schema on every load. It fails closed on a missing,
invalid, stale, or mismatched bundle. A v2 bundle carries pin identity plus each
server's `secret_ref` reference (never the secret value). Trust keys are
workspace-scoped by design; versions and active pointers are project-scoped.

## Consequences

- A database writer without the private key cannot mint an enforceable policy.
- Publishing is an explicit operator step. Editing a draft has no runtime
  effect until a successful publish.
- Key rotation is trust-then-retire: trust the new public key, publish with it,
  then retire the old key. Losing every trusted private key requires a new
  trust bootstrap and a new publication.
- The gateway must reject legacy or unknown bundle fields rather than ignore
  them.
- Tests use the real publisher (`apps/api/tests/policy-helper.ts`) so the
  signature path is exercised, not bypassed.

## Alternatives considered

- **Shared HMAC secret in the API and gateway.** Rejected: any runtime
  compromise could sign policy.
- **Unsigned policy rows with role checks only.** Rejected: a schema owner or
  role bug changes enforcement silently.
- **Runtime policy editor with immediate effect.** Rejected: no review point,
  no immutable version, no signature.
