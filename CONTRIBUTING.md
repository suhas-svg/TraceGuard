# Contributing

One branch per phase, squash-merge through a PR, keep main green. The
rules below exist because this project's product *is* its security
boundary; a change that weakens a denial is a change that fails review
regardless of what it adds.

## Before you open a PR

Run the suites that match what you touched; a PR that changes enforcement
code is expected to show all of them green.

```bash
npm install
npm test                                  # unit tests, all workspaces
npm run test:security                     # container bypass test (needs the compose stack)
npm run test:e2e                          # Playwright scenarios (recreates its own database)
python infra/k8s/check.py                 # Kubernetes manifests
node scripts/bench.mjs                    # performance table (record results in docs/PERFORMANCE.md)
```

Python SDK: `pip install "./sdks/python[dev]" && python -m pytest sdks/python`.
Integration tests need a database with all migrations applied, and a
disposable one at that; see `docs/development.md` for the exact commands
and the `.env` gotcha (do not source `.env` before the suites).

## Tests are part of the change

- New behavior needs a test. A behavior that can deny, approve, quarantine,
  sign, verify, redact, or delete needs a test that proves the *denial*
  case as well: the call that must not reach the upstream, the role that
  must not be able to write, the token that must not authenticate.
- Security-relevant fixes should extend `tests/security/` or the
  corresponding integration suite, not just unit tests.
- Fault-injection behavior (gateway fails closed, telemetry fails open and
  non-blocking, budget wrapper fails closed) is covered by dedicated tests;
  keep them passing or update them deliberately.

## Security-sensitive areas

Treat these as owned by the maintainer; changes get an explicit security
read in review, and reviewers should expect to justify each line:

- `apps/api/src/gateway.ts`, `mcp.ts`, `oauth.ts`, `upstream.ts` — the
  enforcement boundary: policy evaluation, approvals, credentials, SSRF
  validation.
- `apps/api/src/policy.ts`, `policy-bundle.ts`, `tools/policy-publisher/` —
  signing, verification, rollback/fork detection.
- `apps/api/src/seal.ts` — approval argument encryption.
- `apps/api/src/audit.ts`, `packages/audit-chain/`, `packages/canonical-json/` —
  the audit chain, checkpoints, canonical serialization.
- `apps/api/migrations/*.sql`, especially role grants: runtime roles must
  not gain direct `UPDATE`/`DELETE` on `audit_events`, signed policy
  versions, or active pins, and the API role must not gain
  approval-transition privileges.
- `apps/api/src/redact.ts`, `auth.ts`, `users.ts` — secrets handling and
  identity/scopes.

Rules of thumb for these files:

1. Fail closed on unknown, malformed, or missing trust inputs.
2. Never let the control API sign, activate, or transition what the
   gateway owns; the boundary is enforced in database privileges, not just
   code checks.
3. Never log tokens, arguments, or tool payloads.
4. New environment variables get documented in `docs/configuration.md`;
   security-relevant behavior changes get a line in `docs/security.md`
   and the threat model.

## Documentation

Behavior changes that surface in the UI, the deployment, or the security
story update the matching doc (`docs/architecture.md`, `docs/security.md`,
`docs/operations.md`, `docs/compatibility.md`, `docs/privacy.md`). Keep
`docs/compatibility.md` honest: it lists exactly what has been tested.

## License

By contributing you agree your contributions are licensed under
Apache-2.0 (see `LICENSE`).
