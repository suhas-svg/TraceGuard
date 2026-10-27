# Dependencies and licenses

TraceGuard ships under Apache-2.0 (see `LICENSE` and `NOTICE`). Third-party
dependencies are pinned in `pnpm-lock.yaml`; CI installs with
`pnpm install --frozen-lockfile`, so a lockfile that disagrees with a
`package.json` fails the build instead of silently resolving a different tree.

## Review commands

| Command | What it does |
| --- | --- |
| `pnpm install --frozen-lockfile --ignore-scripts` | Reproducible install from the pinned lockfile. |
| `pnpm run deps:check` | Reads the installed pnpm tree, classifies every package as production or development, and checks its SPDX license against the allowlist below. Production violations exit non-zero; development-only warnings do not. |
| `pnpm run deps:sbom` | Writes a CycloneDX 1.5 SBOM to `sbom.cdx.json` (gitignored, uploaded by CI). |
| `pnpm run deps:advisories` | Runs `pnpm audit --prod --audit-level high` behind `scripts/advisory-audit.mjs`, an explicit, reviewable allowlist for advisories we have accepted with a reason and a revisit condition. Fails on any high or critical advisory that is not on the list. |

The license checker is `scripts/dependency-audit.mjs`. It evaluates SPDX
expressions conservatively: an `OR` branch passes when at least one side is
allowed (the distributor may choose that side), and an `AND` branch passes only
when every side is allowed. A package with no license field is a production
violation.

## Allowlist

Permissive licenses accepted for shipped dependencies:

`0BSD`, `Apache-2.0`, `Artistic-2.0`, `BSD`, `BSD-2-Clause`, `BSD-3-Clause`,
`BlueOak-1.0.0`, `CC0-1.0`, `ISC`, `MIT`, `MIT-0`, `MPL-2.0`, `Python-2.0`,
`Unlicense`, `WTFPL`, `Zlib`.

`MPL-2.0` is allowed for unmodified dependencies (file-level copyleft). Do not
vendor or modify an MPL-covered package without recording the change here.

Rejected markers include AGPL, GPL, SSPL, BUSL, CC-BY-NC, the Commons Clause,
`UNLICENSED`, and proprietary terms. `CC-BY-4.0` data (for example the
`caniuse-lite` browser-support tables) appears only in the development tree and
is not distributed.

Adding a license to the allowlist is a deliberate review decision: update this
file with the reason, then change `ALLOWED` in `scripts/dependency-audit.mjs`.

## CI gates

The `build-and-test` job runs, after
`pnpm install --frozen-lockfile --ignore-scripts`:

1. `node scripts/dependency-audit.mjs --sbom sbom.cdx.json`
2. `node scripts/advisory-audit.mjs`

and uploads `sbom.cdx.json` as a build artifact. These are folded into an
existing required check rather than a new job, so branch protection stays on the
seven established checks.

## Automation

`.github/dependabot.yml` opens weekly pull requests for npm and GitHub Actions
updates. Dependabot reads the pnpm lockfile through the npm ecosystem. Minor and
patch npm updates are grouped into one PR; major updates stay separate. Every
update runs the same CI gates, including the license check, the advisory
gate, the full test suite, and the Playwright e2e run.

Dependabot PRs are reviewed like any other change: check the changelog for
license changes, confirm the SBOM diff, and merge only when every required check
is green.

## Current snapshot (2026-10-23)

`pnpm run deps:check` against the installed workspace:

```
Scanned 369 packages from the installed pnpm workspace
  production: 159
  development: 210
Production licenses:
   140  MIT
    11  ISC
     6  BSD-3-Clause
     1  Apache-2.0
     1  BSD-2-Clause

Development warnings (not shipped): 1
  caniuse-lite@1.0.30001819 — CC-BY-4.0 — not-in-allowlist
```

`pnpm run deps:advisories` reports **1 accepted, 0 blocking** at this
revision:

```
accepted GHSA-mrhx-c7xc-m3w5 zod
  reason:  memory exhaustion while validating oversized constrained
           collections; every zod-validated request body is size-capped
           before parsing (Fastify bodyLimit, otlpLimits().maxBodyBytes on
           /v1/traces) and every array schema carries an explicit .max()
           bound, so no unbounded collection reaches zod
  revisit: migrate the workspace to zod >= 4.6.6;
           @modelcontextprotocol/sdk >= 1.32.2 already accepts zod 4
           as a peer
```

The advisory has no patched 3.x release, so the time-boxed exception is the
only option short of a zod 4 migration. Re-run both commands when the lockfile
changes; the snapshot here is evidence for the review, not a substitute for
the gates.
