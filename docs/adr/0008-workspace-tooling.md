# ADR-0008: pnpm workspaces and a committed frozen lockfile

- Status: Accepted
- Date: 2026-10-23
- Deciders: TraceGuard maintainers
- Related: spec §5.2, §5.4, §20; `pnpm-workspace.yaml`, `pnpm-lock.yaml`,
  `.npmrc`, `package.json`, `.github/workflows/ci.yml`, Dockerfiles

## Context

The specification chooses pnpm workspaces for the monorepo and requires
`pnpm-workspace.yaml` plus a committed `pnpm-lock.yaml`. The repository grew on
npm workspaces with a `package-lock.json`. That works locally, but it does not
match the required toolchain, and npm's install layout differs from what a pnpm
Docker build and CI gate need.

The Compose reference adds a constraint: `mock-tools` runs from a bind mount of
`examples/mock-tools` and mounts the host `node_modules` read-only. It resolves
`@modelcontextprotocol/sdk` and `zod` from the repository root. A default pnpm
install with the isolated linker keeps those packages under
`apps/api/node_modules` (or the virtual store), so the mounted upstream would
no longer resolve its imports.

## Decision

- The workspace is managed by **pnpm 9.15.4**, pinned in the root
  `packageManager` field. CI and the Docker builds enable it through corepack;
  contributors install it with corepack or `npm install -g pnpm@9.15.4`.
- `pnpm-workspace.yaml` lists the ten workspace projects. Internal dependencies
  use the `workspace:*` protocol so a package cannot accidentally resolve a
  published `@traceguard/*` artifact.
- `pnpm-lock.yaml` is committed. `package-lock.json` is removed. Every CI job
  installs with `pnpm install --frozen-lockfile --ignore-scripts`; a lockfile
  that drifts from a manifest fails the build.
- `.npmrc` sets `node-linker=hoisted`, matching the npm-style tree the Compose
  `mock-tools` mount expects, and enables workspace linking. This is a
  deliberate compatibility setting, not a claim that isolation is unnecessary.
- Docker images perform filtered installs (`--filter @traceguard/api...`,
  `--filter @traceguard/web...`) after copying every workspace manifest, so the
  frozen lockfile resolves exactly as it does in the repository.
- Root scripts use pnpm (`pnpm -r build`, `pnpm -r --if-present test`,
  `pnpm exec ...`). The dependency/license audit reads the installed pnpm tree
  through `pnpm licenses list --json --prod` instead of parsing an npm lockfile.

## Consequences

- A clean clone, CI, and the images all use one package manager and one
  lockfile. Documentation and operator commands use `pnpm`, not `npm`.
- Adding or renaming a workspace requires a matching `pnpm-workspace.yaml`
  entry and a refreshed lockfile. A stale lockfile is a hard CI failure.
- The hoisted layout makes the Compose demo work without a second install
  inside `mock-tools`. If that mount is ever replaced by a built image, the
  isolated linker can be reconsidered, but it is not required for correctness.
- `--ignore-scripts` is the default in CI. A dependency that genuinely needs a
  lifecycle script must be reviewed and allowlisted rather than silently
  executed during install.
- The SBOM and license gate describe the packages actually installed, so a
  missing or non-allowlisted production license fails the build.

## Alternatives considered

- **Keep npm workspaces.** Rejected: directly contradicts the specified
  toolchain and the repository layout requirement.
- **pnpm's default isolated linker.** Rejected for now: it breaks the
  read-only `node_modules` mount used by the Compose mock upstream.
- **Run `pnpm install` inside every container at start.** Rejected: slow,
  network-dependent at runtime, and it hides dependency drift from the image
  build.
- **Commit both lockfiles.** Rejected: two sources of truth invite installs
  that differ between local and CI runs.
