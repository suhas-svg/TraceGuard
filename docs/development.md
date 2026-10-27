# Development

Requires Node 22, Python 3.10+, Docker with compose, and psql.

```bash
cp .env.example .env
docker compose up -d postgres
for f in apps/api/migrations/*.sql; do psql "$DATABASE_URL" -f "$f"; done
pnpm install --ignore-scripts
```

Run each process in its own shell:

```bash
# API on :8090
DATABASE_URL=... API_KEY=... PORT=8090 DASHBOARD_ORIGIN=http://localhost:5173 \
  node apps/api/dist/index.js
# gateway on :8091 (approval control listener on :8093)
DATABASE_URL=... API_KEY=... APPROVER_KEY=... GATEWAY_PORT=8091 \
  GATEWAY_CONTROL_PORT=8093 \
  APPROVAL_TTL_SECONDS=300 ALLOW_PRIVATE_UPSTREAMS=true \
  node apps/api/dist/gateway.js
# mock tools on :8092
node examples/mock-tools/server.mjs
# dashboard on :5173
pnpm --filter @traceguard/web preview --port 5173
```

Build the whole workspace with `pnpm build`, or one package with
`pnpm --filter <package-name> build`. Tests run per workspace:
`pnpm --filter @traceguard/api test`, `pnpm --filter @traceguard/web test`,
and so on; `pnpm test` runs every workspace suite. Integration tests need a
database with all migrations applied and default to the dev one.

Cross-cutting gates live at the repo root: `pnpm test:secrets` scans every
tracked file for credential shapes, `pnpm test:faults` boots the API and
the gateway against a dead database and requires fail-closed answers (build
`apps/api` first), and `pnpm test:oauth` starts a generated RS256
issuer/JWKS, boots both apps in production OAuth mode, and proves static keys
are refused while OAuth tokens work. All three run in CI.

Do not source `.env` before running the suites: it exports `API_KEY` and
friends, which shadow the test defaults that `tests/setup.ts` installs with
`??=` (every request then 401s). Pass only `DATABASE_URL` — pointing at a
separate, disposable database — and leave the rest unset. `tests/e2e` is the
exception: it sets its own environment and recreates its own database.

The gateway enforces only signed policy: bring a project up with
`pnpm policy:keygen`, `pnpm policy:trust -- --workspace default`, and
`pnpm policy:publish -- --workspace default --project default` (repeat the
publish after every rule, server, or reviewed-pin change). The signing key stays in
`./policy-keys/` on your machine — never in a container. The e2e suite runs
its own publish against its own key and `GATEWAY_STATE_DIR` under
`test-results/`, so it cannot collide with your dev anchor.

One branch per phase, squash-merge through a PR, keep main green.
