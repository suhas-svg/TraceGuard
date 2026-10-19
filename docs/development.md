# Development

Requires Node 22, Python 3.10+, Docker with compose, and psql.

```bash
cp .env.example .env
docker compose up -d postgres
for f in apps/api/migrations/*.sql; do psql "$DATABASE_URL" -f "$f"; done
npm install --ignore-scripts
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
node node_modules/vite/bin/vite.js preview apps/web --port 5173
```

Build with `./node_modules/.bin/tsc -p <package>/tsconfig.json` per
package, or `npm run build --workspace=@traceguard/web` for the bundle
(run the tsc and vite steps directly if npm lifecycle scripts are blocked
on your machine). Tests: `../../node_modules/.bin/vitest run` from
`apps/api`, `./node_modules/.bin/vitest run --root apps/web` from the repo
root. Integration tests need a database with all migrations applied and
default to the dev one.

Do not source `.env` before running the suites: it exports `API_KEY` and
friends, which shadow the test defaults that `tests/setup.ts` installs with
`??=` (every request then 401s). Pass only `DATABASE_URL` — pointing at a
separate, disposable database — and leave the rest unset. `tests/e2e` is the
exception: it sets its own environment and recreates its own database.

The gateway enforces only signed policy: bring a workspace up with
`npm run policy:keygen`, `npm run policy:trust -- --workspace default`, and
`npm run policy:publish -- --workspace default` (repeat the publish after
every rule, server, or reviewed-pin change). The signing key stays in
`./policy-keys/` on your machine — never in a container. The e2e suite runs
its own publish against its own key and `GATEWAY_STATE_DIR` under
`test-results/`, so it cannot collide with your dev anchor.

One branch per phase, squash-merge through a PR, keep main green.
