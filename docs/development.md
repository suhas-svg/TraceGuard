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
# gateway on :8091
DATABASE_URL=... API_KEY=... APPROVER_KEY=... GATEWAY_PORT=8091 \
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

The gateway enforces only signed policy: bring a workspace up with
`npm run policy:keygen`, `npm run policy:trust -- --workspace default`, and
`npm run policy:publish -- --workspace default` (repeat the publish after
every rule, server, or reviewed-pin change). The signing key stays in
`./policy-keys/` on your machine — never in a container. Add
`GATEWAY_STATE_DIR=test-results/e2e-gateway-state` when running the e2e
suite locally so its accepted-version anchor does not collide with your dev
one.

One branch per phase, squash-merge through a PR, keep main green.
