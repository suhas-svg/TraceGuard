#!/usr/bin/env bash
# Brings up the four processes the live walkthrough needs, runs it, tears them
# down. Nothing is seeded into a fixture: the demo talks to the real API, the
# real gateway, the real dashboard bundle, and the real database.
#
#   bash scripts/demo-fixes.sh
#
# Overrides: BASE_PORT (8090), GW_PORT (8091), MOCK_PORT (8092), WEB_PORT (5173),
# UPSTREAM_TIMEOUT_MS (3000 here so the hung-upstream check finishes quickly).
set -u

cd "$(dirname "$0")/.." || exit 1
set -a
[ -f .env ] && . ./.env
set +a

export PORT="${BASE_PORT:-8090}"
export GATEWAY_PORT="${GW_PORT:-8091}"
export MOCK_TOOLS_PORT="${MOCK_PORT:-8092}"
export API_KEY="${API_KEY:-test_key}"
export APPROVER_KEY="${APPROVER_KEY:-test_approver}"
export APPROVAL_ARGS_KEY="${APPROVAL_ARGS_KEY:-abababababababababababababababababababababababababababababababab}"
export ALLOW_PRIVATE_UPSTREAMS=true
export UPSTREAM_TIMEOUT_MS="${UPSTREAM_TIMEOUT_MS:-3000}"

pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT

echo "starting api, gateway, mock tools, web preview..."
node apps/api/dist/index.js > /tmp/demo-api.log 2>&1 & pids+=($!)
node apps/api/dist/gateway.js > /tmp/demo-gw.log 2>&1 & pids+=($!)
node examples/mock-tools/server.mjs > /tmp/demo-mock.log 2>&1 & pids+=($!)
npm run preview --workspace apps/web -- --port "${WEB_PORT:-5173}" --strictPort \
  > /tmp/demo-web.log 2>&1 & pids+=($!)

wait_for() { # url, label, attempts
  for _ in $(seq 1 "$3"); do
    curl -fsS "$1" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  echo "  $2 did not come up (see /tmp/demo-*.log)"; return 1
}
ok=1
wait_for "http://localhost:$PORT/readyz" "api" 40 || ok=0
wait_for "http://localhost:$GATEWAY_PORT/healthz" "gateway" 40 || ok=0
wait_for "http://localhost:$MOCK_TOOLS_PORT/hits" "mock tools" 20 || ok=0
wait_for "http://localhost:${WEB_PORT:-5173}" "web" 40 || ok=0
[ "$ok" = 1 ] || exit 1

API="http://localhost:$PORT" \
GW="http://localhost:$GATEWAY_PORT" \
WEB="http://localhost:${WEB_PORT:-5173}" \
KEY="$API_KEY" APPROVER_KEY="$APPROVER_KEY" \
node scripts/demo-fixes.mjs
