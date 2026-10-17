#!/usr/bin/env bash
# Runs the whole platform locally from the built output and stays up until
# interrupted, for looking at the dashboard or driving a live demo.
#
#   bash scripts/dev-stack.sh          # then open http://localhost:5173
#   bash scripts/dev-stack.sh --stop   # stop everything it started
#
# Ports and keys come from .env, whose defaults are the ones the web bundle is
# built against, so the dashboard needs no configuration to work.
set -u

cd "$(dirname "$0")/.." || exit 1
set -a
[ -f .env ] && . ./.env
set +a

export PORT="${PORT:-8090}"
export GATEWAY_PORT="${GATEWAY_PORT:-8091}"
export MOCK_TOOLS_PORT="${MOCK_TOOLS_PORT:-8092}"
export ALLOW_PRIVATE_UPSTREAMS=true

# The dashboard bundle is built against these two, so a mismatch here shows up
# as an empty dashboard rather than an error.
[ "$PORT" = "8090" ] || echo "warning: PORT=$PORT but the dashboard calls 8090 (see .env)"
[ "$GATEWAY_PORT" = "8091" ] || echo "warning: GATEWAY_PORT=$GATEWAY_PORT but the dashboard calls 8091"

PORTS="$PORT $GATEWAY_PORT $MOCK_TOOLS_PORT 5173"

# A force-kill of this script skips the trap below and leaves all four children
# running, so there is a way to stop them by the port they hold.
if [ "${1:-}" = "--stop" ]; then
  if command -v powershell.exe > /dev/null 2>&1; then
    powershell.exe -NoProfile -Command \
      "Get-NetTCPConnection -State Listen -LocalPort @($(echo $PORTS | tr ' ' ',')) -ErrorAction SilentlyContinue |
       Select-Object -ExpandProperty OwningProcess -Unique |
       ForEach-Object { Stop-Process -Id \$_ -Force -ErrorAction SilentlyContinue }"
  else
    for p in $PORTS; do lsof -ti "tcp:$p" 2>/dev/null | xargs -r kill -9; done
  fi
  echo "stopped anything listening on $PORTS"
  exit 0
fi

pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT INT TERM

node apps/api/dist/index.js > /tmp/stack-api.log 2>&1 & pids+=($!)
node apps/api/dist/gateway.js > /tmp/stack-gw.log 2>&1 & pids+=($!)
node examples/mock-tools/server.mjs > /tmp/stack-mock.log 2>&1 & pids+=($!)
npm run preview --workspace apps/web -- --port 5173 --strictPort \
  > /tmp/stack-web.log 2>&1 & pids+=($!)

ready=1
for _ in $(seq 1 40); do
  curl -fsS "http://localhost:$PORT/readyz" >/dev/null 2>&1 &&
    curl -fsS "http://localhost:5173" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -fsS "http://localhost:$PORT/readyz" >/dev/null 2>&1 || ready=0
curl -fsS "http://localhost:$GATEWAY_PORT/healthz" >/dev/null 2>&1 || ready=0
curl -fsS "http://localhost:$MOCK_TOOLS_PORT/hits" >/dev/null 2>&1 || ready=0
curl -fsS "http://localhost:5173" >/dev/null 2>&1 || ready=0

if [ "$ready" = 1 ]; then
  echo "up: dashboard http://localhost:5173  api http://localhost:$PORT  gateway http://localhost:$GATEWAY_PORT"
else
  echo "one or more processes failed to start; see /tmp/stack-*.log"
fi

# Hold the processes open. Ctrl-C, or killing this script, stops all four.
wait
