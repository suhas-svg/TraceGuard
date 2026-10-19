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
export GATEWAY_CONTROL_PORT="${GATEWAY_CONTROL_PORT:-8093}"
export MOCK_TOOLS_PORT="${MOCK_TOOLS_PORT:-8092}"
export ALLOW_PRIVATE_UPSTREAMS=true

# The dashboard bundle is built against these two, so a mismatch here shows up
# as an empty dashboard rather than an error.
[ "$PORT" = "8090" ] || echo "warning: PORT=$PORT but the dashboard calls 8090 (see .env)"
[ "$GATEWAY_PORT" = "8091" ] || echo "warning: GATEWAY_PORT=$GATEWAY_PORT but the dashboard calls 8091"

PORTS="$PORT $GATEWAY_PORT $MOCK_TOOLS_PORT 5173"
PIDFILE="${TMPDIR:-/tmp}/traceguard-dev-stack.pids"

# A force-kill of this script skips the trap below and leaves all four children
# running, so the pids are recorded on start and stopped by name. Resolving
# listeners by port does not work here: Get-NetTCPConnection reports nothing for
# these processes, so a port-based stop succeeds while changing nothing.
if [ "${1:-}" = "--stop" ]; then
  if [ ! -f "$PIDFILE" ]; then
    echo "no pid file at $PIDFILE — nothing recorded to stop"
    exit 0
  fi
  while read -r pid; do
    [ -n "$pid" ] || continue
    if kill "$pid" 2>/dev/null; then
      echo "stopped $pid"
    elif command -v powershell.exe > /dev/null 2>&1; then
      powershell.exe -NoProfile -Command \
        "Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue" 2>/dev/null &&
        echo "stopped $pid (forced)" || echo "already gone: $pid"
    else
      echo "already gone: $pid"
    fi
  done < "$PIDFILE"
  rm -f "$PIDFILE"
  exit 0
fi

pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done; rm -f "$PIDFILE"; }
trap cleanup EXIT INT TERM

node apps/api/dist/index.js > /tmp/stack-api.log 2>&1 & pids+=($!)
node apps/api/dist/gateway.js > /tmp/stack-gw.log 2>&1 & pids+=($!)
node examples/mock-tools/server.mjs > /tmp/stack-mock.log 2>&1 & pids+=($!)
# Started directly rather than through `npm run preview`: npm spawns vite as a
# child, so the recorded pid is the wrapper and stopping it orphans the server.
(cd apps/web && exec node node_modules/vite/bin/vite.js preview --port 5173 --strictPort) \
  > /tmp/stack-web.log 2>&1 & pids+=($!)
printf '%s\n' "${pids[@]}" > "$PIDFILE"

ready=1
for _ in $(seq 1 40); do
  curl -fsS "http://localhost:$PORT/readyz" >/dev/null 2>&1 &&
    curl -fsS "http://localhost:5173" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -fsS "http://localhost:$PORT/readyz" >/dev/null 2>&1 || ready=0
curl -fsS "http://localhost:$GATEWAY_PORT/healthz" >/dev/null 2>&1 || ready=0
curl -fsS "http://localhost:$GATEWAY_CONTROL_PORT/healthz" >/dev/null 2>&1 || ready=0
curl -fsS "http://localhost:$MOCK_TOOLS_PORT/hits" >/dev/null 2>&1 || ready=0
curl -fsS "http://localhost:5173" >/dev/null 2>&1 || ready=0

if [ "$ready" = 1 ]; then
  echo "up: dashboard http://localhost:5173  api http://localhost:$PORT  gateway http://localhost:$GATEWAY_PORT  approval control http://localhost:$GATEWAY_CONTROL_PORT"
else
  echo "one or more processes failed to start; see /tmp/stack-*.log"
fi

# Hold the processes open. Ctrl-C, or killing this script, stops all four.
wait
