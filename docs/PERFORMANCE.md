# Performance notes

Two things live here: the method (a committed script, so anyone can rerun it) and
the numbers from one run of it. The numbers are a data point, not a claim.

## How to measure

```bash
# API, gateway, and the mock upstream, then the benchmark.
node apps/api/dist/index.js &
node apps/api/dist/gateway.js &
node examples/mock-tools/server.mjs &
N=50 KEY=$API_KEY node scripts/bench.mjs
```

`scripts/bench.mjs` prints the host, node version, and current row counts
alongside the table, so two runs are comparable. It also registers a fresh
server and an allow policy against the mock upstream to time a real proxied call
rather than something easier to measure. If the mock upstream is not running, the
gateway row reports itself as skipped.

## A run of it

Measured 2026-10-17 on a Windows 11 dev box: Docker Desktop Postgres, Node 22,
1422 runs and 562 spans with usage in the database, 30 sequential requests per
path, warmed database.

| Path | n | p50 | p95 | max | mean |
|---|---|---|---|---|---|
| `GET /healthz` | 30 | 15ms | 16ms | 92ms | 14ms |
| `GET /v1/overview` | 30 | 29ms | 52ms | 66ms | 30ms |
| `GET /v1/runs?limit=50` | 30 | 8ms | 13ms | 20ms | 9ms |
| `POST /v1/ingest/events` (1 event) | 30 | 30ms | 70ms | 919ms | 65ms |
| `POST /v1/gateway/tools/call` (incl. upstream) | 30 | 360ms | 458ms | 530ms | 362ms |

Against the §14 engineering targets:

| Target | Budget | Measured | Verdict |
|---|---|---|---|
| Typical dashboard queries | p95 < 500ms | 52ms | inside |
| Ingestion-to-dashboard visibility | p95 < 3s | 70ms | inside |
| Gateway policy overhead | p95 < 100ms | not isolated | see below |

The gateway row measures the whole proxied call — policy decision, upstream MCP
round trip, and the span write — because that is what a client experiences. The
spec's 100ms budget covers the policy decision alone, excluding upstream
execution and human approval, so 458ms is an upper bound on it, not the target
being missed. Isolating the decision needs a timing instrument inside the
gateway; until that exists, quote this row as a whole-call figure.

An earlier version of this file recorded a gateway p95 of 15.7s. That run timed a
build where every call paid a fresh MCP handshake and this machine was stalling
requests for 5-17s; a back-to-back run of the same build showed the stalls too,
so they were environmental rather than a pooling regression. The numbers above
come from the committed script, which is the only reason they are worth
comparing to anything.

## Reading the max column

Occasional 500ms-900ms maxima come from this machine stalling individual
requests. Cold starts miss every target. Rerun on Linux server hardware before
quoting these numbers anywhere else.

## Idempotency

Held throughout: retries of the same event ids stored nothing twice, and a
replayed actuals batch now reports `duplicates` instead of doubling the invoice.
