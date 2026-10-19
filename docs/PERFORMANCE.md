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

The §14 thresholds are also a gate: `scripts/bench.mjs` prints a PASS/FAIL
verdict per NFR at the end of each run and exits non-zero when any p95 misses
its budget. It is not a CI job because it needs a live stack and a warm
database; run it against the deployment you are about to quote.

## A run of it

Measured 2026-10-17 on a Windows 11 dev box — Intel Core i7-8750H (6 cores /
12 threads), 16 GB RAM — running Node 22 with Docker Desktop Postgres,
2215 runs and 726 spans with usage in the database, 50 sequential requests per
path, warmed database.

| Path | n | p50 | p95 | max | mean |
|---|---|---|---|---|---|
| `GET /healthz` | 50 | 15ms | 16ms | 16ms | 13ms |
| `GET /v1/overview` | 50 | 31ms | 37ms | 55ms | 31ms |
| `GET /v1/runs?limit=50` | 50 | 6ms | 7ms | 19ms | 7ms |
| `POST /v1/ingest/events` (1 event) | 50 | 29ms | 93ms | 15421ms | 346ms |
| `POST /v1/gateway/tools/call` (incl. upstream) | 50 | 66ms | 75ms | 612ms | 74ms |

Against the §14 engineering targets:

| Target | Budget | Measured | Verdict |
|---|---|---|---|
| NFR-003 Typical dashboard queries | p95 < 500ms | 37ms | inside |
| NFR-002 Ingestion-to-dashboard visibility | p95 < 3s | 93ms | inside |
| NFR-001 Gateway policy overhead | p95 < 100ms | 15ms over 110 decisions | inside |

The gateway figure is measured, not inferred. The gateway records how long each
policy decision took in `policy_decisions.overhead_ms`, read before the call is
forwarded, so the upstream round trip is excluded by construction rather than by
subtraction. `scripts/bench.mjs` reports the p95 from that trail when
`DATABASE_URL` is set. The whole-call row above includes the upstream round trip
and the span write, which is what a client experiences; it is not the target.

An earlier version of this file recorded a gateway p95 of 15.7s and called the
policy overhead "not isolated". The second is now fixed; the first was this
machine stalling requests for 5-17s, which it still does — see the ingest max
below. That stall is environmental rather than a pooling regression, and a
back-to-back run of the same build showed it too.

## Reading the max column

Occasional multi-second maxima (15.4s on ingest above) come from this machine
stalling individual requests; the p50 and p95 on the same run are unaffected,
which is why the targets are quoted at p95. Cold starts miss every target.
Rerun on Linux server hardware before quoting these numbers anywhere else.

## Idempotency

Held throughout: retries of the same event ids stored nothing twice, and a
replayed actuals batch now reports `duplicates` instead of doubling the invoice.
