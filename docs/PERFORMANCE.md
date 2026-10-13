# Performance notes

Measured 2026-10-13 on a Windows dev box (Docker Desktop Postgres,
Node 22, small database with hundreds of rows). curl client timing,
sequential requests, warmed database except where noted.

| Path | n | p50 | p95 | max |
|---|---|---|---|---|
| Ingest 1 event | 50 | 250ms | 1.28s | 17.2s |
| Gateway allow call, fresh handshake per call | 20 | 259ms | 1.45s | 4.1s |
| Gateway allow call, pooled upstream client | 60 | 269ms | 15.7s | 15.9s |
| Gateway allow call, old build re-run | 59 | 279ms | n/a | 16.3s |

Against the engineering targets: ingestion-to-API p95 of 1.28s is inside
the 3s visibility target on a warm database.

The max values come from this machine stalling some calls for 5 to 17
seconds. A back-to-back run of the old build showed the same stalls, so
they are environmental, not from pooling. Pooling removes the per-call
MCP handshake (2ms reused versus up to 99ms fresh in isolation) and pays
off against remote upstreams; locally Postgres roundtrips dominate both
builds. Cold starts miss every target here. Rerun
these numbers on Linux server hardware before quoting them anywhere else.
Idempotency held throughout: retries of the same event ids stored nothing
twice.
