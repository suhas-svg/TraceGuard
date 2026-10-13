# Performance notes

Measured 2026-10-13 on a Windows dev box (Docker Desktop Postgres,
Node 22, small database with hundreds of rows). curl client timing,
sequential requests, warmed database except where noted.

| Path | n | p50 | p95 | max |
|---|---|---|---|---|
| Ingest 1 event | 50 | 250ms | 1.28s | 17.2s |
| Gateway allow call end to end | 20 | 259ms | 1.45s | 4.1s |

Against the engineering targets: ingestion-to-API p95 of 1.28s is inside
the 3s visibility target on a warm database. Gateway p95 of 1.45s is not
the sub-100ms warmed decision target, because each call opens a fresh MCP
handshake to the upstream. Connection reuse is the known fix and is not
implemented yet.

The max values come from this machine stalling the first database write
after idle for 5 to 17 seconds. Cold starts miss every target here. Rerun
these numbers on Linux server hardware before quoting them anywhere else.
Idempotency held throughout: retries of the same event ids stored nothing
twice.
