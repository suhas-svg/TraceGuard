-- 031_role_grant_spans.sql
-- §13.4 least privilege: the API path is the only runtime writer of spans —
-- events ingest and OTLP traces both INSERT here, and the OTLP route flips
-- parent_state when a late parent arrives. Grant exactly that: SELECT for
-- reads, INSERT for ingest, UPDATE for the parent bookkeeping. DELETE stays
-- with retention_job; the API can never erase traces.
GRANT SELECT, INSERT, UPDATE ON spans TO api_runtime;
