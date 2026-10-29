-- 051: agent principals are non-human MCP callers and must never hold the
-- human approval or admin scopes. The API already rejects those values, but
-- the table is writable by api_runtime, so enforce the same boundary in
-- PostgreSQL as defense in depth.
--
-- Idempotent: normalize any legacy rows before installing the constraint.
BEGIN;

UPDATE agent_principals
   SET allowed_scopes = allowed_scopes - 'approve' - 'admin'
 WHERE allowed_scopes ?| ARRAY['approve', 'admin'];

ALTER TABLE agent_principals
  DROP CONSTRAINT IF EXISTS agent_principals_no_human_scopes;

ALTER TABLE agent_principals
  ADD CONSTRAINT agent_principals_no_human_scopes
  CHECK (allowed_scopes <@ '["gateway", "read", "ingest"]'::jsonb);

COMMIT;
