-- 021: pins cover the complete tool definition, and drift is auditable per
-- tool.
--
-- The previous pin hashed name/description/input schema with a hand-rolled
-- canonical form. The pin now covers every declared field (title, both
-- schemas, annotations, icons, execution hints, allowlisted _meta) over
-- RFC 8785 canonical bytes. Candidate rows are derived data, so they are
-- dropped here and re-created by the next discovery under the new
-- algorithm, instead of every tool quarantining on first refresh.

DELETE FROM server_tools;

ALTER TABLE server_tools
  ADD COLUMN IF NOT EXISTS definition JSONB NOT NULL,
  ADD COLUMN IF NOT EXISTS previous_definition JSONB,
  ADD COLUMN IF NOT EXISTS previous_hash TEXT,
  ADD COLUMN IF NOT EXISTS definition_version INTEGER NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS quarantine_reason TEXT;
