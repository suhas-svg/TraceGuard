-- FR-021: correlate policy decisions with the trace (run/span) and the
-- logical request id the client sent. The gateway already knows these when it
-- records a decision; storing them turns "the run was denied" into "which
-- rule denied which call, and which approval covered it".
--
-- Nullable on purpose: calls made outside a run (health probes, ad-hoc tool
-- calls) have no run or span, and legacy rows predate these columns.
ALTER TABLE policy_decisions ADD COLUMN IF NOT EXISTS run_id uuid;
ALTER TABLE policy_decisions ADD COLUMN IF NOT EXISTS span_id uuid;
ALTER TABLE policy_decisions ADD COLUMN IF NOT EXISTS request_id text;

CREATE INDEX IF NOT EXISTS policy_decisions_run_idx
  ON policy_decisions (run_id) WHERE run_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS policy_decisions_span_idx
  ON policy_decisions (span_id) WHERE span_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS policy_decisions_request_idx
  ON policy_decisions (request_id) WHERE request_id IS NOT NULL;
