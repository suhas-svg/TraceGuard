-- Trace fidelity: OTLP ingestion metadata on spans, child-before-parent
-- linking, and a spans retention target (§11).
--
-- Spans now record how they arrived (events vs otlp), the protocol schema
-- version, the receive time beside the event time, a clock-skew flag, and the
-- parent-link state. The parent foreign key is dropped: exporters batch spans
-- out of order, so an early child is linked when its parent lands instead of
-- being rejected, and a parent that never arrives is marked ORPHANED by the
-- admin sweep.

ALTER TABLE spans
  ADD COLUMN IF NOT EXISTS received_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS ingestion_source text NOT NULL DEFAULT 'events',
  ADD COLUMN IF NOT EXISTS schema_version text NOT NULL DEFAULT '1',
  ADD COLUMN IF NOT EXISTS clock_skew boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS parent_state text NOT NULL DEFAULT 'resolved';

ALTER TABLE spans DROP CONSTRAINT IF EXISTS spans_parent_state_check;
ALTER TABLE spans
  ADD CONSTRAINT spans_parent_state_check
  CHECK (parent_state IN ('resolved', 'unresolved', 'orphaned'));

ALTER TABLE spans DROP CONSTRAINT IF EXISTS spans_parent_span_id_fkey;

-- The orphan sweep scans only the pending links.
CREATE INDEX IF NOT EXISTS idx_spans_parent_pending
  ON spans (parent_span_id) WHERE parent_state = 'unresolved';

-- Retention gains trace data as a first-class target. A spans rule ages out
-- whole runs (their spans follow the cascade) and additionally enforces an
-- optional row cap, oldest traces first. Decisions, approvals, and the audit
-- log are not reachable from this target.
ALTER TABLE retention_rules DROP CONSTRAINT IF EXISTS retention_rules_target_check;
ALTER TABLE retention_rules
  ADD CONSTRAINT retention_rules_target_check
  CHECK (target IN ('runs', 'approvals', 'webhook_deliveries', 'spans'));
ALTER TABLE retention_rules ADD COLUMN IF NOT EXISTS max_rows BIGINT;
ALTER TABLE retention_rules DROP CONSTRAINT IF EXISTS retention_rules_max_rows_check;
ALTER TABLE retention_rules
  ADD CONSTRAINT retention_rules_max_rows_check
  CHECK (max_rows IS NULL OR max_rows >= 1);

-- Spec default: 7 days or 100,000 spans, whichever hits first (§11.4).
INSERT INTO retention_rules (workspace_id, name, target, older_than_days, max_rows, enabled)
SELECT id, 'default-span-retention', 'spans', 7, 100000, true FROM workspaces
ON CONFLICT (workspace_id, name) DO NOTHING;
