-- §9.2 approval state machine v2: the ten states, durable execution intent,
-- an explicit outcome (including ambiguity), and DB-time terminal stamps.
-- Existing rows map onto the new vocabulary: 'denied' -> 'rejected';
-- 'consumed' -> 'response_received' (those rows predate outcome tracking and
-- are annotated as such).
ALTER TABLE approvals DROP CONSTRAINT IF EXISTS approvals_status_check;

-- Columns first: the backfill below stamps terminal_at.
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS claim_id UUID;
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS claim_lease_expires_at TIMESTAMPTZ;
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS execution_started_at TIMESTAMPTZ;
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS response_is_error BOOLEAN;
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS outcome_summary TEXT NOT NULL DEFAULT '';
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS outcome_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS terminal_at TIMESTAMPTZ;

UPDATE approvals SET status = 'rejected' WHERE status = 'denied';
UPDATE approvals SET status = 'response_received',
                     outcome_summary = '[migrated: pre-v2 consumed row]',
                     terminal_at = COALESCE(terminal_at, decided_at)
 WHERE status = 'consumed';

ALTER TABLE approvals ALTER COLUMN status SET DEFAULT 'pending';
ALTER TABLE approvals ADD CONSTRAINT approvals_status_check CHECK (status IN (
  'pending',            -- PENDING_APPROVAL
  'approved',           -- APPROVED
  'rejected',           -- REJECTED
  'expired',            -- EXPIRED
  'claimed',            -- CLAIMED (transitional inside the consume transaction)
  'executing',          -- EXECUTING: the linearization point; dispatch may follow
  'response_received',  -- RESPONSE_RECEIVED (response_is_error distinguishes)
  'outcome_unknown',    -- OUTCOME_UNKNOWN: never auto-retried
  'policy_invalidated', -- POLICY_INVALIDATED
  'tool_quarantined'    -- TOOL_QUARANTINED
));

-- The recovery sweep looks for stuck executing rows and stray claims.
CREATE INDEX IF NOT EXISTS idx_approvals_live
  ON approvals (status, execution_started_at, claim_lease_expires_at)
  WHERE status IN ('claimed', 'executing');
