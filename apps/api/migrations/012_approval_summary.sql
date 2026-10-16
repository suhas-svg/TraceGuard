-- Phase 9 fix: approval terminal states keep only a redacted summary and the
-- args hash. Pending rows still carry sealed arguments; once an approval is
-- denied, expired, or consumed, its args blob is cleared and the summary
-- below is what remains for the audit trail.
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS args_summary TEXT;
