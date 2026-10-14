-- Phase 7: mark which approval rows hold sealed arguments. Legacy rows
-- stay readable as plaintext; every row written after this migration seals.
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS args_enc BOOLEAN NOT NULL DEFAULT false;
