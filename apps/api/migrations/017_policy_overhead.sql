-- Section 14 sets a policy-decision budget: p95 under 100ms, excluding upstream
-- execution and human approval. Nothing recorded how long a decision took, so
-- that target could only be inferred from a whole-call figure which includes
-- the upstream round trip the target explicitly excludes.
--
-- Nullable on purpose: rows written before this, and any path that does not
-- measure, stay NULL. A zero would read as an instant decision.
ALTER TABLE policy_decisions ADD COLUMN IF NOT EXISTS overhead_ms INTEGER;
