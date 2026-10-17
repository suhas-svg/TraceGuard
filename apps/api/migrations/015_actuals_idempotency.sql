-- A re-uploaded or retried invoice export must not double the actual side of a
-- comparison: the same line imported twice flipped the sign and magnitude of
-- every variance, with no duplicate marker anywhere.
--
-- The natural key of an invoice line is the model, the billing window, and the
-- source it came from. A corrected figure is a new source (for example
-- 'aws-jan-fixed'), not a second row under the old one.
--
-- Rows that already collide on that key are re-imports of one line, so the
-- earliest is kept and the rest are dropped before the constraint can exist.
-- operator note: if a collision here was a deliberate second figure, give it a
-- distinct source value and re-import it.
DELETE FROM actuals a
 USING actuals b
 WHERE a.id > b.id
   AND a.workspace_id = b.workspace_id
   AND a.provider = b.provider
   AND a.model = b.model
   AND a.period_start = b.period_start
   AND a.period_end = b.period_end
   AND a.source = b.source;

CREATE UNIQUE INDEX IF NOT EXISTS idx_actuals_natural_key
  ON actuals (workspace_id, provider, model, period_start, period_end, source);
