-- Missing pricing or usage must stay NULL, not zero: eval results record an
-- unknown cost as NULL (matching the usage endpoint), so comparisons can
-- tell "no price known" apart from "$0.00".
ALTER TABLE eval_results ALTER COLUMN cost_micro DROP NOT NULL;
ALTER TABLE eval_results ALTER COLUMN cost_micro DROP DEFAULT;
