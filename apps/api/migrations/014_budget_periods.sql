-- FR-009: a budget can now be scoped to a reporting period rather than to the
-- lifetime of the row. No counter is reset on a schedule: windowed spend is
-- summed from budget_ledger, which already carries created_at, so past windows
-- stay explainable and a missed cron cannot leave a budget stuck open.
ALTER TABLE budgets ADD COLUMN IF NOT EXISTS period TEXT NOT NULL DEFAULT 'lifetime'
  CHECK (period IN ('lifetime', 'day', 'week', 'month'));

-- An abandoned hold (the caller died between reserve and settle) is released by
-- the next check against the same budget. Operators need to see when that
-- happened rather than infer it from a status they never set.
ALTER TABLE budget_reservations ADD COLUMN IF NOT EXISTS released_at TIMESTAMPTZ;
