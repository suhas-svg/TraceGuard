-- §12 budget fidelity (migration 030).
--
-- Prices become NUMERIC so sub-micro-unit rates are representable — a model
-- priced below one micro-dollar per unit can be configured exactly, and the
-- money math stays exact (the ledger keeps integer micro-dollars).
--
-- Reservations record WHY they closed: a settle against measured usage, a
-- settle at the reserved maximum because usage never arrived, or an expiry
-- sweep timing the hold out. The partial index serves the global sweep of
-- abandoned holds (§12.3).

ALTER TABLE pricing
  ALTER COLUMN input_price_per_million TYPE NUMERIC(18,6) USING input_price_per_million::numeric,
  ALTER COLUMN output_price_per_million TYPE NUMERIC(18,6) USING output_price_per_million::numeric,
  ALTER COLUMN cached_input_price_per_million TYPE NUMERIC(18,6) USING cached_input_price_per_million::numeric;

ALTER TABLE budget_reservations ADD COLUMN IF NOT EXISTS settle_reason TEXT;
ALTER TABLE budget_reservations DROP CONSTRAINT IF EXISTS budget_reservations_settle_reason_check;
ALTER TABLE budget_reservations ADD CONSTRAINT budget_reservations_settle_reason_check
  CHECK (settle_reason IS NULL OR settle_reason IN ('usage_known', 'usage_unavailable', 'timeout'));

CREATE INDEX IF NOT EXISTS idx_reservations_expired
  ON budget_reservations (expires_at) WHERE status = 'held';
