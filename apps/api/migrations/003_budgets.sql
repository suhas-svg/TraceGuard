-- Phase 4: versioned pricing, budgets, spend ledger, reservations.
-- Money is integer micro-dollars everywhere, never floats. Unknown model
-- means NULL cost, not zero: that falls out of the LEFT JOIN in the usage
-- query, not out of a stored default.
CREATE TABLE IF NOT EXISTS pricing (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  effective_from TIMESTAMPTZ NOT NULL DEFAULT now(),
  input_price_per_million BIGINT NOT NULL CHECK (input_price_per_million >= 0),
  output_price_per_million BIGINT NOT NULL CHECK (output_price_per_million >= 0),
  cached_input_price_per_million BIGINT NOT NULL DEFAULT 0 CHECK (cached_input_price_per_million >= 0),
  currency TEXT NOT NULL DEFAULT 'USD',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pricing_lookup
  ON pricing(provider, model, effective_from DESC);

CREATE TABLE IF NOT EXISTS budgets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  scope TEXT NOT NULL CHECK (scope IN ('run', 'agent')),
  ref_id UUID NOT NULL,
  limit_micro BIGINT NOT NULL CHECK (limit_micro >= 0),
  effect TEXT NOT NULL DEFAULT 'block' CHECK (effect IN ('block', 'warn')),
  spent_micro BIGINT NOT NULL DEFAULT 0,
  reserved_micro BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_budgets_ref ON budgets(scope, ref_id);

-- Append-only spend record. spent_micro on budgets is a cached sum of this.
CREATE TABLE IF NOT EXISTS budget_ledger (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  budget_id UUID NOT NULL REFERENCES budgets(id) ON DELETE CASCADE,
  amount_micro BIGINT NOT NULL CHECK (amount_micro >= 0),
  reservation_id UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ledger_budget ON budget_ledger(budget_id, created_at DESC);

CREATE TABLE IF NOT EXISTS budget_reservations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  budget_id UUID NOT NULL REFERENCES budgets(id) ON DELETE CASCADE,
  amount_micro BIGINT NOT NULL CHECK (amount_micro >= 0),
  status TEXT NOT NULL DEFAULT 'held' CHECK (status IN ('held', 'settled', 'released')),
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_reservations_budget ON budget_reservations(budget_id, status);
