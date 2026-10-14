-- Phase 10: provider actuals for cost reconciliation. Actuals are imported
-- records (CSV exports, invoice lines), never edited: corrections arrive as
-- new rows, and the comparison always states its window and sources.
CREATE TABLE IF NOT EXISTS actuals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  period_start TIMESTAMPTZ NOT NULL,
  period_end TIMESTAMPTZ NOT NULL,
  input_tokens BIGINT NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
  output_tokens BIGINT NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
  actual_cost_micro BIGINT NOT NULL CHECK (actual_cost_micro >= 0),
  source TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (period_end > period_start)
);
CREATE INDEX IF NOT EXISTS idx_actuals_lookup
  ON actuals(workspace_id, provider, model, period_start, period_end);
