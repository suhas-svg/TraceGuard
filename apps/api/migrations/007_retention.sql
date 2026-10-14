-- Phase 9: retention rules and runs. Deletion targets execution and
-- operational data only. The compliance-critical tables are never targets:
-- policies (versioned history), policy_decisions, approvals pending rows,
-- audit_events (append-only), budgets and ledger (money trail).
CREATE TABLE IF NOT EXISTS retention_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  target TEXT NOT NULL CHECK (target IN ('runs', 'approvals', 'webhook_deliveries')),
  older_than_days INTEGER NOT NULL CHECK (older_than_days >= 1),
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, name)
);

CREATE TABLE IF NOT EXISTS retention_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at TIMESTAMPTZ,
  deleted_counts JSONB NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'success', 'failed'))
);
