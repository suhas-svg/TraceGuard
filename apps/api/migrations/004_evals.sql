-- Phase 5: evaluation suites, cases, runs, results.
-- Suite versions lock on first use: rows are never edited after a run
-- references them; new versions are new rows.
CREATE TABLE IF NOT EXISTS eval_suites (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  description TEXT NOT NULL DEFAULT '',
  locked BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (name, version)
);

CREATE TABLE IF NOT EXISTS eval_cases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  suite_id UUID NOT NULL REFERENCES eval_suites(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  input_payload JSONB NOT NULL DEFAULT '{}',
  expected JSONB NOT NULL DEFAULT '{}',
  assertions JSONB NOT NULL DEFAULT '[]',
  exec_config JSONB NOT NULL DEFAULT '{}',
  UNIQUE (suite_id, name)
);

CREATE TABLE IF NOT EXISTS eval_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  suite_id UUID NOT NULL REFERENCES eval_suites(id) ON DELETE RESTRICT,
  suite_version INTEGER NOT NULL,
  agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
  agent_name TEXT NOT NULL DEFAULT '',
  config_fingerprint TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  trials INTEGER NOT NULL DEFAULT 1,
  cost_cap_micro BIGINT NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'running'
    CHECK (status IN ('running', 'success', 'failed', 'cancelled')),
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS eval_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  eval_run_id UUID NOT NULL REFERENCES eval_runs(id) ON DELETE CASCADE,
  case_id UUID NOT NULL REFERENCES eval_cases(id) ON DELETE CASCADE,
  trial INTEGER NOT NULL DEFAULT 1,
  agent_run_id UUID REFERENCES runs(id) ON DELETE SET NULL,
  passed BOOLEAN NOT NULL,
  assertion_results JSONB NOT NULL DEFAULT '[]',
  latency_ms INTEGER NOT NULL DEFAULT 0,
  cost_micro BIGINT NOT NULL DEFAULT 0,
  error_summary TEXT
);
CREATE INDEX IF NOT EXISTS idx_results_run ON eval_results(eval_run_id, case_id, trial);
