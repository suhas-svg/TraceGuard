-- Phase 2: gateway registry, versioned policies, approvals, decisions, audit.
-- Audit is append-only by convention: no UPDATE or DELETE against audit_events
-- exists anywhere in the codebase. A dedicated PG role with revoked rights is
-- still needed before multi-user use (see shortcut note in src/audit.ts).
CREATE TABLE IF NOT EXISTS mcp_servers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  base_url TEXT NOT NULL CHECK (base_url LIKE 'http://%' OR base_url LIKE 'https://%'),
  auth_secret TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, name)
);

CREATE TABLE IF NOT EXISTS server_tools (
  server_id UUID NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
  tool_name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  input_schema JSONB NOT NULL DEFAULT '{}',
  definition_hash TEXT NOT NULL,
  quarantined BOOLEAN NOT NULL DEFAULT false,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (server_id, tool_name)
);

-- Policies are immutable versions: an update inserts a new row pointing at
-- previous_id and marks the old row superseded. Decisions cite the exact row.
CREATE TABLE IF NOT EXISTS policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT true,
  priority INTEGER NOT NULL DEFAULT 0,
  agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
  server_id UUID REFERENCES mcp_servers(id) ON DELETE CASCADE,
  tool_name TEXT,
  effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny', 'require_approval')),
  conditions JSONB NOT NULL DEFAULT '{}',
  version INTEGER NOT NULL DEFAULT 1,
  previous_id UUID REFERENCES policies(id),
  superseded_by UUID REFERENCES policies(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_policies_lookup
  ON policies(workspace_id, enabled, server_id, tool_name);

CREATE TABLE IF NOT EXISTS approvals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id TEXT NOT NULL UNIQUE,
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  caller TEXT NOT NULL,
  server_id UUID NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
  tool_name TEXT NOT NULL,
  args_hash TEXT NOT NULL,
  args JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'consumed')),
  requested_by TEXT NOT NULL DEFAULT '',
  decided_by TEXT,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  decided_at TIMESTAMPTZ,
  decision_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status, expires_at);

CREATE TABLE IF NOT EXISTS policy_decisions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  caller TEXT NOT NULL,
  server_id UUID REFERENCES mcp_servers(id) ON DELETE SET NULL,
  tool_name TEXT NOT NULL,
  args_hash TEXT NOT NULL DEFAULT '',
  decision TEXT NOT NULL
    CHECK (decision IN ('allow', 'deny', 'need_approval', 'approved_retry', 'error')),
  policy_id UUID REFERENCES policies(id) ON DELETE SET NULL,
  policy_version INTEGER,
  matched_rules JSONB NOT NULL DEFAULT '[]',
  reason TEXT NOT NULL DEFAULT '',
  approval_id UUID REFERENCES approvals(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_decisions_lookup
  ON policy_decisions(server_id, tool_name, timestamp DESC);

CREATE TABLE IF NOT EXISTS audit_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor_type TEXT NOT NULL,
  actor_id TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL DEFAULT '',
  result TEXT NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}',
  prev_hash TEXT NOT NULL DEFAULT '',
  hash TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_action_time ON audit_events(action, timestamp DESC);
