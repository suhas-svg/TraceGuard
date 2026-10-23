-- §13.1/§14: server drafts are untrusted proposals, and disabling a server is
-- an explicit lifecycle action rather than deleting its audit history.
BEGIN;

ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS mcp_server_drafts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  base_url TEXT NOT NULL,
  gateway_alias TEXT NOT NULL,
  secret_ref TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'exported')),
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  exported_at TIMESTAMPTZ,
  CONSTRAINT mcp_server_drafts_secret_ref_format CHECK (
    secret_ref IS NULL OR (
      length(secret_ref) <= 512
      AND secret_ref ~ '^(env:[A-Za-z_][A-Za-z0-9_]*|file:.+)$'
    )
  )
);

CREATE INDEX IF NOT EXISTS idx_mcp_server_drafts_project
  ON mcp_server_drafts(project_id, created_at DESC);

-- A proposal is never trusted policy. The control API may create and edit it,
-- but the operator publisher remains the only path that can turn it into
-- active signed configuration.
GRANT SELECT, INSERT, UPDATE ON mcp_server_drafts TO api_runtime;

COMMENT ON TABLE mcp_server_drafts IS
  'Untrusted MCP server proposals; active mcp_servers are separate and only callable via the signed manifest.';

COMMIT;
