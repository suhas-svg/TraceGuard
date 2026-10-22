-- 038: §7.1/§13.1 identity model.
--
-- Workspaces stay the installation/data boundary. Projects are the policy and
-- data scope inside a workspace, agent principals are the non-human MCP
-- callers bound to one project, and ingestion keys are separate credentials
-- that can only submit telemetry. Existing rows are backfilled into a
-- "default" project per workspace so this migration is forward-only and does
-- not invalidate installed data.
--
-- The project_id columns are NOT NULL on the operational tables. BEFORE INSERT
-- triggers fill them from the row's workspace/server when an older caller does
-- not name a project; new code still passes project_id explicitly.

BEGIN;

CREATE TABLE IF NOT EXISTS projects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'archived')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, name)
);
CREATE INDEX IF NOT EXISTS idx_projects_workspace ON projects(workspace_id);

CREATE TABLE IF NOT EXISTS agent_principals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT '',
  allowed_scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
  status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (project_id, issuer, subject)
);
CREATE INDEX IF NOT EXISTS idx_agent_principals_project
  ON agent_principals(project_id, status);

CREATE TABLE IF NOT EXISTS ingest_api_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  scopes JSONB NOT NULL DEFAULT '["ingest"]'::jsonb,
  created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ingest_api_keys_project
  ON ingest_api_keys(project_id, revoked_at);

-- One default project per existing workspace. 016's "project" budget scope
-- called a workspace a project; this is the first real project row and keeps
-- the old rows addressable.
INSERT INTO projects (workspace_id, name)
SELECT w.id, 'default'
  FROM workspaces w
 WHERE NOT EXISTS (
   SELECT 1 FROM projects p WHERE p.workspace_id = w.id AND p.name = 'default'
 );

CREATE OR REPLACE FUNCTION ensure_default_project(p_workspace_id uuid)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_id uuid;
BEGIN
  SELECT id INTO v_id
    FROM projects
   WHERE workspace_id = p_workspace_id AND name = 'default';
  IF v_id IS NULL THEN
    INSERT INTO projects (workspace_id, name)
    VALUES (p_workspace_id, 'default')
    ON CONFLICT (workspace_id, name) DO UPDATE SET name = EXCLUDED.name
    RETURNING id INTO v_id;
  END IF;
  RETURN v_id;
END;
$$;

CREATE OR REPLACE FUNCTION create_default_project_for_workspace()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  PERFORM ensure_default_project(NEW.id);
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS workspaces_default_project ON workspaces;
CREATE TRIGGER workspaces_default_project
  AFTER INSERT ON workspaces
  FOR EACH ROW EXECUTE FUNCTION create_default_project_for_workspace();

-- Fill helpers. They are SECURITY DEFINER because a runtime role only needs
-- the INSERT privilege on its own table; resolving the default project is not
-- a privilege the caller should have to hold separately.
CREATE OR REPLACE FUNCTION fill_project_from_workspace()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  IF NEW.project_id IS NULL AND NEW.workspace_id IS NOT NULL THEN
    NEW.project_id := ensure_default_project(NEW.workspace_id);
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION fill_project_from_server_or_workspace()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  IF NEW.project_id IS NULL AND NEW.server_id IS NOT NULL THEN
    SELECT project_id INTO NEW.project_id
      FROM mcp_servers WHERE id = NEW.server_id;
  END IF;
  IF NEW.project_id IS NULL AND NEW.workspace_id IS NOT NULL THEN
    NEW.project_id := ensure_default_project(NEW.workspace_id);
  END IF;
  RETURN NEW;
END;
$$;

-- Add the scope columns. Keep them nullable until after the backfill.
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE CASCADE;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE CASCADE;
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE CASCADE;
ALTER TABLE policy_decisions ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE CASCADE;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE CASCADE;
ALTER TABLE budgets ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE CASCADE;

-- Backfill in dependency order. Rows with a server take the server's project;
-- everything else lands in the workspace's default project.
UPDATE mcp_servers
   SET project_id = ensure_default_project(workspace_id)
 WHERE project_id IS NULL;

UPDATE policies p
   SET project_id = s.project_id
  FROM mcp_servers s
 WHERE p.server_id = s.id AND p.project_id IS NULL;

UPDATE policies
   SET project_id = ensure_default_project(workspace_id)
 WHERE project_id IS NULL;

UPDATE approvals a
   SET project_id = s.project_id
  FROM mcp_servers s
 WHERE a.server_id = s.id AND a.project_id IS NULL;

UPDATE approvals
   SET project_id = ensure_default_project(workspace_id)
 WHERE project_id IS NULL;

UPDATE policy_decisions d
   SET project_id = s.project_id
  FROM mcp_servers s
 WHERE d.server_id = s.id AND d.project_id IS NULL;

UPDATE policy_decisions
   SET project_id = ensure_default_project(workspace_id)
 WHERE project_id IS NULL;

UPDATE runs
   SET project_id = ensure_default_project(workspace_id)
 WHERE project_id IS NULL;

UPDATE budgets
   SET project_id = ensure_default_project(workspace_id)
 WHERE project_id IS NULL;

ALTER TABLE mcp_servers ALTER COLUMN project_id SET NOT NULL;
ALTER TABLE policies ALTER COLUMN project_id SET NOT NULL;
ALTER TABLE approvals ALTER COLUMN project_id SET NOT NULL;
ALTER TABLE policy_decisions ALTER COLUMN project_id SET NOT NULL;
ALTER TABLE runs ALTER COLUMN project_id SET NOT NULL;
ALTER TABLE budgets ALTER COLUMN project_id SET NOT NULL;

DROP TRIGGER IF EXISTS mcp_servers_fill_project ON mcp_servers;
CREATE TRIGGER mcp_servers_fill_project
  BEFORE INSERT ON mcp_servers
  FOR EACH ROW EXECUTE FUNCTION fill_project_from_workspace();

DROP TRIGGER IF EXISTS policies_fill_project ON policies;
CREATE TRIGGER policies_fill_project
  BEFORE INSERT ON policies
  FOR EACH ROW EXECUTE FUNCTION fill_project_from_workspace();

DROP TRIGGER IF EXISTS approvals_fill_project ON approvals;
CREATE TRIGGER approvals_fill_project
  BEFORE INSERT ON approvals
  FOR EACH ROW EXECUTE FUNCTION fill_project_from_server_or_workspace();

DROP TRIGGER IF EXISTS policy_decisions_fill_project ON policy_decisions;
CREATE TRIGGER policy_decisions_fill_project
  BEFORE INSERT ON policy_decisions
  FOR EACH ROW EXECUTE FUNCTION fill_project_from_server_or_workspace();

DROP TRIGGER IF EXISTS runs_fill_project ON runs;
CREATE TRIGGER runs_fill_project
  BEFORE INSERT ON runs
  FOR EACH ROW EXECUTE FUNCTION fill_project_from_workspace();

DROP TRIGGER IF EXISTS budgets_fill_project ON budgets;
CREATE TRIGGER budgets_fill_project
  BEFORE INSERT ON budgets
  FOR EACH ROW EXECUTE FUNCTION fill_project_from_workspace();

-- Server names are unique inside a project, not the whole workspace. Existing
-- workspace uniqueness would block the same alias in two projects.
ALTER TABLE mcp_servers DROP CONSTRAINT IF EXISTS mcp_servers_workspace_id_name_key;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'mcp_servers_project_id_name_key'
       AND conrelid = 'mcp_servers'::regclass
  ) THEN
    ALTER TABLE mcp_servers
      ADD CONSTRAINT mcp_servers_project_id_name_key UNIQUE (project_id, name);
  END IF;
END $$;

-- §9.4: approvals deduplicate by (project, caller, logical request id), not
-- globally. The old global request_id unique constraint made a project-scoped
-- logical id collide with an unrelated project's id.
ALTER TABLE approvals DROP CONSTRAINT IF EXISTS approvals_request_id_key;
DROP INDEX IF EXISTS approvals_request_id_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_approvals_project_caller_request
  ON approvals(project_id, caller, request_id);

-- The 11-argument request procedure is the only request entry point. Dropping
-- the 10-argument form keeps a single callable signature and avoids
-- ambiguous overloads.
DROP FUNCTION IF EXISTS approval_request(text,uuid,text,uuid,text,text,jsonb,boolean,text,integer);

CREATE OR REPLACE FUNCTION approval_request(
  p_request_id text,
  p_workspace_id uuid,
  p_caller text,
  p_server_id uuid,
  p_tool_name text,
  p_args_hash text,
  p_args jsonb,
  p_args_enc boolean,
  p_requested_by text,
  p_ttl_seconds integer,
  p_project_id uuid DEFAULT NULL
) RETURNS SETOF approvals
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_row approvals%ROWTYPE;
  v_project uuid;
BEGIN
  IF p_ttl_seconds IS NULL OR p_ttl_seconds <= 0 THEN
    RAISE EXCEPTION 'approval TTL must be positive';
  END IF;
  v_project := p_project_id;
  IF v_project IS NULL THEN
    SELECT project_id INTO v_project FROM mcp_servers WHERE id = p_server_id;
  END IF;
  IF v_project IS NULL THEN
    v_project := ensure_default_project(p_workspace_id);
  END IF;
  INSERT INTO approvals
    (request_id, workspace_id, project_id, caller, server_id, tool_name,
     args_hash, args, args_enc, requested_by, expires_at)
  VALUES
    (p_request_id, p_workspace_id, v_project, p_caller, p_server_id, p_tool_name,
     p_args_hash, p_args, p_args_enc, p_requested_by,
     now() + (p_ttl_seconds * interval '1 second'))
  ON CONFLICT (project_id, caller, request_id) DO NOTHING
  RETURNING * INTO v_row;
  IF v_row.id IS NULL THEN
    RETURN;
  END IF;
  RETURN NEXT v_row;
  RETURN;
END;
$$;

ALTER FUNCTION approval_request(text,uuid,text,uuid,text,text,jsonb,boolean,text,integer,uuid)
  OWNER TO approval_owner;
REVOKE ALL ON FUNCTION approval_request(text,uuid,text,uuid,text,text,jsonb,boolean,text,integer,uuid)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION approval_request(text,uuid,text,uuid,text,text,jsonb,boolean,text,integer,uuid)
  TO gateway_runtime;

-- Runtime privileges for the new identity tables. The gateway needs to map an
-- OAuth token to an AgentPrincipal and read project scope, but not to mint
-- identities or read ingestion key hashes.
GRANT SELECT ON projects, agent_principals TO gateway_runtime, policy_publisher, retention_job;
GRANT SELECT ON projects, agent_principals, ingest_api_keys TO api_runtime;
GRANT INSERT, UPDATE, DELETE ON projects, agent_principals, ingest_api_keys TO api_runtime;

COMMIT;
