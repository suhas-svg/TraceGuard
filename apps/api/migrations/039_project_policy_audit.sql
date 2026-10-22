-- 039: signed policy publication and audit attribution become project-scoped.
--
-- 038 added projects and put project_id on the execution tables, but signed
-- policy versions, active_config, and audit_events were still workspace-wide.
-- This migration makes the trusted policy pointer and the audit hash cover a
-- project without rewriting the signed bundle bytes of existing versions.
--
-- Existing versions and active pointers belong to each workspace's default
-- project. Legacy bundles without a project_id are accepted only for that
-- default project by the gateway loader; new bundles always carry one.

BEGIN;

-- ---------------------------------------------------------------------------
-- Signed policy versions
-- ---------------------------------------------------------------------------

ALTER TABLE policy_versions
  ADD COLUMN IF NOT EXISTS project_id uuid REFERENCES projects(id) ON DELETE CASCADE;

CREATE OR REPLACE FUNCTION fill_policy_version_project() RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
  IF NEW.project_id IS NULL THEN
    NEW.project_id := ensure_default_project(NEW.workspace_id);
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS policy_versions_fill_project ON policy_versions;
CREATE TRIGGER policy_versions_fill_project
  BEFORE INSERT ON policy_versions
  FOR EACH ROW EXECUTE FUNCTION fill_policy_version_project();

-- The immutability trigger fires on UPDATE too, including a backfill. Disable
-- it only for the one-time attribution update, never for signed bundle bytes.
ALTER TABLE policy_versions DISABLE TRIGGER policy_versions_immutable;
UPDATE policy_versions
   SET project_id = ensure_default_project(workspace_id)
 WHERE project_id IS NULL;
ALTER TABLE policy_versions ENABLE TRIGGER policy_versions_immutable;

ALTER TABLE policy_versions ALTER COLUMN project_id SET NOT NULL;
ALTER TABLE policy_versions
  DROP CONSTRAINT IF EXISTS policy_versions_workspace_id_version_key;
ALTER TABLE policy_versions
  ADD CONSTRAINT policy_versions_project_id_version_key UNIQUE (project_id, version);

DROP INDEX IF EXISTS policy_versions_workspace_version_idx;
CREATE INDEX IF NOT EXISTS policy_versions_project_version_idx
  ON policy_versions (project_id, version DESC);

-- ---------------------------------------------------------------------------
-- Active policy pointer
-- ---------------------------------------------------------------------------

ALTER TABLE active_config
  ADD COLUMN IF NOT EXISTS project_id uuid REFERENCES projects(id) ON DELETE CASCADE;

CREATE OR REPLACE FUNCTION fill_active_config_project() RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
  IF NEW.project_id IS NULL THEN
    NEW.project_id := ensure_default_project(NEW.workspace_id);
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS active_config_fill_project ON active_config;
CREATE TRIGGER active_config_fill_project
  BEFORE INSERT OR UPDATE ON active_config
  FOR EACH ROW EXECUTE FUNCTION fill_active_config_project();

UPDATE active_config
   SET project_id = ensure_default_project(workspace_id)
 WHERE project_id IS NULL;

ALTER TABLE active_config ALTER COLUMN project_id SET NOT NULL;
ALTER TABLE active_config DROP CONSTRAINT IF EXISTS active_config_pkey;
ALTER TABLE active_config ADD PRIMARY KEY (project_id);

CREATE INDEX IF NOT EXISTS active_config_workspace_idx
  ON active_config (workspace_id);

-- The version row carries the project, so the procedure signature stays the
-- same for existing grants and callers. It verifies that the version belongs
-- to the named workspace before moving that project's pointer. The old
-- function returns void, so it must be dropped before the boolean form.
DROP FUNCTION IF EXISTS policy_activate_version(uuid, uuid);

CREATE FUNCTION policy_activate_version(
  p_workspace_id uuid,
  p_policy_version_id uuid
) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_project_id uuid;
BEGIN
  SELECT project_id INTO v_project_id
    FROM policy_versions
   WHERE id = p_policy_version_id
     AND workspace_id = p_workspace_id;

  IF v_project_id IS NULL THEN
    RAISE EXCEPTION 'policy version not found for workspace';
  END IF;

  INSERT INTO active_config (project_id, workspace_id, policy_version_id, updated_at)
  VALUES (v_project_id, p_workspace_id, p_policy_version_id, now())
  ON CONFLICT (project_id) DO UPDATE
    SET workspace_id = EXCLUDED.workspace_id,
        policy_version_id = EXCLUDED.policy_version_id,
        updated_at = now();

  RETURN true;
END;
$$;

ALTER FUNCTION policy_activate_version(uuid, uuid) OWNER TO policy_owner;
REVOKE ALL ON FUNCTION policy_activate_version(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION policy_activate_version(uuid, uuid) TO policy_publisher;

-- ---------------------------------------------------------------------------
-- Audit attribution (hash version 4)
-- ---------------------------------------------------------------------------

ALTER TABLE audit_events
  ADD COLUMN IF NOT EXISTS project_id uuid REFERENCES projects(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS audit_events_project_timestamp_idx
  ON audit_events (project_id, timestamp, id);

DROP FUNCTION IF EXISTS append_audit_event(
  uuid, timestamptz, text, text, text, text, text, text, jsonb, text, text,
  uuid, bigint, smallint, uuid, jsonb
);

CREATE OR REPLACE FUNCTION append_audit_event(
  p_id uuid,
  p_timestamp timestamptz,
  p_actor_type text, p_actor_id text, p_action text,
  p_resource_type text, p_resource_id text, p_result text,
  p_metadata jsonb, p_prev_hash text, p_hash text,
  p_workspace_id uuid, p_seq bigint,
  p_hash_version smallint DEFAULT 4,
  p_policy_version_id uuid DEFAULT NULL,
  p_matched_rule_ids jsonb DEFAULT NULL,
  p_project_id uuid DEFAULT NULL
) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  head text;
  v_ws uuid := COALESCE(p_workspace_id, '00000000-0000-0000-0000-000000000000'::uuid);
BEGIN
  PERFORM pg_advisory_xact_lock(852100000001);

  -- A project attribution that does not belong to the event's workspace would
  -- make the v4 hash describe a scope the event never executed in.
  IF p_project_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM projects
     WHERE id = p_project_id
       AND workspace_id = p_workspace_id
  ) THEN
    RETURN false;
  END IF;

  SELECT head_hash INTO head FROM audit_chain_state WHERE id;
  IF COALESCE(head, '') <> COALESCE(p_prev_hash, '') THEN
    RETURN false;
  END IF;

  INSERT INTO audit_events
    (id, timestamp, actor_type, actor_id, action, resource_type, resource_id,
     result, metadata, prev_hash, hash,
     workspace_id, seq, hash_version, policy_version_id, matched_rule_ids,
     project_id)
  VALUES
    (p_id, p_timestamp, p_actor_type, p_actor_id, p_action, p_resource_type,
     p_resource_id, p_result, COALESCE(p_metadata, '{}'::jsonb), p_prev_hash,
     p_hash, p_workspace_id, p_seq, COALESCE(p_hash_version, 4),
     p_policy_version_id, p_matched_rule_ids, p_project_id);

  INSERT INTO audit_chain_state (id, head_hash)
  VALUES (true, p_hash)
  ON CONFLICT (id) DO UPDATE SET head_hash = EXCLUDED.head_hash;

  INSERT INTO audit_chain_heads (workspace_id, last_seq, head_hash)
  VALUES (v_ws, p_seq, p_hash)
  ON CONFLICT (workspace_id)
  DO UPDATE SET last_seq = GREATEST(audit_chain_heads.last_seq, EXCLUDED.last_seq),
                head_hash = EXCLUDED.head_hash;
  RETURN true;
END $$;

ALTER FUNCTION append_audit_event(
  uuid, timestamptz, text, text, text, text, text, text, jsonb, text, text,
  uuid, bigint, smallint, uuid, jsonb, uuid
) OWNER TO audit_owner;

-- The SECURITY DEFINER append validates project/workspace consistency as its
-- owner. It must be able to read the mapping, never write it.
GRANT SELECT ON projects TO audit_owner;

REVOKE ALL ON FUNCTION append_audit_event(
  uuid, timestamptz, text, text, text, text, text, text, jsonb, text, text,
  uuid, bigint, smallint, uuid, jsonb, uuid
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION append_audit_event(
  uuid, timestamptz, text, text, text, text, text, text, jsonb, text, text,
  uuid, bigint, smallint, uuid, jsonb, uuid
) TO api_runtime, gateway_runtime, policy_publisher, retention_job;

COMMIT;
