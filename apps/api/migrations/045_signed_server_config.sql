-- B2 / §13.1: an active MCP server is a signed configuration, not an
-- arbitrary row. The bundle already carries server_id/alias/base_url; this
-- migration binds the mutable row to the signed bundle version and prevents
-- the API role from changing the configuration after publication.

ALTER TABLE mcp_servers
  ADD COLUMN IF NOT EXISTS signed_bundle_version bigint;

-- Existing rows are deliberately left NULL: an upgrade must republish before
-- any server becomes callable again. This is the fail-closed migration path.
COMMENT ON COLUMN mcp_servers.signed_bundle_version IS
  'Signed policy bundle version that stamped this server configuration; NULL is an unpublished draft.';

-- policy_owner runs the stamping procedure. It may only update the version
-- column, not the rest of the row.
GRANT UPDATE (signed_bundle_version) ON mcp_servers TO policy_owner;

CREATE OR REPLACE FUNCTION stamp_signed_servers(
  p_project_id uuid,
  p_version bigint
) RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_count integer;
BEGIN
  IF p_project_id IS NULL OR p_version IS NULL OR p_version <= 0 THEN
    RAISE EXCEPTION 'project id and positive signed version are required';
  END IF;
  IF NOT EXISTS (
    SELECT 1
      FROM policy_versions pv
      JOIN active_config ac ON ac.policy_version_id = pv.id
     WHERE pv.project_id = p_project_id
       AND ac.project_id = p_project_id
       AND pv.version = p_version
  ) THEN
    RAISE EXCEPTION 'signed version % is not the active policy for project %', p_version, p_project_id;
  END IF;
  IF EXISTS (
    SELECT 1 FROM mcp_servers
     WHERE project_id = p_project_id AND signed_bundle_version > p_version
  ) THEN
    RAISE EXCEPTION 'signed server configuration cannot move backwards';
  END IF;

  UPDATE mcp_servers
     SET signed_bundle_version = p_version
   WHERE project_id = p_project_id;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END;
$$;

ALTER FUNCTION stamp_signed_servers(uuid, bigint) OWNER TO policy_owner;
REVOKE ALL ON FUNCTION stamp_signed_servers(uuid, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION stamp_signed_servers(uuid, bigint) TO policy_publisher;

-- Once a server has been stamped, the API role may disable it but may not
-- rewrite its URL, alias, secret reference, project, or signed version. The
-- publisher's SECURITY DEFINER procedure is the only writer of the version.
CREATE OR REPLACE FUNCTION guard_mcp_server_signed_config() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF current_user = 'policy_owner' OR pg_has_role(current_user, 'policy_owner', 'member') THEN
    RETURN NEW;
  END IF;

  IF TG_OP = 'INSERT' THEN
    IF NEW.signed_bundle_version IS NOT NULL THEN
      RAISE EXCEPTION 'signed server configuration may only be stamped by the policy publisher';
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.signed_bundle_version IS NOT NULL THEN
    IF NEW.name IS DISTINCT FROM OLD.name
       OR NEW.base_url IS DISTINCT FROM OLD.base_url
       OR NEW.gateway_alias IS DISTINCT FROM OLD.gateway_alias
       OR NEW.secret_ref IS DISTINCT FROM OLD.secret_ref
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id THEN
      RAISE EXCEPTION 'signed server configuration is immutable; create a draft and republish';
    END IF;
    IF NEW.disabled_at IS DISTINCT FROM OLD.disabled_at
       AND NOT (OLD.disabled_at IS NULL AND NEW.disabled_at IS NOT NULL) THEN
      RAISE EXCEPTION 'a disabled server cannot be re-enabled directly';
    END IF;
  END IF;

  IF NEW.signed_bundle_version IS DISTINCT FROM OLD.signed_bundle_version THEN
    RAISE EXCEPTION 'signed server configuration may only be stamped by the policy publisher';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS mcp_servers_guard_signed_config ON mcp_servers;
CREATE TRIGGER mcp_servers_guard_signed_config
  BEFORE INSERT OR UPDATE ON mcp_servers
  FOR EACH ROW EXECUTE FUNCTION guard_mcp_server_signed_config();
