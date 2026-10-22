-- §5.3 / §13.4: the publisher inserts immutable policy versions, but trust and
-- activation changes go through narrow procedures owned by a non-login role.
-- The publisher keeps INSERT on policy_versions (one new signed version) and
-- loses INSERT/UPDATE on policy_signing_keys and active_config.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'policy_owner') THEN
    CREATE ROLE policy_owner NOLOGIN;
  END IF;
END $$;
GRANT USAGE ON SCHEMA public TO policy_owner;
GRANT SELECT, INSERT, UPDATE ON policy_signing_keys TO policy_owner;
GRANT SELECT, INSERT, UPDATE ON active_config TO policy_owner;
GRANT SELECT ON policy_versions TO policy_owner;

-- Trust, retire, or re-activate one signing key. All live keys are retired in
-- the same call when --rotate is set; without rotation a different live key is
-- refused. Returns one row per state change plus an already_trusted row when
-- the requested key is already live, so the caller can audit the exact result.
CREATE OR REPLACE FUNCTION policy_trust_key(
  p_workspace_id uuid,
  p_key_id text,
  p_public_key_pem text,
  p_rotate boolean
) RETURNS TABLE(action text, key_row_id uuid, out_key_id text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_existing_id uuid;
  v_live record;
  v_inserted_id uuid;
BEGIN
  IF p_workspace_id IS NULL THEN
    RAISE EXCEPTION 'workspace id is required';
  END IF;
  IF p_key_id IS NULL OR btrim(p_key_id) = '' THEN
    RAISE EXCEPTION 'signing key id is required';
  END IF;
  IF p_public_key_pem IS NULL OR btrim(p_public_key_pem) = '' THEN
    RAISE EXCEPTION 'public key is required';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtext('policy-keys:' || p_workspace_id::text));

  SELECT k.id INTO v_existing_id
    FROM policy_signing_keys k
   WHERE k.workspace_id = p_workspace_id AND k.key_id = p_key_id;

  IF v_existing_id IS NOT NULL AND EXISTS (
    SELECT 1 FROM policy_signing_keys k
     WHERE k.id = v_existing_id AND k.retired_at IS NULL
  ) THEN
    action := 'already_trusted';
    key_row_id := v_existing_id;
    out_key_id := p_key_id;
    RETURN NEXT;
    RETURN;
  END IF;

  IF EXISTS (
    SELECT 1 FROM policy_signing_keys k
     WHERE k.workspace_id = p_workspace_id AND k.retired_at IS NULL
  ) AND NOT COALESCE(p_rotate, false) THEN
    RAISE EXCEPTION 'this workspace already trusts a different signing key; pass --rotate to replace it';
  END IF;

  FOR v_live IN
    SELECT k.id, k.key_id
      FROM policy_signing_keys k
     WHERE k.workspace_id = p_workspace_id AND k.retired_at IS NULL
     ORDER BY k.created_at, k.id
  LOOP
    UPDATE policy_signing_keys SET retired_at = now() WHERE id = v_live.id;
    action := 'retired';
    key_row_id := v_live.id;
    out_key_id := v_live.key_id;
    RETURN NEXT;
  END LOOP;

  IF v_existing_id IS NOT NULL THEN
    UPDATE policy_signing_keys SET retired_at = NULL WHERE id = v_existing_id;
    action := 'reactivated';
    key_row_id := v_existing_id;
    out_key_id := p_key_id;
    RETURN NEXT;
    RETURN;
  END IF;

  INSERT INTO policy_signing_keys (workspace_id, key_id, public_key_pem)
  VALUES (p_workspace_id, p_key_id, btrim(p_public_key_pem))
  RETURNING id INTO v_inserted_id;

  action := 'trusted';
  key_row_id := v_inserted_id;
  out_key_id := p_key_id;
  RETURN NEXT;
  RETURN;
END;
$$;

-- Activate an already-inserted signed version for its workspace. The version
-- must belong to that workspace; the upsert is the only trusted-config write.
CREATE OR REPLACE FUNCTION policy_activate_version(
  p_workspace_id uuid,
  p_policy_version_id uuid
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  IF p_workspace_id IS NULL OR p_policy_version_id IS NULL THEN
    RAISE EXCEPTION 'workspace id and policy version id are required';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM policy_versions
     WHERE id = p_policy_version_id AND workspace_id = p_workspace_id
  ) THEN
    RAISE EXCEPTION 'policy version does not belong to this workspace';
  END IF;
  INSERT INTO active_config (workspace_id, policy_version_id, updated_at)
  VALUES (p_workspace_id, p_policy_version_id, now())
  ON CONFLICT (workspace_id) DO UPDATE
    SET policy_version_id = EXCLUDED.policy_version_id, updated_at = now();
END;
$$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'policy_owner') THEN
    ALTER FUNCTION policy_trust_key(uuid, text, text, boolean) OWNER TO policy_owner;
    ALTER FUNCTION policy_activate_version(uuid, uuid) OWNER TO policy_owner;
    -- The consume-time FOR SHARE helper must run as the role that still holds
    -- the active_config write privilege after this migration.
    ALTER FUNCTION lock_active_config_share(uuid) OWNER TO policy_owner;
  END IF;
END $$;

REVOKE ALL ON FUNCTION policy_trust_key(uuid, text, text, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION policy_activate_version(uuid, uuid) FROM PUBLIC;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'policy_publisher') THEN
    GRANT EXECUTE ON FUNCTION policy_trust_key(uuid, text, text, boolean) TO policy_publisher;
    GRANT EXECUTE ON FUNCTION policy_activate_version(uuid, uuid) TO policy_publisher;
    REVOKE INSERT, UPDATE ON policy_signing_keys FROM policy_publisher;
    REVOKE INSERT, UPDATE ON active_config FROM policy_publisher;
  END IF;
END $$;
