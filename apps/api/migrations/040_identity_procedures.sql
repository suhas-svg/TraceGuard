-- NFR-008: api_runtime may read identity state but must not write it. A
-- compromised API process could otherwise insert an admin user or grant its
-- own key the approve scope, which would defeat the issuer-owned role model.
--
-- The writes move behind SECURITY DEFINER procedures owned by a no-login
-- identity_owner. Each procedure is deliberately narrow: it performs one
-- operation and returns only the columns the route is allowed to expose.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'identity_owner') THEN
    CREATE ROLE identity_owner NOLOGIN;
  END IF;
END $$;

GRANT USAGE ON SCHEMA public TO identity_owner;
GRANT SELECT, INSERT, UPDATE, DELETE ON users, api_keys, memberships TO identity_owner;
GRANT SELECT ON workspaces TO identity_owner;

REVOKE INSERT, UPDATE, DELETE ON users, api_keys, memberships FROM api_runtime;

CREATE OR REPLACE FUNCTION identity_bootstrap(
  p_email text,
  p_password_hash text
) RETURNS TABLE (id uuid, email text, role text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  -- First registration wins. The lock and the emptiness check stay in one
  -- procedure so two fresh-install registrations cannot both become admin.
  LOCK TABLE users IN EXCLUSIVE MODE;
  IF EXISTS (SELECT 1 FROM users) THEN
    RETURN;
  END IF;
  RETURN QUERY
    WITH inserted AS (
      INSERT INTO users (email, password_hash, role)
      VALUES (p_email, p_password_hash, 'admin')
      RETURNING users.id, users.email, users.role
    )
    SELECT i.id, i.email, i.role FROM inserted i;
END;
$$;

CREATE OR REPLACE FUNCTION identity_create_user(
  p_email text,
  p_password_hash text,
  p_role text
) RETURNS TABLE (id uuid, email text, role text, created_at timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  RETURN QUERY
    WITH inserted AS (
      INSERT INTO users (email, password_hash, role)
      VALUES (p_email, p_password_hash, p_role)
      RETURNING users.id, users.email, users.role, users.created_at
    )
    SELECT i.id, i.email, i.role, i.created_at FROM inserted i;
END;
$$;

CREATE OR REPLACE FUNCTION identity_create_login_key(
  p_user_id uuid,
  p_key_hash text,
  p_scopes jsonb,
  p_expires_at timestamptz
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  INSERT INTO api_keys (user_id, name, key_hash, scopes, expires_at)
  VALUES (p_user_id, 'login', p_key_hash, p_scopes, p_expires_at);
END;
$$;

CREATE OR REPLACE FUNCTION identity_create_key(
  p_user_id uuid,
  p_name text,
  p_key_hash text,
  p_scopes jsonb,
  p_workspace_id uuid,
  p_expires_at timestamptz
) RETURNS TABLE (
  id uuid, name text, scopes jsonb, workspace_id uuid,
  expires_at timestamptz, created_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  RETURN QUERY
    WITH inserted AS (
      INSERT INTO api_keys (user_id, name, key_hash, scopes, workspace_id, expires_at)
      VALUES (p_user_id, p_name, p_key_hash, p_scopes, p_workspace_id, p_expires_at)
      RETURNING api_keys.id, api_keys.name, api_keys.scopes, api_keys.workspace_id,
                api_keys.expires_at, api_keys.created_at
    )
    SELECT i.id, i.name, i.scopes, i.workspace_id, i.expires_at, i.created_at
    FROM inserted i;
END;
$$;

CREATE OR REPLACE FUNCTION identity_revoke_key_by_hash(
  p_key_hash text
) RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_id uuid;
BEGIN
  DELETE FROM api_keys WHERE key_hash = p_key_hash RETURNING api_keys.id INTO v_id;
  RETURN v_id;
END;
$$;

CREATE OR REPLACE FUNCTION identity_revoke_key(
  p_id uuid,
  p_user_id uuid
) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  DELETE FROM api_keys WHERE id = p_id AND user_id = p_user_id;
  RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION identity_grant_membership(
  p_user_id uuid,
  p_workspace_id uuid
) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  INSERT INTO memberships (user_id, workspace_id) VALUES (p_user_id, p_workspace_id);
  RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION identity_revoke_membership(
  p_user_id uuid,
  p_workspace_id uuid
) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  DELETE FROM memberships WHERE user_id = p_user_id AND workspace_id = p_workspace_id;
  RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION identity_touch_key(
  p_key_hash text
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  UPDATE api_keys SET last_used_at = now() WHERE key_hash = p_key_hash;
END;
$$;

ALTER FUNCTION identity_bootstrap(text, text) OWNER TO identity_owner;
ALTER FUNCTION identity_create_user(text, text, text) OWNER TO identity_owner;
ALTER FUNCTION identity_create_login_key(uuid, text, jsonb, timestamptz) OWNER TO identity_owner;
ALTER FUNCTION identity_create_key(uuid, text, text, jsonb, uuid, timestamptz) OWNER TO identity_owner;
ALTER FUNCTION identity_revoke_key_by_hash(text) OWNER TO identity_owner;
ALTER FUNCTION identity_revoke_key(uuid, uuid) OWNER TO identity_owner;
ALTER FUNCTION identity_grant_membership(uuid, uuid) OWNER TO identity_owner;
ALTER FUNCTION identity_revoke_membership(uuid, uuid) OWNER TO identity_owner;
ALTER FUNCTION identity_touch_key(text) OWNER TO identity_owner;

REVOKE ALL ON FUNCTION identity_bootstrap(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity_create_user(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity_create_login_key(uuid, text, jsonb, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity_create_key(uuid, text, text, jsonb, uuid, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity_revoke_key_by_hash(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity_revoke_key(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity_grant_membership(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity_revoke_membership(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity_touch_key(text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION identity_bootstrap(text, text) TO api_runtime;
GRANT EXECUTE ON FUNCTION identity_create_user(text, text, text) TO api_runtime;
GRANT EXECUTE ON FUNCTION identity_create_login_key(uuid, text, jsonb, timestamptz) TO api_runtime;
GRANT EXECUTE ON FUNCTION identity_create_key(uuid, text, text, jsonb, uuid, timestamptz) TO api_runtime;
GRANT EXECUTE ON FUNCTION identity_revoke_key_by_hash(text) TO api_runtime;
GRANT EXECUTE ON FUNCTION identity_revoke_key(uuid, uuid) TO api_runtime;
GRANT EXECUTE ON FUNCTION identity_grant_membership(uuid, uuid) TO api_runtime;
GRANT EXECUTE ON FUNCTION identity_revoke_membership(uuid, uuid) TO api_runtime;
GRANT EXECUTE ON FUNCTION identity_touch_key(text) TO api_runtime;
