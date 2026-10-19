-- 027: consume-time serialization on the active-config row without granting
-- runtime roles any write access.
--
-- §9.2 has the consume transaction serialize on the active-config row before
-- it re-validates policy and commits an execution intent, so an activation
-- cannot swap the signed bundle out from under a dispatch. A bare
-- `SELECT ... FOR SHARE` cannot do that from the runtime roles: PostgreSQL
-- checks the locking clause against UPDATE privilege (not SELECT), and
-- gateway_runtime deliberately has none — §13.4 keeps every runtime role
-- unable to touch the trusted edition. The first e2e run of the two-phase
-- claim failed closed on exactly this (42501 on active_config).
--
-- This SECURITY DEFINER helper runs as policy_publisher, which owns the
-- writes, so the FOR SHARE lock passes the ACL check. Row locks belong to
-- the *transaction*, not the role, so the lock still lands on the calling
-- consume transaction: the publisher's activation UPDATE then waits for it
-- exactly as §9.2 intends, and gateway_runtime still cannot write anything.

CREATE OR REPLACE FUNCTION lock_active_config_share(p_workspace_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  PERFORM 1 FROM active_config WHERE workspace_id = p_workspace_id FOR SHARE;
END
$$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'policy_publisher') THEN
    ALTER FUNCTION lock_active_config_share(uuid) OWNER TO policy_publisher;
  END IF;
END
$$;

REVOKE ALL ON FUNCTION lock_active_config_share(uuid) FROM PUBLIC;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_runtime') THEN
    GRANT EXECUTE ON FUNCTION lock_active_config_share(uuid) TO gateway_runtime;
  END IF;
END
$$;
