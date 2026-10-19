-- 028: round-2 spec-conformance fixes.
--
-- 1) §10.1/§10.2: the audit chain moves to a canonical (RFC 8785) hash with
--    per-workspace sequence allocation and policy attribution. Existing
--    events stay on hash_version 1 and keep verifying through the legacy
--    formula; new appends use hash_version 2. The append function allocates
--    the per-workspace sequence under the chain lock. The sequence is
--    deliberately NOT part of the hash input: the appender computes the hash
--    before the database allocates the counter, and chain integrity rests on
--    the previous_hash linkage (see @traceguard/audit-chain).
-- 2) §11.3: runs that never send a terminal event are ORPHANED, not failed.
-- 3) §13.4: gateway_runtime loses SELECT on users.password_hash; it keeps
--    the (id, role) columns its auth join needs.

ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS workspace_id uuid;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS seq bigint;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS hash_version smallint NOT NULL DEFAULT 1;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS policy_version_id uuid;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS matched_rule_ids jsonb;
CREATE INDEX IF NOT EXISTS idx_audit_events_workspace_seq
  ON audit_events (workspace_id, seq);

-- The 10-argument form is replaced by the extended one; dropping first is
-- what allows a single non-overloaded signature (callers always go through
-- @traceguard/audit-chain, which passes all 14 arguments).
DROP FUNCTION IF EXISTS append_audit_event(
  timestamptz, text, text, text, text, text, text, jsonb, text, text
);

-- Idempotent on re-run: db-roles re-applies every migration on each boot.
CREATE OR REPLACE FUNCTION append_audit_event(
  p_timestamp timestamptz,
  p_actor_type text, p_actor_id text, p_action text,
  p_resource_type text, p_resource_id text, p_result text,
  p_metadata jsonb, p_prev_hash text, p_hash text,
  p_workspace_id uuid DEFAULT NULL, p_hash_version smallint DEFAULT 2,
  p_policy_version_id uuid DEFAULT NULL, p_matched_rule_ids jsonb DEFAULT NULL
) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  head text;
  v_seq bigint;
BEGIN
  -- One appender at a time: two writers reading the same tail would append
  -- sibling rows, and a legitimate fork is indistinguishable from tampering.
  -- The lock id matches CHAIN_LOCK in @traceguard/audit-chain, which owns
  -- the hash formula; this function owns serialization, the head check and
  -- the per-workspace sequence.
  PERFORM pg_advisory_xact_lock(852100000001);

  SELECT hash INTO head FROM audit_events ORDER BY timestamp DESC, id DESC LIMIT 1;
  -- False, not an exception: a caller inside a transaction must be able to
  -- retry against the moved head, and a raised error would abort its
  -- transaction (the approval execution-intent path appends in one).
  IF coalesce(head, '') <> coalesce(p_prev_hash, '') THEN
    RETURN false;
  END IF;

  -- Per-workspace sequence under the lock; rows without a workspace form
  -- their own group via IS NOT DISTINCT FROM.
  SELECT coalesce(max(seq), 0) + 1 INTO v_seq FROM audit_events
   WHERE workspace_id IS NOT DISTINCT FROM p_workspace_id;

  INSERT INTO audit_events
    (timestamp, actor_type, actor_id, action, resource_type, resource_id,
     result, metadata, prev_hash, hash,
     workspace_id, seq, hash_version, policy_version_id, matched_rule_ids)
  VALUES (p_timestamp, p_actor_type, p_actor_id, p_action, p_resource_type,
          p_resource_id, p_result, coalesce(p_metadata, '{}'::jsonb), p_prev_hash, p_hash,
          p_workspace_id, v_seq, coalesce(p_hash_version, 2), p_policy_version_id, p_matched_rule_ids);
  RETURN true;
END $$;

-- §10.1: append function owned by the non-login audit role (mirrors 025).
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_owner') THEN
    ALTER FUNCTION append_audit_event(
      timestamptz, text, text, text, text, text, text, jsonb, text, text,
      uuid, smallint, uuid, jsonb
    ) OWNER TO audit_owner;
  END IF;
END $$;

-- Functions default to PUBLIC EXECUTE; membership of this one is explicit.
REVOKE EXECUTE ON FUNCTION append_audit_event(
  timestamptz, text, text, text, text, text, text, jsonb, text, text,
  uuid, smallint, uuid, jsonb
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION append_audit_event(
  timestamptz, text, text, text, text, text, text, jsonb, text, text,
  uuid, smallint, uuid, jsonb
) TO api_runtime, gateway_runtime, policy_publisher;

-- §11.3: runs with no terminal event inside the window are ORPHANED.
ALTER TABLE runs DROP CONSTRAINT IF EXISTS runs_status_check;
ALTER TABLE runs ADD CONSTRAINT runs_status_check
  CHECK (status IN ('running','success','failed','cancelled','orphaned'));

-- §13.4: the enforcement runtime must not read human password hashes. The
-- (id, role) columns remain: the shared auth path joins api_keys to users
-- for role-scoped principals.
REVOKE SELECT ON users FROM gateway_runtime;
GRANT SELECT (id, role) ON users TO gateway_runtime;
