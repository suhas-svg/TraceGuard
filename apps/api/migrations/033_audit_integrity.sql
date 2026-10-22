-- 033: audit-integrity fixes from the independent spec audit.
--
-- 1) §10.1: the event ID and per-workspace sequence are part of the hashed
--    event fields. v2 hashed neither, so a database owner could rewrite an
--    ID or sequence without changing the hash. New events use hash_version 3;
--    v1/v2 rows keep verifying with their original formula.
-- 2) The append path allocates the sequence and reads the chain head in one
--    transaction (prepare_audit_append) and then inserts the pre-hashed event
--    (append_audit_event). The advisory lock is transaction-scoped, so the
--    head cannot move between allocation and insert. A durable head table
--    keeps the per-workspace sequence continuing across a prune.
-- 3) §10.2: checkpoints are created and pruned by the operator-side
--    `audit:checkpoint` CLI, not by the gateway. The gateway keeps only the
--    public verification key. A checkpoint is anchored at the *last event in
--    the pruned segment* and prune deletes through that event; the first
--    retained event therefore links to the checkpoint hash.

ALTER TABLE audit_checkpoints ADD COLUMN IF NOT EXISTS up_to_event_id uuid;

CREATE TABLE IF NOT EXISTS audit_chain_heads (
  workspace_id uuid PRIMARY KEY,
  last_seq bigint NOT NULL DEFAULT 0,
  head_hash text NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS audit_chain_state (
  id boolean PRIMARY KEY DEFAULT true CHECK (id),
  head_hash text NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS audit_prunes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  checkpoint_id uuid NOT NULL REFERENCES audit_checkpoints(id),
  pruned_at timestamptz NOT NULL DEFAULT now(),
  deleted bigint NOT NULL CHECK (deleted >= 0),
  external_ref text NOT NULL
);

-- Seed the per-workspace sequence state from whatever v1/v2 history exists.
-- Unattributed legacy rows use the all-zero UUID as their group key.
INSERT INTO audit_chain_heads (workspace_id, last_seq, head_hash)
SELECT DISTINCT ON (COALESCE(workspace_id, '00000000-0000-0000-0000-000000000000'::uuid))
       COALESCE(workspace_id, '00000000-0000-0000-0000-000000000000'::uuid),
       COALESCE(seq, 0), hash
  FROM audit_events
 ORDER BY COALESCE(workspace_id, '00000000-0000-0000-0000-000000000000'::uuid),
          timestamp DESC, id DESC
ON CONFLICT (workspace_id) DO NOTHING;

INSERT INTO audit_chain_state (id, head_hash)
SELECT true, COALESCE((
  SELECT hash FROM audit_events ORDER BY timestamp DESC, id DESC LIMIT 1
), '')
ON CONFLICT (id) DO NOTHING;

-- Allocate the next per-workspace sequence and return the current global head
-- while holding the chain lock. The caller hashes with both values and then
-- calls append_audit_event in the same transaction.
CREATE OR REPLACE FUNCTION prepare_audit_append(p_workspace_id uuid)
RETURNS TABLE(prev_hash text, seq bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_ws uuid := COALESCE(p_workspace_id, '00000000-0000-0000-0000-000000000000'::uuid);
  v_head text;
  v_seq bigint;
BEGIN
  PERFORM pg_advisory_xact_lock(852100000001);

  SELECT head_hash INTO v_head FROM audit_chain_state WHERE id;
  IF v_head IS NULL THEN
    SELECT COALESCE(up_to_hash, '') INTO v_head
      FROM audit_checkpoints
     ORDER BY created_at DESC
     LIMIT 1;
  END IF;

  -- The test/dev reset truncates this table. Without the anchor row the
  -- UPDATE below would match nothing and every append would see the empty
  -- head, producing sibling roots instead of a chain.
  INSERT INTO audit_chain_state (id, head_hash)
  VALUES (true, COALESCE(v_head, ''))
  ON CONFLICT (id) DO NOTHING;

  INSERT INTO audit_chain_heads (workspace_id, last_seq, head_hash)
  VALUES (v_ws, 1, '')
  ON CONFLICT (workspace_id)
  DO UPDATE SET last_seq = audit_chain_heads.last_seq + 1
  RETURNING last_seq INTO v_seq;

  RETURN QUERY SELECT COALESCE(v_head, ''), v_seq;
END $$;

-- Drop the old overloads so no runtime can append without an ID/sequence.
DROP FUNCTION IF EXISTS append_audit_event(
  timestamptz, text, text, text, text, text, text, jsonb, text, text
);
DROP FUNCTION IF EXISTS append_audit_event(
  timestamptz, text, text, text, text, text, text, jsonb, text, text,
  uuid, smallint, uuid, jsonb
);

CREATE OR REPLACE FUNCTION append_audit_event(
  p_id uuid,
  p_timestamp timestamptz,
  p_actor_type text, p_actor_id text, p_action text,
  p_resource_type text, p_resource_id text, p_result text,
  p_metadata jsonb, p_prev_hash text, p_hash text,
  p_workspace_id uuid, p_seq bigint,
  p_hash_version smallint DEFAULT 3,
  p_policy_version_id uuid DEFAULT NULL,
  p_matched_rule_ids jsonb DEFAULT NULL
) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  head text;
  v_ws uuid := COALESCE(p_workspace_id, '00000000-0000-0000-0000-000000000000'::uuid);
BEGIN
  -- prepare_audit_append already took this lock; taking it again is harmless
  -- and keeps a direct caller from appending without serialization.
  PERFORM pg_advisory_xact_lock(852100000001);

  SELECT head_hash INTO head FROM audit_chain_state WHERE id;
  IF COALESCE(head, '') <> COALESCE(p_prev_hash, '') THEN
    RETURN false;
  END IF;

  INSERT INTO audit_events
    (id, timestamp, actor_type, actor_id, action, resource_type, resource_id,
     result, metadata, prev_hash, hash,
     workspace_id, seq, hash_version, policy_version_id, matched_rule_ids)
  VALUES
    (p_id, p_timestamp, p_actor_type, p_actor_id, p_action, p_resource_type,
     p_resource_id, p_result, COALESCE(p_metadata, '{}'::jsonb), p_prev_hash,
     p_hash, p_workspace_id, p_seq, COALESCE(p_hash_version, 3),
     p_policy_version_id, p_matched_rule_ids);

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

-- §10.2: prune through the checkpoint's last event. The retained chain then
-- starts immediately after it, with prev_hash = checkpoint.up_to_hash. If the
-- whole chain is pruned, the durable state keeps that hash so the next append
-- continues from the checkpoint rather than pretending the history began at
-- the empty string.
DROP FUNCTION IF EXISTS prune_audit_events(text);

CREATE OR REPLACE FUNCTION prune_audit_events(p_checkpoint_id uuid, p_external_ref text)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_event_id uuid;
  v_hash text;
  v_ts timestamptz;
  v_id uuid;
  v_deleted bigint;
  v_tail text;
BEGIN
  PERFORM pg_advisory_xact_lock(852100000001);

  SELECT up_to_event_id, up_to_hash INTO v_event_id, v_hash
    FROM audit_checkpoints WHERE id = p_checkpoint_id;
  IF v_hash IS NULL THEN
    RETURN -1;
  END IF;
  IF v_event_id IS NULL THEN
    SELECT id INTO v_event_id FROM audit_events WHERE hash = v_hash LIMIT 1;
  END IF;
  IF v_event_id IS NULL THEN
    RETURN -1;
  END IF;

  SELECT timestamp, id INTO v_ts, v_id FROM audit_events WHERE id = v_event_id;
  IF v_id IS NULL THEN
    RETURN -1;
  END IF;

  ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only;
  DELETE FROM audit_events WHERE (timestamp, id) <= (v_ts, v_id);
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only;

  SELECT hash INTO v_tail FROM audit_events ORDER BY timestamp DESC, id DESC LIMIT 1;
  INSERT INTO audit_chain_state (id, head_hash)
  VALUES (true, COALESCE(v_tail, v_hash))
  ON CONFLICT (id) DO UPDATE SET head_hash = EXCLUDED.head_hash;

  INSERT INTO audit_prunes (checkpoint_id, deleted, external_ref)
  VALUES (p_checkpoint_id, v_deleted, p_external_ref);

  RETURN v_deleted;
END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_owner') THEN
    ALTER TABLE audit_chain_heads OWNER TO audit_owner;
    ALTER TABLE audit_chain_state OWNER TO audit_owner;
    ALTER TABLE audit_prunes OWNER TO audit_owner;
    ALTER FUNCTION prepare_audit_append(uuid) OWNER TO audit_owner;
    ALTER FUNCTION append_audit_event(
      uuid, timestamptz, text, text, text, text, text, text, jsonb, text, text,
      uuid, bigint, smallint, uuid, jsonb
    ) OWNER TO audit_owner;
    ALTER FUNCTION prune_audit_events(uuid, text) OWNER TO audit_owner;
  END IF;
END $$;

REVOKE ALL ON FUNCTION prepare_audit_append(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION append_audit_event(
  uuid, timestamptz, text, text, text, text, text, text, jsonb, text, text,
  uuid, bigint, smallint, uuid, jsonb
) FROM PUBLIC;
REVOKE ALL ON FUNCTION prune_audit_events(uuid, text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION prepare_audit_append(uuid)
  TO api_runtime, gateway_runtime, policy_publisher, retention_job;
GRANT EXECUTE ON FUNCTION append_audit_event(
  uuid, timestamptz, text, text, text, text, text, text, jsonb, text, text,
  uuid, bigint, smallint, uuid, jsonb
) TO api_runtime, gateway_runtime, policy_publisher, retention_job;
GRANT EXECUTE ON FUNCTION prune_audit_events(uuid, text) TO retention_job;

-- The gateway may verify/export checkpoints and read the chain, but it may
-- neither sign/store a checkpoint nor prune one. The operator CLI connects
-- with the retention role for those two operations.
REVOKE INSERT ON audit_checkpoints FROM gateway_runtime;
GRANT SELECT, INSERT ON audit_checkpoints TO retention_job;
-- The operator CLI signs with a host key, then reads the exact prefix and
-- invokes the retention-only prune function.
GRANT SELECT ON audit_events TO retention_job;
GRANT SELECT ON audit_prunes TO api_runtime, gateway_runtime;
GRANT SELECT ON audit_chain_heads, audit_chain_state TO api_runtime, gateway_runtime;
