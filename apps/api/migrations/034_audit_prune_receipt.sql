-- §10.2 / FR-019: the external receipt is part of the prune contract, not
-- merely advice enforced by the operator CLI. A direct `retention_job` call
-- with a blank reference must fail too.
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

  IF p_external_ref IS NULL OR btrim(p_external_ref) = '' THEN
    RAISE EXCEPTION 'prune requires a non-empty external receipt';
  END IF;

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
    ALTER FUNCTION prune_audit_events(uuid, text) OWNER TO audit_owner;
  END IF;
END $$;

REVOKE ALL ON FUNCTION prune_audit_events(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION prune_audit_events(uuid, text) TO retention_job;
