-- FR-019: signed audit checkpoints and checkpoint-anchored pruning.
--
-- Append-only since migration 022 is tamper-evident, not tamper-proof: the
-- party holding the database can rewrite rows and recompute the chain. A
-- checkpoint signed with a key that never lives in the database or the
-- containers anchors the history externally.
--
-- Pruning deletes only events strictly older than the checkpoint's head row
-- and keeps that head row, so the surviving chain begins with a broken
-- prev-link whose expected hash is the checkpoint's up_to_hash — the
-- verifier treats that as anchored, never as corruption.
--
-- The append-only trigger is disabled only inside this owner's maintenance
-- function, inside a transaction serialized with appends on the chain lock
-- (852100000001, matching CHAIN_LOCK in @traceguard/audit-chain).

CREATE TABLE IF NOT EXISTS audit_checkpoints (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at timestamptz NOT NULL DEFAULT now(),
  up_to_timestamp timestamptz NOT NULL,
  up_to_hash text NOT NULL,
  event_count bigint NOT NULL CHECK (event_count >= 0),
  signature text NOT NULL,
  key_id text NOT NULL,
  payload jsonb NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_checkpoints_created ON audit_checkpoints (created_at DESC);

CREATE OR REPLACE FUNCTION guard_audit_checkpoint() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'audit checkpoints are retired, never deleted';
  END IF;
  RAISE EXCEPTION 'audit checkpoints are immutable; write a new checkpoint instead';
END $$;

DROP TRIGGER IF EXISTS audit_checkpoints_guard ON audit_checkpoints;
CREATE TRIGGER audit_checkpoints_guard BEFORE UPDATE OR DELETE ON audit_checkpoints
  FOR EACH ROW EXECUTE FUNCTION guard_audit_checkpoint();

CREATE OR REPLACE FUNCTION prune_audit_events(p_up_to_hash text) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  v_ts timestamptz;
  v_id uuid;
  v_deleted bigint;
BEGIN
  PERFORM pg_advisory_xact_lock(852100000001);
  SELECT timestamp, id INTO v_ts, v_id FROM audit_events WHERE hash = p_up_to_hash;
  IF v_id IS NULL THEN
    RETURN -1;
  END IF;
  ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only;
  DELETE FROM audit_events WHERE (timestamp, id) < (v_ts, v_id);
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only;
  RETURN v_deleted;
END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_owner') THEN
    ALTER TABLE audit_checkpoints OWNER TO audit_owner;
    ALTER FUNCTION prune_audit_events(text) OWNER TO audit_owner;
  END IF;
END $$;

REVOKE ALL ON FUNCTION prune_audit_events(text) FROM PUBLIC;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_runtime') THEN
    GRANT EXECUTE ON FUNCTION prune_audit_events(text) TO gateway_runtime;
    GRANT SELECT, INSERT ON audit_checkpoints TO gateway_runtime;
  END IF;
END $$;
