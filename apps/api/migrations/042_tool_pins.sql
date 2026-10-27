-- FR-017: tool definitions are immutable pin versions, not rows that are
-- overwritten on discovery. A changed definition becomes a candidate; an
-- admin submits it for review, approves it for publication, and the publisher
-- activates it while signing the next policy bundle. Calls stay blocked until
-- that activation lands, so a quarantine cannot be cleared by a shortcut.
CREATE TABLE IF NOT EXISTS tool_pins (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  server_id uuid NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
  tool_name text NOT NULL,
  version integer NOT NULL CHECK (version > 0),
  definition jsonb NOT NULL,
  definition_hash text NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'candidate', 'pending_review', 'approved', 'superseded')),
  quarantine_reason text,
  created_at timestamptz NOT NULL DEFAULT now(),
  reviewed_at timestamptz,
  reviewed_by text,
  UNIQUE (server_id, tool_name, version)
);

-- Exactly one active version per tool. The activation procedure makes the old
-- active row superseded before promoting the candidate, inside one transaction.
CREATE UNIQUE INDEX IF NOT EXISTS tool_pins_one_active
  ON tool_pins (server_id, tool_name) WHERE status = 'active';

-- A pin's identity and definition are append-only. Status and review fields may
-- move through the workflow, but an approved definition can never be edited in
-- place; a re-approval creates another version.
CREATE OR REPLACE FUNCTION tool_pins_reject_definition_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.server_id IS DISTINCT FROM OLD.server_id
     OR NEW.tool_name IS DISTINCT FROM OLD.tool_name
     OR NEW.version IS DISTINCT FROM OLD.version
     OR NEW.definition IS DISTINCT FROM OLD.definition
     OR NEW.definition_hash IS DISTINCT FROM OLD.definition_hash THEN
    RAISE EXCEPTION 'tool pin definitions are immutable';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS tool_pins_immutable ON tool_pins;
CREATE TRIGGER tool_pins_immutable
  BEFORE UPDATE ON tool_pins
  FOR EACH ROW EXECUTE FUNCTION tool_pins_reject_definition_change();

ALTER TABLE server_tools
  ADD COLUMN IF NOT EXISTS active_pin_id uuid REFERENCES tool_pins(id),
  ADD COLUMN IF NOT EXISTS candidate_pin_id uuid REFERENCES tool_pins(id);

-- Backfill the current reviewed definition as version 1 and the quarantined
-- upstream definition as a candidate when it differs. server_tools keeps the
-- active definition/hash/version so existing read paths stay coherent while the
-- new pointer columns are rolled out.
DO $$
DECLARE
  r record;
  v_active_id uuid;
  v_candidate_id uuid;
  v_active_definition jsonb;
  v_active_hash text;
BEGIN
  FOR r IN
    SELECT server_id, tool_name, definition, definition_hash,
           previous_definition, previous_hash, quarantined, quarantine_reason,
           updated_at
      FROM server_tools
     WHERE active_pin_id IS NULL
     ORDER BY server_id, tool_name
  LOOP
    IF r.quarantined AND r.previous_definition IS NOT NULL THEN
      v_active_definition := r.previous_definition;
      v_active_hash := COALESCE(r.previous_hash, r.definition_hash);
    ELSE
      v_active_definition := r.definition;
      v_active_hash := r.definition_hash;
    END IF;

    INSERT INTO tool_pins
      (server_id, tool_name, version, definition, definition_hash, status,
       quarantine_reason, created_at)
    VALUES
      (r.server_id, r.tool_name, 1, v_active_definition, v_active_hash, 'active',
       NULL, COALESCE(r.updated_at, now()))
    RETURNING id INTO v_active_id;

    UPDATE server_tools
       SET active_pin_id = v_active_id,
           definition = v_active_definition,
           definition_hash = v_active_hash,
           description = COALESCE(v_active_definition->>'description', ''),
           input_schema = COALESCE(v_active_definition->'inputSchema', '{}'::jsonb),
           definition_version = 1
     WHERE server_id = r.server_id AND tool_name = r.tool_name;

    IF r.quarantined AND r.definition_hash IS DISTINCT FROM v_active_hash THEN
      INSERT INTO tool_pins
        (server_id, tool_name, version, definition, definition_hash, status,
         quarantine_reason, created_at)
      VALUES
        (r.server_id, r.tool_name, 2, r.definition, r.definition_hash, 'candidate',
         COALESCE(r.quarantine_reason, 'definition changed'), now())
      RETURNING id INTO v_candidate_id;

      UPDATE server_tools
         SET candidate_pin_id = v_candidate_id
       WHERE server_id = r.server_id AND tool_name = r.tool_name;
    END IF;
  END LOOP;
END $$;

GRANT SELECT, INSERT, UPDATE ON tool_pins TO api_runtime;
GRANT SELECT ON tool_pins TO gateway_runtime;
GRANT SELECT ON tool_pins TO policy_publisher;
GRANT SELECT ON mcp_servers TO policy_owner;
GRANT SELECT, INSERT, UPDATE ON tool_pins TO policy_owner;
GRANT SELECT, UPDATE ON server_tools TO policy_owner;

-- Called by the publisher in the same transaction as policy activation. Only
-- an admin-approved candidate can be promoted, and the old active pin is kept
-- as superseded history. Returns the number of tools activated.
CREATE OR REPLACE FUNCTION activate_approved_tool_pins(
  p_project_id uuid
) RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  r record;
  v_count integer := 0;
BEGIN
  IF p_project_id IS NULL THEN
    RAISE EXCEPTION 'project id is required';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtext('tool-pins:' || p_project_id::text));
  FOR r IN
    SELECT st.server_id, st.tool_name, st.active_pin_id, st.candidate_pin_id,
           ap.definition AS old_definition, ap.definition_hash AS old_hash,
           cp.id AS candidate_id, cp.version AS candidate_version,
           cp.definition AS candidate_definition, cp.definition_hash AS candidate_hash
      FROM server_tools st
      JOIN mcp_servers s ON s.id = st.server_id
      JOIN tool_pins ap ON ap.id = st.active_pin_id
      JOIN tool_pins cp ON cp.id = st.candidate_pin_id AND cp.status = 'approved'
     WHERE s.project_id = p_project_id
     ORDER BY st.server_id, st.tool_name
  LOOP
    UPDATE tool_pins SET status = 'superseded' WHERE id = r.active_pin_id;
    UPDATE tool_pins SET status = 'active' WHERE id = r.candidate_id;
    UPDATE server_tools
       SET active_pin_id = r.candidate_id,
           candidate_pin_id = NULL,
           previous_definition = r.old_definition,
           previous_hash = r.old_hash,
           definition = r.candidate_definition,
           definition_hash = r.candidate_hash,
           description = COALESCE(r.candidate_definition->>'description', ''),
           input_schema = COALESCE(r.candidate_definition->'inputSchema', '{}'::jsonb),
           definition_version = r.candidate_version,
           quarantined = false,
           quarantine_reason = NULL,
           updated_at = now()
     WHERE server_id = r.server_id AND tool_name = r.tool_name;
    v_count := v_count + 1;
  END LOOP;
  RETURN v_count;
END;
$$;

ALTER FUNCTION activate_approved_tool_pins(uuid) OWNER TO policy_owner;
REVOKE ALL ON FUNCTION activate_approved_tool_pins(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION activate_approved_tool_pins(uuid) TO policy_publisher;
