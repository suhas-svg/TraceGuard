-- 050: remove the API's ability to activate or unquarantine tool pins.
--
-- 046 moved the admin writes into api_set_server_tool_state, but that
-- procedure still accepted p_quarantined = false and an arbitrary
-- p_active_pin_id.  A compromised api_runtime could therefore undo a
-- quarantine or promote a pin without a new signed bundle.  This migration
-- replaces it with three procedures that cannot perform either transition:
--
--   api_initialize_tool_pin      first discovery only, no existing pin history
--   api_create_tool_pin_candidate candidate/pending-review rows only
--   api_set_tool_review_state    sets a candidate and always quarantines
--
-- Activation remains exclusive to activate_approved_tool_pins(), owned by
-- policy_owner and executable only by policy_publisher.
--
-- Idempotent: the db-roles bootstrap re-applies every migration on boot.

BEGIN;

DROP FUNCTION IF EXISTS api_set_server_tool_state(uuid, text, uuid, boolean, uuid, boolean, text);

CREATE OR REPLACE FUNCTION api_initialize_tool_pin(
  p_server_id uuid,
  p_tool_name text,
  p_definition jsonb,
  p_definition_hash text,
  p_description text DEFAULT '',
  p_input_schema jsonb DEFAULT '{}'::jsonb
) RETURNS SETOF tool_pins
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_pin tool_pins%ROWTYPE;
BEGIN
  IF p_server_id IS NULL OR p_tool_name IS NULL OR length(p_tool_name) = 0 THEN
    RAISE EXCEPTION 'server id and tool name are required';
  END IF;

  -- Serialize first discovery per tool so two concurrent discoveries cannot
  -- create two version-1 pins.
  PERFORM pg_advisory_xact_lock(
    hashtext('tool-init:' || p_server_id::text || ':' || p_tool_name)
  );

  IF NOT EXISTS (SELECT 1 FROM mcp_servers WHERE id = p_server_id) THEN
    RAISE EXCEPTION 'server not found';
  END IF;

  -- Initial activation is allowed only when the tool has never had a pin.
  -- Re-discovery, reapproval, and quarantine recovery must go through the
  -- candidate/review/publish path.
  IF EXISTS (
    SELECT 1 FROM tool_pins
     WHERE server_id = p_server_id AND tool_name = p_tool_name
  ) THEN
    RAISE EXCEPTION 'tool already has pin history';
  END IF;

  IF EXISTS (
    SELECT 1 FROM server_tools
     WHERE server_id = p_server_id AND tool_name = p_tool_name
  ) THEN
    RAISE EXCEPTION 'server tool already exists';
  END IF;

  INSERT INTO tool_pins
    (server_id, tool_name, version, definition, definition_hash, status)
  VALUES
    (p_server_id, p_tool_name, 1, p_definition, p_definition_hash, 'active')
  RETURNING * INTO v_pin;

  INSERT INTO server_tools
    (server_id, tool_name, description, input_schema, definition,
     definition_hash, definition_version, active_pin_id, quarantined)
  VALUES
    (p_server_id, p_tool_name, COALESCE(p_description, ''),
     COALESCE(p_input_schema, '{}'::jsonb), p_definition, p_definition_hash,
     1, v_pin.id, false);

  RETURN QUERY SELECT * FROM tool_pins WHERE id = v_pin.id;
END;
$$;

CREATE OR REPLACE FUNCTION api_create_tool_pin_candidate(
  p_server_id uuid,
  p_tool_name text,
  p_definition jsonb,
  p_definition_hash text,
  p_status text DEFAULT 'candidate',
  p_reason text DEFAULT NULL
) RETURNS SETOF tool_pins
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_version integer;
  v_pin tool_pins%ROWTYPE;
BEGIN
  IF p_status NOT IN ('candidate', 'pending_review') THEN
    RAISE EXCEPTION 'unsupported candidate status %', p_status;
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtext('tool-pin:' || p_server_id::text || ':' || p_tool_name)
  );

  IF NOT EXISTS (
    SELECT 1 FROM server_tools
     WHERE server_id = p_server_id AND tool_name = p_tool_name
  ) THEN
    RAISE EXCEPTION 'server tool not found';
  END IF;

  SELECT COALESCE(MAX(version), 0) + 1 INTO v_version
    FROM tool_pins
   WHERE server_id = p_server_id AND tool_name = p_tool_name;

  INSERT INTO tool_pins
    (server_id, tool_name, version, definition, definition_hash, status,
     quarantine_reason)
  VALUES
    (p_server_id, p_tool_name, v_version, p_definition, p_definition_hash,
     p_status, p_reason)
  RETURNING * INTO v_pin;

  RETURN QUERY SELECT * FROM tool_pins WHERE id = v_pin.id;
END;
$$;

CREATE OR REPLACE FUNCTION api_set_tool_review_state(
  p_server_id uuid,
  p_tool_name text,
  p_candidate_pin_id uuid DEFAULT NULL,
  p_set_candidate boolean DEFAULT false,
  p_reason text DEFAULT NULL
) RETURNS SETOF server_tools
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_pin tool_pins%ROWTYPE;
BEGIN
  IF p_set_candidate AND p_candidate_pin_id IS NOT NULL THEN
    SELECT * INTO v_pin FROM tool_pins WHERE id = p_candidate_pin_id;
    IF NOT FOUND OR v_pin.server_id <> p_server_id
       OR v_pin.tool_name <> p_tool_name
       OR v_pin.status NOT IN ('candidate', 'pending_review', 'approved') THEN
      RAISE EXCEPTION 'candidate pin does not belong to this tool';
    END IF;
  END IF;

  -- This procedure can only enter quarantine. Clearing it is an activation
  -- decision reserved for activate_approved_tool_pins() after a signed
  -- bundle has been published.
  UPDATE server_tools
     SET candidate_pin_id = CASE
           WHEN p_set_candidate THEN p_candidate_pin_id
           ELSE candidate_pin_id
         END,
         quarantined = true,
         quarantine_reason = COALESCE(p_reason, quarantine_reason),
         updated_at = now()
   WHERE server_id = p_server_id AND tool_name = p_tool_name;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'server tool not found';
  END IF;

  RETURN QUERY
    SELECT * FROM server_tools
     WHERE server_id = p_server_id AND tool_name = p_tool_name;
END;
$$;

ALTER FUNCTION api_initialize_tool_pin(uuid, text, jsonb, text, text, jsonb) OWNER TO policy_owner;
ALTER FUNCTION api_create_tool_pin_candidate(uuid, text, jsonb, text, text, text) OWNER TO policy_owner;
ALTER FUNCTION api_set_tool_review_state(uuid, text, uuid, boolean, text) OWNER TO policy_owner;

REVOKE ALL ON FUNCTION api_initialize_tool_pin(uuid, text, jsonb, text, text, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION api_create_tool_pin_candidate(uuid, text, jsonb, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION api_set_tool_review_state(uuid, text, uuid, boolean, text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION api_initialize_tool_pin(uuid, text, jsonb, text, text, jsonb) TO api_runtime;
GRANT EXECUTE ON FUNCTION api_create_tool_pin_candidate(uuid, text, jsonb, text, text, text) TO api_runtime;
GRANT EXECUTE ON FUNCTION api_set_tool_review_state(uuid, text, uuid, boolean, text) TO api_runtime;

-- The API reads pins and tool rows but cannot write them directly. All writes
-- now go through the procedures above or the publisher-only activation path.
REVOKE INSERT, UPDATE, DELETE ON tool_pins FROM api_runtime;
REVOKE INSERT, UPDATE, DELETE ON server_tools FROM api_runtime;

-- The SECURITY DEFINER bodies above run as policy_owner. It already has
-- SELECT/UPDATE on server_tools from migration 042; first-discovery
-- initialization also needs INSERT there. This grant is not inherited by
-- api_runtime, which only has EXECUTE on the narrow procedures.
GRANT INSERT ON server_tools TO policy_owner;

COMMIT;
