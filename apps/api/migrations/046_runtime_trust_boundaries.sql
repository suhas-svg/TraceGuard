-- 046: close the remaining API writes to trusted tool state.
--
-- §13.4 and §14 forbid a runtime service account from holding table-level
-- UPDATE on the active tool definition pin. The admin workflow still needs to
-- move pins through review, so the writes move into two narrow SECURITY
-- DEFINER procedures owned by the non-login policy_owner. The API keeps
-- INSERT for append-only discovery; it loses UPDATE and the trace DELETE
-- grants that let it rewrite or erase execution evidence.
--
-- Idempotent: db-roles re-applies every migration on boot.

CREATE OR REPLACE FUNCTION api_set_tool_pin_status(
  p_pin_id uuid,
  p_status text,
  p_reviewed_by text DEFAULT NULL,
  p_reason text DEFAULT NULL
) RETURNS SETOF tool_pins
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_pin tool_pins%ROWTYPE;
BEGIN
  SELECT * INTO v_pin FROM tool_pins WHERE id = p_pin_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tool pin not found';
  END IF;

  IF p_status = 'superseded' THEN
    IF v_pin.status NOT IN ('candidate', 'pending_review', 'approved') THEN
      RAISE EXCEPTION 'pin % cannot move from % to superseded', p_pin_id, v_pin.status;
    END IF;
  ELSIF p_status = 'pending_review' THEN
    IF v_pin.status <> 'candidate' THEN
      RAISE EXCEPTION 'pin % cannot move from % to pending_review', p_pin_id, v_pin.status;
    END IF;
  ELSIF p_status = 'approved' THEN
    IF v_pin.status <> 'pending_review' THEN
      RAISE EXCEPTION 'pin % cannot move from % to approved', p_pin_id, v_pin.status;
    END IF;
  ELSE
    RAISE EXCEPTION 'unsupported pin transition %', p_status;
  END IF;

  UPDATE tool_pins
     SET status = p_status,
         quarantine_reason = CASE
           WHEN p_status = 'approved' THEN NULL
           WHEN p_reason IS NOT NULL THEN p_reason
           ELSE quarantine_reason
         END,
         reviewed_at = CASE WHEN p_status = 'approved' THEN now() ELSE reviewed_at END,
         reviewed_by = CASE WHEN p_status = 'approved' THEN p_reviewed_by ELSE reviewed_by END
   WHERE id = p_pin_id;

  RETURN QUERY SELECT * FROM tool_pins WHERE id = p_pin_id;
END;
$$;

CREATE OR REPLACE FUNCTION api_set_server_tool_state(
  p_server_id uuid,
  p_tool_name text,
  p_active_pin_id uuid DEFAULT NULL,
  p_set_candidate boolean DEFAULT false,
  p_candidate_pin_id uuid DEFAULT NULL,
  p_quarantined boolean DEFAULT NULL,
  p_reason text DEFAULT NULL
) RETURNS SETOF server_tools
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_pin tool_pins%ROWTYPE;
BEGIN
  IF p_active_pin_id IS NOT NULL THEN
    SELECT * INTO v_pin FROM tool_pins WHERE id = p_active_pin_id;
    IF NOT FOUND OR v_pin.server_id <> p_server_id OR v_pin.tool_name <> p_tool_name
       OR v_pin.status <> 'active' THEN
      RAISE EXCEPTION 'active pin does not belong to this tool';
    END IF;
  END IF;

  IF p_set_candidate AND p_candidate_pin_id IS NOT NULL THEN
    SELECT * INTO v_pin FROM tool_pins WHERE id = p_candidate_pin_id;
    IF NOT FOUND OR v_pin.server_id <> p_server_id OR v_pin.tool_name <> p_tool_name
       OR v_pin.status NOT IN ('candidate', 'pending_review', 'approved') THEN
      RAISE EXCEPTION 'candidate pin does not belong to this tool';
    END IF;
  END IF;

  UPDATE server_tools
     SET active_pin_id = COALESCE(p_active_pin_id, active_pin_id),
         candidate_pin_id = CASE
           WHEN p_set_candidate THEN p_candidate_pin_id
           ELSE candidate_pin_id
         END,
         quarantined = CASE
           WHEN p_quarantined IS NULL THEN quarantined
           ELSE p_quarantined
         END,
         quarantine_reason = CASE
           WHEN p_quarantined IS FALSE THEN NULL
           WHEN p_reason IS NOT NULL THEN p_reason
           ELSE quarantine_reason
         END,
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

ALTER FUNCTION api_set_tool_pin_status(uuid, text, text, text) OWNER TO policy_owner;
ALTER FUNCTION api_set_server_tool_state(uuid, text, uuid, boolean, uuid, boolean, text) OWNER TO policy_owner;

REVOKE ALL ON FUNCTION api_set_tool_pin_status(uuid, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION api_set_server_tool_state(uuid, text, uuid, boolean, uuid, boolean, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION api_set_tool_pin_status(uuid, text, text, text) TO api_runtime;
GRANT EXECUTE ON FUNCTION api_set_server_tool_state(uuid, text, uuid, boolean, uuid, boolean, text) TO api_runtime;

REVOKE UPDATE ON tool_pins FROM api_runtime;
REVOKE UPDATE ON server_tools FROM api_runtime;
REVOKE DELETE ON runs FROM api_runtime;
REVOKE DELETE ON spans FROM api_runtime;
