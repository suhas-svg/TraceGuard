-- 048: let the gateway reserve tool-call budget without direct money-table DML.
--
-- The gateway holds only SELECT on budgets (migration 024), so a tool-call hold
-- cannot be a table write. The writes move into two narrow SECURITY DEFINER
-- procedures owned by a non-login budget_owner. This also keeps the counters
-- and the reservation ledger in one atomic unit.
--
-- A hold is not spend. It reserves headroom while the upstream call is in
-- flight; the gateway releases it in a finally block. If the process dies, the
-- existing expired-hold sweep settles the hold at its reserved maximum, which
-- is the conservative recovery the spec asks for.
--
-- Idempotent: db-roles re-applies every migration on boot.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'budget_owner') THEN
    CREATE ROLE budget_owner NOLOGIN;
  END IF;
  GRANT USAGE ON SCHEMA public TO budget_owner;
  GRANT SELECT, UPDATE ON budgets TO budget_owner;
  GRANT SELECT, INSERT, UPDATE ON budget_reservations TO budget_owner;
END
$$;

CREATE OR REPLACE FUNCTION gateway_reserve_tool_call(
  p_workspace_id uuid,
  p_run_id uuid,
  p_agent_id uuid,
  p_amount_micro bigint,
  p_ttl_seconds integer
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_row RECORD;
  v_ids uuid[] := '{}';
  v_scopes text[] := '{}';
  v_spent bigint[] := '{}';
  v_reserved bigint[] := '{}';
  v_limits bigint[] := '{}';
  v_reservation uuid;
  v_reservation_ids uuid[] := '{}';
  i integer;
BEGIN
  -- With no attribution or no configured hold amount there is nothing to
  -- reserve. Returning an empty outcome keeps the call path unchanged.
  IF p_amount_micro IS NULL OR p_amount_micro <= 0
     OR (p_run_id IS NULL AND p_agent_id IS NULL) THEN
    RETURN jsonb_build_object(
      'reservation_ids', '[]'::jsonb,
      'budget_ids', '[]'::jsonb,
      'exhausted', NULL
    );
  END IF;

  -- Lock every covering block budget before deciding. The check and the
  -- increment then see one consistent set of counters, even under concurrent
  -- calls against the same run or agent.
  FOR v_row IN
    SELECT id, scope, spent_micro, reserved_micro, limit_micro
      FROM budgets
     WHERE workspace_id = p_workspace_id
       AND effect = 'block'
       AND ((scope = 'run' AND ref_id = p_run_id)
            OR (scope = 'agent' AND ref_id = p_agent_id))
     ORDER BY id
     FOR UPDATE
  LOOP
    v_ids := v_ids || v_row.id;
    v_scopes := v_scopes || v_row.scope;
    v_spent := v_spent || v_row.spent_micro;
    v_reserved := v_reserved || v_row.reserved_micro;
    v_limits := v_limits || v_row.limit_micro;
  END LOOP;

  IF array_length(v_ids, 1) IS NULL THEN
    RETURN jsonb_build_object(
      'reservation_ids', '[]'::jsonb,
      'budget_ids', '[]'::jsonb,
      'exhausted', NULL
    );
  END IF;

  -- All-or-nothing: every covering budget must have headroom for the hold.
  -- Nothing has been mutated yet, so an exhausted budget leaves no cleanup.
  FOR i IN 1..array_length(v_ids, 1) LOOP
    IF v_spent[i] + v_reserved[i] + p_amount_micro > v_limits[i] THEN
      RETURN jsonb_build_object(
        'reservation_ids', '[]'::jsonb,
        'budget_ids', '[]'::jsonb,
        'exhausted', jsonb_build_object(
          'id', v_ids[i],
          'scope', v_scopes[i],
          'spent_micro', v_spent[i],
          'reserved_micro', v_reserved[i],
          'limit_micro', v_limits[i]
        )
      );
    END IF;
  END LOOP;

  FOR i IN 1..array_length(v_ids, 1) LOOP
    UPDATE budgets
       SET reserved_micro = reserved_micro + p_amount_micro,
           updated_at = now()
     WHERE id = v_ids[i];

    INSERT INTO budget_reservations (budget_id, amount_micro, expires_at)
    VALUES (v_ids[i], p_amount_micro,
            now() + make_interval(secs => GREATEST(p_ttl_seconds, 1)))
    RETURNING id INTO v_reservation;

    v_reservation_ids := v_reservation_ids || v_reservation;
  END LOOP;

  RETURN jsonb_build_object(
    'reservation_ids', to_jsonb(v_reservation_ids),
    'budget_ids', to_jsonb(v_ids),
    'exhausted', NULL
  );
END;
$$;

CREATE OR REPLACE FUNCTION gateway_release_tool_call(
  p_workspace_id uuid,
  p_reservation_ids uuid[]
) RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_row RECORD;
  v_released integer := 0;
BEGIN
  IF p_reservation_ids IS NULL OR array_length(p_reservation_ids, 1) IS NULL THEN
    RETURN 0;
  END IF;

  -- Only this workspace's still-held reservations are released. A hold the
  -- expiry sweep already settled is deliberately ignored, so the reserved
  -- amount cannot be returned twice.
  FOR v_row IN
    SELECT r.id, r.budget_id, r.amount_micro
      FROM budget_reservations r
      JOIN budgets b ON b.id = r.budget_id
     WHERE r.id = ANY(p_reservation_ids)
       AND r.status = 'held'
       AND b.workspace_id = p_workspace_id
     ORDER BY r.id
     FOR UPDATE OF r, b
  LOOP
    UPDATE budget_reservations
       SET status = 'released', released_at = now()
     WHERE id = v_row.id;

    UPDATE budgets
       SET reserved_micro = GREATEST(0, reserved_micro - v_row.amount_micro),
           updated_at = now()
     WHERE id = v_row.budget_id;

    v_released := v_released + 1;
  END LOOP;

  RETURN v_released;
END;
$$;

ALTER FUNCTION gateway_reserve_tool_call(uuid, uuid, uuid, bigint, integer) OWNER TO budget_owner;
ALTER FUNCTION gateway_release_tool_call(uuid, uuid[]) OWNER TO budget_owner;

REVOKE ALL ON FUNCTION gateway_reserve_tool_call(uuid, uuid, uuid, bigint, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION gateway_release_tool_call(uuid, uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION gateway_reserve_tool_call(uuid, uuid, uuid, bigint, integer) TO gateway_runtime;
GRANT EXECUTE ON FUNCTION gateway_release_tool_call(uuid, uuid[]) TO gateway_runtime;
