-- §5.3 / §13.4: approval state changes go through narrow procedures owned by
-- a non-login role. The gateway keeps SELECT on approvals (for the control
-- surface and enforcement checks) but loses table-level INSERT/UPDATE. API
-- and retention roles never mutate approvals at all.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'approval_owner') THEN
    CREATE ROLE approval_owner NOLOGIN;
  END IF;
END $$;
GRANT USAGE ON SCHEMA public TO approval_owner;
GRANT SELECT, INSERT, UPDATE ON approvals TO approval_owner;

CREATE OR REPLACE FUNCTION approval_request(
  p_request_id text,
  p_workspace_id uuid,
  p_caller text,
  p_server_id uuid,
  p_tool_name text,
  p_args_hash text,
  p_args jsonb,
  p_args_enc boolean,
  p_requested_by text,
  p_ttl_seconds integer
) RETURNS SETOF approvals
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_row approvals%ROWTYPE;
BEGIN
  IF p_ttl_seconds IS NULL OR p_ttl_seconds <= 0 THEN
    RAISE EXCEPTION 'approval TTL must be positive';
  END IF;
  INSERT INTO approvals
    (request_id, workspace_id, caller, server_id, tool_name, args_hash, args,
     args_enc, requested_by, expires_at)
  VALUES
    (p_request_id, p_workspace_id, p_caller, p_server_id, p_tool_name,
     p_args_hash, p_args, p_args_enc, p_requested_by,
     now() + (p_ttl_seconds * interval '1 second'))
  ON CONFLICT (request_id) DO NOTHING
  RETURNING * INTO v_row;
  IF v_row.id IS NULL THEN
    RETURN;
  END IF;
  RETURN NEXT v_row;
  RETURN;
END;
$$;

CREATE OR REPLACE FUNCTION approval_decide(
  p_id uuid,
  p_approved boolean,
  p_decided_by text,
  p_reason text,
  p_summary text
) RETURNS SETOF approvals
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_row approvals%ROWTYPE;
BEGIN
  IF p_approved IS NULL THEN
    RAISE EXCEPTION 'approval decision must be explicit';
  END IF;
  UPDATE approvals
     SET status = CASE WHEN p_approved THEN 'approved' ELSE 'rejected' END,
         decided_by = p_decided_by,
         decided_at = now(),
         decision_reason = COALESCE(p_reason, ''),
         terminal_at = CASE WHEN p_approved THEN terminal_at ELSE now() END,
         args = CASE WHEN p_approved THEN args ELSE '{}'::jsonb END,
         args_enc = CASE WHEN p_approved THEN args_enc ELSE false END,
         args_summary = CASE WHEN p_approved THEN args_summary ELSE COALESCE(p_summary, '') END
   WHERE id = p_id AND status = 'pending'
  RETURNING * INTO v_row;
  IF v_row.id IS NULL THEN
    RETURN;
  END IF;
  RETURN NEXT v_row;
  RETURN;
END;
$$;

-- One whitelisted entry point for gateway enforcement transitions. The action
-- name is not interpolated into SQL; each branch has its own from-state guard.
CREATE OR REPLACE FUNCTION approval_transition(
  p_id uuid,
  p_action text,
  p_claim_id text DEFAULT NULL,
  p_reason text DEFAULT '',
  p_summary text DEFAULT '',
  p_is_error boolean DEFAULT NULL,
  p_outcome_hash text DEFAULT NULL,
  p_seconds integer DEFAULT NULL
) RETURNS SETOF approvals
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_row approvals%ROWTYPE;
  v_claim uuid;
  v_seconds integer;
BEGIN
  IF p_action IN ('claim', 'release_claim',
                  'invalidate_claimed_tool_quarantined',
                  'invalidate_claimed_policy', 'execute') THEN
    IF p_claim_id IS NULL OR btrim(p_claim_id) = '' THEN
      RAISE EXCEPTION 'claim_id is required for %', p_action;
    END IF;
    v_claim := p_claim_id::uuid;
  END IF;

  CASE p_action
    WHEN 'invalidate_approved_tool_quarantined' THEN
      UPDATE approvals
         SET status = 'tool_quarantined', terminal_at = now(),
             args = '{}'::jsonb, args_enc = false,
             args_summary = COALESCE(p_summary, '')
       WHERE id = p_id AND status = 'approved'
      RETURNING * INTO v_row;

    WHEN 'invalidate_approved_policy' THEN
      UPDATE approvals
         SET status = 'policy_invalidated', terminal_at = now(),
             decision_reason = COALESCE(p_reason, ''),
             args = '{}'::jsonb, args_enc = false,
             args_summary = COALESCE(p_summary, '')
       WHERE id = p_id AND status = 'approved'
      RETURNING * INTO v_row;

    WHEN 'expire_pending' THEN
      UPDATE approvals
         SET status = 'expired', terminal_at = now(),
             args = '{}'::jsonb, args_enc = false,
             args_summary = COALESCE(p_summary, '')
       WHERE id = p_id AND status = 'pending'
      RETURNING * INTO v_row;

    WHEN 'expire_approved' THEN
      UPDATE approvals
         SET status = 'expired', terminal_at = now(),
             args = '{}'::jsonb, args_enc = false,
             args_summary = COALESCE(p_summary, '')
       WHERE id = p_id AND status = 'approved'
      RETURNING * INTO v_row;

    WHEN 'claim' THEN
      v_seconds := COALESCE(p_seconds, 30);
      IF v_seconds <= 0 THEN
        RAISE EXCEPTION 'claim lease must be positive';
      END IF;
      UPDATE approvals
         SET status = 'claimed', claim_id = v_claim,
             claim_lease_expires_at = now() + (v_seconds * interval '1 second')
       WHERE id = p_id AND status = 'approved'
      RETURNING * INTO v_row;

    WHEN 'release_claim' THEN
      UPDATE approvals
         SET status = 'approved', claim_id = NULL, claim_lease_expires_at = NULL
       WHERE id = p_id AND status = 'claimed' AND claim_id = v_claim
      RETURNING * INTO v_row;

    WHEN 'invalidate_claimed_tool_quarantined' THEN
      UPDATE approvals
         SET status = 'tool_quarantined', terminal_at = now(),
             decision_reason = COALESCE(p_reason, ''),
             args = '{}'::jsonb, args_enc = false,
             args_summary = COALESCE(p_summary, '')
       WHERE id = p_id AND status = 'claimed' AND claim_id = v_claim
      RETURNING * INTO v_row;

    WHEN 'invalidate_claimed_policy' THEN
      UPDATE approvals
         SET status = 'policy_invalidated', terminal_at = now(),
             decision_reason = COALESCE(p_reason, ''),
             args = '{}'::jsonb, args_enc = false,
             args_summary = COALESCE(p_summary, '')
       WHERE id = p_id AND status = 'claimed' AND claim_id = v_claim
      RETURNING * INTO v_row;

    WHEN 'execute' THEN
      UPDATE approvals
         SET status = 'executing', execution_started_at = now(),
             args = '{}'::jsonb, args_enc = false,
             args_summary = COALESCE(p_summary, '')
       WHERE id = p_id AND status = 'claimed' AND claim_id = v_claim
      RETURNING * INTO v_row;

    WHEN 'outcome_unknown' THEN
      UPDATE approvals
         SET status = 'outcome_unknown', terminal_at = now(),
             outcome_summary = COALESCE(p_summary, '')
       WHERE id = p_id AND status = 'executing'
      RETURNING * INTO v_row;

    WHEN 'response_received' THEN
      UPDATE approvals
         SET status = 'response_received', response_is_error = p_is_error,
             terminal_at = now(), outcome_summary = COALESCE(p_summary, ''),
             outcome_hash = COALESCE(p_outcome_hash, '')
       WHERE id = p_id AND status = 'executing'
      RETURNING * INTO v_row;

    WHEN 'sweep_release' THEN
      UPDATE approvals
         SET status = 'approved', claim_id = NULL, claim_lease_expires_at = NULL
       WHERE id = p_id AND status = 'claimed'
         AND claim_lease_expires_at < now()
      RETURNING * INTO v_row;

    WHEN 'sweep_expire_claimed' THEN
      UPDATE approvals
         SET status = 'expired', terminal_at = now(),
             claim_id = NULL, claim_lease_expires_at = NULL,
             args = '{}'::jsonb, args_enc = false,
             args_summary = COALESCE(p_summary, '')
       WHERE id = p_id AND status = 'claimed'
         AND claim_lease_expires_at < now() AND expires_at <= now()
      RETURNING * INTO v_row;

    WHEN 'sweep_expire_executing' THEN
      UPDATE approvals
         SET status = 'outcome_unknown', terminal_at = now(),
             outcome_summary = COALESCE(p_summary, '')
       WHERE id = p_id AND status = 'executing'
      RETURNING * INTO v_row;

    ELSE
      RAISE EXCEPTION 'unknown approval transition: %', p_action;
  END CASE;

  IF v_row.id IS NULL THEN
    RETURN;
  END IF;
  RETURN NEXT v_row;
  RETURN;
END;
$$;

ALTER FUNCTION approval_request(text,uuid,text,uuid,text,text,jsonb,boolean,text,integer) OWNER TO approval_owner;
ALTER FUNCTION approval_decide(uuid,boolean,text,text,text) OWNER TO approval_owner;
ALTER FUNCTION approval_transition(uuid,text,text,text,text,boolean,text,integer) OWNER TO approval_owner;

REVOKE ALL ON FUNCTION approval_request(text,uuid,text,uuid,text,text,jsonb,boolean,text,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION approval_decide(uuid,boolean,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION approval_transition(uuid,text,text,text,text,boolean,text,integer) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION approval_request(text,uuid,text,uuid,text,text,jsonb,boolean,text,integer) TO gateway_runtime;
GRANT EXECUTE ON FUNCTION approval_decide(uuid,boolean,text,text,text) TO gateway_runtime;
GRANT EXECUTE ON FUNCTION approval_transition(uuid,text,text,text,text,boolean,text,integer) TO gateway_runtime;

-- No runtime service may mutate approvals directly. Gateway uses the three
-- procedures above; API and retention have no approval write path at all.
REVOKE INSERT, UPDATE, DELETE ON approvals FROM gateway_runtime, api_runtime, retention_job;
REVOKE DELETE ON approvals FROM approval_owner;
