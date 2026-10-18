-- 023_db_roles.sql
-- §13.4: least-privilege database roles, so "the API cannot rewrite signed
-- policy, alter audit history, or decide an approval" is a database privilege
-- rather than a convention every future code path must remember.
--
-- Roles are created NOLOGIN. A deployment enables LOGIN with a password from
-- its secret store and points the service's DATABASE_URL at it
-- (docs/operations.md); tests exercise each role with SET ROLE
-- (apps/api/tests/db-roles.test.ts). Two deviations from §13.4's table are
-- deliberate and recorded in docs/security.md:
--   * the gateway still holds UPDATE on approvals table-wise instead of
--     calling one procedure per transition (its transitions are CAS updates
--     written in one place; the API role holds none of them);
--   * the retention sweep runs inside the API process, so api_runtime keeps
--     the trace-data deletes; approval pruning goes through retention_job,
--     which the sweep uses when DATABASE_URL_RETENTION is set.

DO $$
DECLARE
  role_name text;
BEGIN
  FOREACH role_name IN ARRAY ARRAY[
    'api_runtime', 'gateway_runtime', 'policy_publisher',
    'retention_job', 'audit_owner', 'migration_owner'
  ] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN', role_name);
    END IF;
  END LOOP;
END $$;

GRANT USAGE ON SCHEMA public TO
  api_runtime, gateway_runtime, policy_publisher, retention_job, migration_owner;

-- §10.1: the audit table and its append function are owned by a role that
-- cannot log in. Runtime roles get EXECUTE on the function, never INSERT.
ALTER TABLE audit_events OWNER TO audit_owner;
-- 022 creates this trigger function; guard the ownership move so this file
-- still applies to a database that ran the earlier migrations in a
-- different order.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE p.proname = 'reject_audit_mutation' AND n.nspname = 'public'
  ) THEN
    ALTER FUNCTION reject_audit_mutation() OWNER TO audit_owner;
  END IF;
END $$;

CREATE OR REPLACE FUNCTION append_audit_event(
  p_timestamp timestamptz,
  p_actor_type text, p_actor_id text, p_action text,
  p_resource_type text, p_resource_id text, p_result text,
  p_metadata jsonb, p_prev_hash text, p_hash text
) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  head text;
BEGIN
  -- One appender at a time: two writers reading the same tail would append
  -- sibling rows, and a legitimate fork is indistinguishable from tampering.
  -- The lock id matches CHAIN_LOCK in @traceguard/audit-chain, which owns
  -- the hash formula; this function owns serialization and the head check.
  PERFORM pg_advisory_xact_lock(852100000001);

  SELECT hash INTO head FROM audit_events ORDER BY timestamp DESC, id DESC LIMIT 1;
  -- False, not an exception: a caller inside a transaction must be able to
  -- retry against the moved head, and a raised error would abort its
  -- transaction (the approval execution-intent path appends in one).
  IF coalesce(head, '') <> coalesce(p_prev_hash, '') THEN
    RETURN false;
  END IF;

  INSERT INTO audit_events
    (timestamp, actor_type, actor_id, action, resource_type, resource_id,
     result, metadata, prev_hash, hash)
  VALUES (p_timestamp, p_actor_type, p_actor_id, p_action, p_resource_type,
          p_resource_id, p_result, p_metadata, p_prev_hash, p_hash);
  RETURN true;
END $$;

-- Functions default to PUBLIC EXECUTE; membership of this one is explicit.
REVOKE EXECUTE ON FUNCTION append_audit_event(
  timestamptz, text, text, text, text, text, text, jsonb, text, text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION append_audit_event(
  timestamptz, text, text, text, text, text, text, jsonb, text, text
) TO api_runtime, gateway_runtime, policy_publisher;

-- api_runtime: the control API. Reads broadly, writes its own operational
-- tables and drafts, and is denied every trusted-configuration write and all
-- approval transitions.
GRANT SELECT ON
  workspaces, users, api_keys, memberships, agents, runs, spans,
  budgets, budget_reservations, budget_ledger, pricing, actuals,
  eval_suites, eval_cases, eval_runs, eval_results,
  webhook_subscriptions, webhook_deliveries, retention_rules, retention_runs,
  policies, mcp_servers, server_tools, policy_decisions, policy_versions,
  active_config, approvals, audit_events
TO api_runtime;

GRANT INSERT, UPDATE, DELETE ON
  users, api_keys, memberships, budgets, budget_reservations,
  eval_suites, eval_runs, webhook_subscriptions, retention_rules
TO api_runtime;
GRANT INSERT, UPDATE ON
  agents, runs, pricing, webhook_deliveries, retention_runs, policies
TO api_runtime;
GRANT INSERT ON
  workspaces, spans, budget_ledger, actuals, eval_cases, eval_results
TO api_runtime;
-- Retention of trace data stays with the API process; approval pruning is
-- retention_job's alone (§13.4), and the sweep connects with its credentials
-- when DATABASE_URL_RETENTION is set. The REVOKE makes the split real on a
-- database that granted it to the API before this file existed.
GRANT DELETE ON spans, runs, webhook_deliveries TO api_runtime;
REVOKE DELETE ON approvals FROM api_runtime;

-- gateway_runtime: the enforcement boundary. Reads signed policy and trust
-- state, writes decisions, approvals, pins and discovery, and appends audit
-- through the function only. It cannot publish or alter trusted
-- configuration, and it has no draft-write denial here because this
-- single-node deployment serves the policy screens from the gateway.
GRANT SELECT ON
  api_keys, users, memberships, workspaces,
  policies, mcp_servers, server_tools, policy_decisions, approvals,
  policy_versions, policy_signing_keys, active_config, audit_events,
  webhook_subscriptions
TO gateway_runtime;

GRANT INSERT, UPDATE ON approvals, server_tools, policies, mcp_servers, webhook_deliveries TO gateway_runtime;
GRANT INSERT ON policy_decisions, spans, workspaces TO gateway_runtime;

-- policy_publisher: the operator CLI. Appends versions and trust state,
-- moves the active pointer, and cannot rewrite what it already published.
GRANT SELECT ON
  workspaces, policies, mcp_servers, server_tools, policy_versions,
  policy_signing_keys, active_config, audit_events
TO policy_publisher;
GRANT INSERT ON policy_versions, policy_signing_keys, active_config, workspaces TO policy_publisher;
GRANT UPDATE ON policy_signing_keys, active_config TO policy_publisher;

-- retention_job: trace-data deletion, and nothing in the trusted or audit
-- tables (audit pruning additionally requires a signed checkpoint, which
-- does not exist yet, so the role holds no audit privilege at all).
GRANT SELECT ON
  workspaces, retention_rules, retention_runs, spans, runs, approvals,
  webhook_deliveries
TO retention_job;
GRANT INSERT, UPDATE ON retention_rules, retention_runs TO retention_job;
GRANT DELETE ON spans, runs, approvals, webhook_deliveries TO retention_job;

-- migration_owner is a membership target for the deployer: DDL should run
-- as this role (SET ROLE migration_owner) so no runtime role ever needs it.
-- Current installations run migrations as the database owner, which already
-- satisfies "runtime services must not use the migration owner".
