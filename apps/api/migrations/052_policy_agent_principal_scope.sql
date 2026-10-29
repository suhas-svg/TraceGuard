-- 052: policy agent scope names an authenticated AgentPrincipal, not a
-- telemetry agent. The gateway now derives the agent identity from the
-- bearer token, so the draft row must reference the same provisioned principal
-- in the same project.
--
-- Existing rows that point at a telemetry agent (or at a principal in another
-- project) cannot be made safe by keeping them enabled: clearing the scope
-- would broaden a deny/approval rule into a workspace-wide rule. Disable and
-- clear them instead, so an upgrade fails closed until an operator recreates
-- the rule against a real principal.
--
-- Idempotent: the db-roles bootstrap re-applies every migration on boot.

BEGIN;

-- The composite foreign key needs a unique target. The id is already the
-- primary key, so this only adds the project component PostgreSQL requires.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'agent_principals'::regclass
       AND conname = 'agent_principals_id_project_key'
  ) THEN
    ALTER TABLE agent_principals
      ADD CONSTRAINT agent_principals_id_project_key UNIQUE (id, project_id);
  END IF;
END $$;

UPDATE policies p
   SET enabled = false,
       agent_id = NULL
 WHERE p.agent_id IS NOT NULL
   AND NOT EXISTS (
     SELECT 1 FROM agent_principals ap
      WHERE ap.id = p.agent_id
        AND ap.project_id = p.project_id
   );

ALTER TABLE policies DROP CONSTRAINT IF EXISTS policies_agent_id_fkey;
ALTER TABLE policies DROP CONSTRAINT IF EXISTS policies_agent_principal_fkey;

ALTER TABLE policies
  ADD CONSTRAINT policies_agent_principal_fkey
  FOREIGN KEY (agent_id, project_id)
  REFERENCES agent_principals(id, project_id)
  ON DELETE CASCADE;

COMMIT;
