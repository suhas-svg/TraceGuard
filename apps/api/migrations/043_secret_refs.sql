-- §7.3/§7.4: upstream credentials are referenced, never stored.
--
-- This is a deliberately destructive, fail-closed upgrade. The old
-- auth_secret values are dropped rather than migrated into secret_ref: a
-- database dump must not retain an upstream credential, and a reference
-- cannot be inferred from a value. Existing servers stay registered but fail
-- closed until an operator re-registers them with secret_ref and rotates the
-- credential. See docs/operations.md for the rotation procedure.
BEGIN;

ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS secret_ref TEXT;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'mcp_servers'::regclass
      AND conname = 'mcp_servers_secret_ref_format'
  ) THEN
    ALTER TABLE mcp_servers
      ADD CONSTRAINT mcp_servers_secret_ref_format
      CHECK (
        secret_ref IS NULL OR (
          length(secret_ref) <= 512
          AND secret_ref ~ '^(env:[A-Za-z_][A-Za-z0-9_]*|file:.+)$'
        )
      );
  END IF;
END $$;

COMMENT ON COLUMN mcp_servers.secret_ref IS
  'Reference resolved by the gateway (env:NAME or file:/path). Never the credential value.';

ALTER TABLE mcp_servers DROP COLUMN IF EXISTS auth_secret;

COMMIT;
