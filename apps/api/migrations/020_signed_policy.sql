-- 020: trusted policy becomes immutable signed editions.
--
-- A published policy is an insert into policy_versions plus a pointer move in
-- active_config; no runtime role ever updates a trusted edition. The gateway
-- will verify signature, key id, monotonic version and previous_version_hash
-- before using a bundle; this migration provides the durable shape only.

CREATE TABLE IF NOT EXISTS policy_signing_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  key_id TEXT NOT NULL,
  algorithm TEXT NOT NULL DEFAULT 'Ed25519' CHECK (algorithm = 'Ed25519'),
  public_key_pem TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  retired_at TIMESTAMPTZ,
  UNIQUE (workspace_id, key_id)
);

CREATE TABLE IF NOT EXISTS policy_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  version BIGINT NOT NULL CHECK (version > 0),
  bundle JSONB NOT NULL,
  content_hash TEXT NOT NULL,
  signature TEXT NOT NULL,
  signing_key_id UUID NOT NULL REFERENCES policy_signing_keys(id),
  previous_version_hash TEXT,
  published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  published_by TEXT NOT NULL,
  UNIQUE (workspace_id, version)
);

CREATE INDEX IF NOT EXISTS policy_versions_workspace_version_idx
  ON policy_versions (workspace_id, version DESC);

CREATE TABLE IF NOT EXISTS active_config (
  workspace_id UUID PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE,
  policy_version_id UUID NOT NULL REFERENCES policy_versions(id),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policy_drafts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL DEFAULT 'draft',
  content JSONB NOT NULL DEFAULT '{}',
  revision INTEGER NOT NULL DEFAULT 1,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS policy_drafts_workspace_updated_idx
  ON policy_drafts (workspace_id, updated_at DESC);

-- Immutable even for a role that can write the table: publishing means a new
-- version, never editing history.
CREATE OR REPLACE FUNCTION reject_policy_version_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'policy_versions is immutable; publish a new version';
END;
$$;

DROP TRIGGER IF EXISTS policy_versions_immutable ON policy_versions;
CREATE TRIGGER policy_versions_immutable
  BEFORE UPDATE OR DELETE ON policy_versions
  FOR EACH ROW EXECUTE FUNCTION reject_policy_version_mutation();
