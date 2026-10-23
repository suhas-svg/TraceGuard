-- FR-016: the dashboard exchanges a bearer key for a short-lived, server-side
-- session. The browser gets an opaque session cookie (HttpOnly) and a separate
-- CSRF cookie; privileged keys never stay in localStorage. The session row is
-- the authority, so revocation is a row delete, not a client-side convention.
CREATE TABLE IF NOT EXISTS dashboard_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash text NOT NULL UNIQUE,
  csrf_hash text NOT NULL,
  principal jsonb NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);

CREATE INDEX IF NOT EXISTS dashboard_sessions_expires_at_idx
  ON dashboard_sessions (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON dashboard_sessions TO api_runtime;
-- The gateway process hosts the approval control listener and resolves the
-- approver session there. It only needs to read; last_used_at updates are
-- best-effort and happen on the API listener's connection.
GRANT SELECT ON dashboard_sessions TO gateway_runtime;
