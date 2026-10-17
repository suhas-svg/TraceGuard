-- §7.5: every exposed tool name is namespaced by a stable per-workspace server
-- alias (`alias__tool`). Existing rows get a deterministic alias; collisions
-- from sanitising different names to the same alias get a numeric suffix.
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS gateway_alias TEXT;

WITH sanitized AS (
  SELECT id, workspace_id, created_at,
         COALESCE(NULLIF(
           lower(left(regexp_replace(regexp_replace(name, '[^a-zA-Z0-9]+', '_', 'g'),
                                    '^_+|_+$', '', 'g'), 32)),
           ''), 'server') AS base
    FROM mcp_servers
), ranked AS (
  SELECT id, base,
         row_number() OVER (PARTITION BY workspace_id, base ORDER BY created_at, id) AS rn
    FROM sanitized
)
UPDATE mcp_servers s
   SET gateway_alias = CASE WHEN r.rn = 1 THEN r.base ELSE r.base || '_' || r.rn END
  FROM ranked r
 WHERE s.id = r.id AND s.gateway_alias IS NULL;

ALTER TABLE mcp_servers ALTER COLUMN gateway_alias SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_servers_workspace_alias
  ON mcp_servers (workspace_id, gateway_alias);
