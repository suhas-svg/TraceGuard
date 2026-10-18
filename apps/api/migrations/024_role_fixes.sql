-- 024_role_fixes.sql
-- Grants the e2e stack discovered by running every scenario as the roles
-- rather than as the owner: the gateway's budget gate reads `budgets`, and
-- its denied-span write needs SELECT on `spans` because the statement ends
-- with ON CONFLICT (id) DO NOTHING, which reads for the conflicting row.
-- Without the spans read the denial still happened but its span was silently
-- dropped (the gateway now logs that failure; gateway.ts recordDeniedSpan).
-- Grants are additive, so this converges databases that already applied 023.

GRANT SELECT ON budgets, spans TO gateway_runtime;
