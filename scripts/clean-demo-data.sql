-- Removes the test fixtures the demo and bench scripts leave behind, so a live
-- walkthrough of the dashboard is not buried under them. Every target is
-- identified by the name prefix those scripts generate, never by age or by
-- "looks unused":
--
--   demo-, bench-, chain-, sweep-, warn-   scripts/demo-fixes.mjs, scripts/bench.mjs
--   peek-                                  the approval-withholding check
--
-- It deliberately touches nothing else: runs, spans, audit_events, decisions,
-- and ledger rows are history, and wanting a tidy demo is not a reason to delete
-- history.
--
-- Budgets are NOT included, and that is a real gap rather than an oversight:
-- budgets carry no name and the demo mints a random UUID for ref_id, so there is
-- no way to tell a demo budget from a real one except by guessing, and guessing
-- is how a cleanup script deletes something that mattered. Clear them by hand if
-- they bother you.
--
--   docker exec -i traceguard-postgres-1 psql -U traceguard -d traceguard \
--     -v ON_ERROR_STOP=1 < scripts/clean-demo-data.sql

BEGIN;

-- Counts first, so the output says what was removed rather than only that it worked.
CREATE TEMP TABLE removed AS
SELECT 'policies' AS what, count(*)::int AS n FROM policies
  WHERE name ~ '^(demo|bench|chain|sweep|warn)-'
UNION ALL SELECT 'servers', count(*)::int FROM mcp_servers
  WHERE name ~ '^(demo|bench|chain|sweep|warn)-'
UNION ALL SELECT 'eval_suites', count(*)::int FROM eval_suites
  WHERE name ~ '^(demo|bench|chain|sweep|warn)-'
UNION ALL SELECT 'users', count(*)::int FROM users
  WHERE email ~ '^(demo|peek)-'
UNION ALL SELECT 'webhook_subscriptions', count(*)::int FROM webhook_subscriptions
  WHERE name ~ '^(demo|bench)-'
UNION ALL SELECT 'pricing', count(*)::int FROM pricing
  WHERE provider ~ '^(demo|bench|chain)-';

-- policy_decisions and eval_results reference these, so they go first. They are
-- test rows too, and leaving them would break the foreign keys below.
DELETE FROM policy_decisions WHERE policy_id IN
  (SELECT id FROM policies WHERE name ~ '^(demo|bench|chain|sweep|warn)-');
DELETE FROM policies WHERE name ~ '^(demo|bench|chain|sweep|warn)-';

DELETE FROM eval_results WHERE eval_run_id IN
  (SELECT id FROM eval_runs WHERE suite_id IN
    (SELECT id FROM eval_suites WHERE name ~ '^(demo|bench|chain|sweep|warn)-'));
DELETE FROM eval_runs WHERE suite_id IN
  (SELECT id FROM eval_suites WHERE name ~ '^(demo|bench|chain|sweep|warn)-');
DELETE FROM eval_cases WHERE suite_id IN
  (SELECT id FROM eval_suites WHERE name ~ '^(demo|bench|chain|sweep|warn)-');
DELETE FROM eval_suites WHERE name ~ '^(demo|bench|chain|sweep|warn)-';

DELETE FROM server_tools WHERE server_id IN
  (SELECT id FROM mcp_servers WHERE name ~ '^(demo|bench|chain|sweep|warn)-');
DELETE FROM mcp_servers WHERE name ~ '^(demo|bench|chain|sweep|warn)-';

DELETE FROM webhook_deliveries WHERE subscription_id IN
  (SELECT id FROM webhook_subscriptions WHERE name ~ '^(demo|bench)-');
DELETE FROM webhook_subscriptions WHERE name ~ '^(demo|bench)-';

DELETE FROM pricing WHERE provider ~ '^(demo|bench|chain)-';

-- Keys and memberships cascade from users.
DELETE FROM users WHERE email ~ '^(demo|peek)-';

SELECT what, n FROM removed ORDER BY what;

COMMIT;
