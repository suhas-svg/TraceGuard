-- 049: retention_job needs SELECT on webhook_subscriptions for the
-- webhook_deliveries sweep. applyRule deletes deliveries scoped to the
-- workspace through a USING join on webhook_subscriptions, and without
-- this grant every run touching that target fails with 42501.
GRANT SELECT ON webhook_subscriptions TO retention_job;
