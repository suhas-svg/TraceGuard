-- 025_audit_function_owner.sql
-- §10.1: the append function must be owned by the non-login audit_owner role,
-- not by whichever role happened to run the migration. 023 owns audit_events
-- itself, but the CREATE OR REPLACE FUNCTION at the end of 023 was never
-- followed by an OWNER move, so the SECURITY DEFINER context ran as the
-- migration role (a superuser in dev, which silently masked the gap).
-- Guard the ALTER so this file still applies to a database that ran the
-- earlier migrations in a different order.

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE p.proname = 'append_audit_event' AND n.nspname = 'public'
  ) THEN
    ALTER FUNCTION append_audit_event(
      timestamptz, text, text, text, text, text, text, jsonb, text, text
    ) OWNER TO audit_owner;
  END IF;
END $$;
