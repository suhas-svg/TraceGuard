-- 022: the enforcement plane is signed policy, and history is immutable at
-- the database layer.
--
-- policy_decisions gains the exact signed policy version it evaluated.
-- audit_events gains a mutation guard, so append-only stops being a
-- convention the runtime could ignore; the signer trust store becomes
-- insert-or-retire. policy_drafts is dropped: the editable draft store is the
-- existing versioned `policies` table (drafts never enforce anything), and
-- two tables for one concept is how a reviewer ends up reading the wrong one.

ALTER TABLE policy_decisions
  ADD COLUMN IF NOT EXISTS policy_version_id UUID REFERENCES policy_versions(id);

DROP TABLE IF EXISTS policy_drafts;

CREATE OR REPLACE FUNCTION reject_audit_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only';
END;
$$;

DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events;
CREATE TRIGGER audit_events_append_only
  BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();

-- Key material is insert-or-retire: a runtime write cannot swap the pinned
-- public key for another one, only a publisher can add a key and only
-- retirement marks it unusable.
CREATE OR REPLACE FUNCTION guard_signing_key_material() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'policy signing keys are retired, never deleted';
  END IF;
  IF NEW.key_id <> OLD.key_id OR NEW.public_key_pem <> OLD.public_key_pem
     OR NEW.algorithm <> OLD.algorithm OR NEW.workspace_id <> OLD.workspace_id THEN
    RAISE EXCEPTION 'policy signing key material is immutable; trust a new key instead';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS policy_signing_keys_guard ON policy_signing_keys;
CREATE TRIGGER policy_signing_keys_guard
  BEFORE UPDATE OR DELETE ON policy_signing_keys
  FOR EACH ROW EXECUTE FUNCTION guard_signing_key_material();
