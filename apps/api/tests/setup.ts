// Test-only defaults. CI passes real values through the environment;
// local runs fall back to the dev database and throwaway keys.
process.env.API_KEY ??= "test_key";
process.env.APPROVER_KEY ??= "test_approver";
// Fixed test-only seal key. Production keys come from the environment and
// are never committed.
process.env.APPROVAL_ARGS_KEY ??= "ab".repeat(32);
process.env.ALLOW_PRIVATE_UPSTREAMS ??= "true";
process.env.DATABASE_URL ??=
  process.env.TEST_DATABASE_URL ??
  "postgres://traceguard:traceguard_dev_only@localhost:5432/traceguard";

// Approval queue protections default to the spec's limits. The unit suite
// creates many approvals for the same caller inside one minute, so raise the
// creation-rate knob here; the dedicated protection tests lower it again to
// prove enforcement.
process.env.APPROVAL_RATE_PER_MINUTE ??= "100";
