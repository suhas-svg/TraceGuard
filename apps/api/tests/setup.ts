import { beforeAll } from "vitest";
import { Pool } from "pg";

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

// Every file shares one database and none of them clean up, so whichever file
// runs first decides what the next one sees (approvals saw 403s from a policy
// left behind elsewhere). Migrations seed no rows, so wiping everything before
// each file is safe.
beforeAll(async () => {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  try {
    const { rows } = await pool.query<{ tablename: string }>(
      "select tablename from pg_tables where schemaname = 'public'"
    );
    if (rows.length > 0) {
      const tables = rows.map((row) => `"${row.tablename}"`).join(", ");
      await pool.query(`TRUNCATE ${tables} RESTART IDENTITY CASCADE`);
    }
  } finally {
    await pool.end();
  }
});
