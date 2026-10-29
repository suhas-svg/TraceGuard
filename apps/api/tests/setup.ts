import { afterAll, beforeAll } from "vitest";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Pool } from "pg";
import type { FastifyInstance } from "fastify";

// Test-only defaults. CI passes real values through the environment;
// local runs fall back to the dev database and throwaway keys.
process.env.API_KEY ??= "test_key";
process.env.APPROVER_KEY ??= "test_approver";
// Fixed test-only seal key. Production keys come from the environment and
// are never committed.
process.env.APPROVAL_ARGS_KEY ??= "ab".repeat(32);
process.env.ALLOW_PRIVATE_UPSTREAMS ??= "true";
// §7.5 pins only allowlisted `_meta` keys; the suite pins one key so the
// allowlist path is exercised rather than skipped.
process.env.TOOL_PIN_META_ALLOWLIST ??= "io.example/flag";
// §13.3 pins the highest accepted policy version in a gateway-writable file
// so a rolled-back pointer cannot pass verification. Each test file runs in
// its own process with its own directory, wiped before the file's tests so
// the truncated database and the anchor start from the same place.
process.env.GATEWAY_STATE_DIR ??= join(tmpdir(), `traceguard-gateway-state-${process.pid}`);
// ADR-0010: the API resolves no upstream credentials; discovery is delegated to
// the gateway's internal listener. Each test file starts its own listener on an
// ephemeral port and points the API at it.
process.env.GATEWAY_INTERNAL_TOKEN ??= "test_internal_token";
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
let internalGateway: FastifyInstance | undefined;

beforeAll(async () => {
  // Wipe the gateway policy anchor too: the database is about to be empty,
  // and a surviving anchor from an earlier run would read every first
  // publish as a rollback.
  const stateDir = process.env.GATEWAY_STATE_DIR ?? "";
  if (stateDir) {
    rmSync(stateDir, { recursive: true, force: true });
    mkdirSync(stateDir, { recursive: true });
  }
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

  // Discovery resolves the upstream credential inside the gateway (ADR-0010),
  // so the suite runs one internal listener per test file and points the API at
  // it. The import is dynamic: gateway.ts reads API_KEY and APPROVER_KEY at
  // module load, and ESM hoisting would evaluate it before the defaults above.
  const { buildGatewayInternal } = await import("../src/gateway.js");
  internalGateway = buildGatewayInternal();
  await internalGateway.listen({ port: 0, host: "127.0.0.1" });
  const address = internalGateway.server.address();
  if (!address || typeof address === "string") {
    throw new Error("internal gateway did not bind a TCP port");
  }
  process.env.GATEWAY_INTERNAL_URL = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  await internalGateway?.close();
  internalGateway = undefined;
});
