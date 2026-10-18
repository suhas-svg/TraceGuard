// Prepares the e2e database: drop, create, migrate. Playwright starts its
// webServers before globalSetup runs, so the api's readiness probe (/readyz)
// would otherwise wait forever on a database that does not exist yet. The
// api webServer command chains this script, which makes the ordering
// explicit. Safe to re-run: the database is recreated from scratch.
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

const { Client } = pg;
const DB_URL =
  process.env.E2E_DATABASE_URL ??
  "postgres://traceguard:traceguard_dev_only@localhost:5432/traceguard_e2e";

const url = new URL(DB_URL);
const dbName = decodeURIComponent(url.pathname.replace(/^\//, ""));
if (!dbName || dbName === "postgres") {
  throw new Error(`refusing to reset database "${dbName}"`);
}
const ident = `"${dbName.replaceAll('"', '""')}"`;

const adminUrl = new URL(DB_URL);
adminUrl.pathname = "/postgres";
const admin = new Client({ connectionString: adminUrl.toString() });
await admin.connect();
await admin.query(`DROP DATABASE IF EXISTS ${ident} WITH (FORCE)`);
await admin.query(`CREATE DATABASE ${ident}`);
await admin.end();

const db = new Client({ connectionString: DB_URL });
await db.connect();
const here = dirname(fileURLToPath(import.meta.url));
const migrations = join(here, "..", "..", "apps", "api", "migrations");
for (const f of readdirSync(migrations).filter((f) => f.endsWith(".sql")).sort()) {
  await db.query(readFileSync(join(migrations, f), "utf8"));
}
// The api, gateway, publisher and sweep connect as their least-privilege
// roles (§13.4), so the e2e run exercises the grants rather than the owner.
// Test-only passwords; a deployment sets its own before enabling LOGIN.
const ROLE_PASSWORDS = {
  api_runtime: "e2e_api_pw",
  gateway_runtime: "e2e_gateway_pw",
  policy_publisher: "e2e_publisher_pw",
  retention_job: "e2e_retention_pw"
};
for (const [role, password] of Object.entries(ROLE_PASSWORDS)) {
  await db.query(`ALTER ROLE ${role} LOGIN PASSWORD '${password}'`);
}
await db.end();
console.log(`e2e database ${dbName} reset, migrated, and role logins enabled`);
