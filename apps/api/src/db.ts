import { Pool } from "pg";

const connectionString = process.env.DATABASE_URL;
if (!connectionString) throw new Error("DATABASE_URL is required");

export const pool = new Pool({ connectionString, max: 10 });

// §13.4: the retention sweep deletes terminal approvals, which api_runtime is
// deliberately not granted. A deployment sets DATABASE_URL_RETENTION to the
// retention_job credentials; without it (dev, tests) the sweep uses the main
// pool like every other route.
export const retentionPool = process.env.DATABASE_URL_RETENTION
  ? new Pool({ connectionString: process.env.DATABASE_URL_RETENTION, max: 2 })
  : null;

export async function isDbReady(): Promise<boolean> {
  try {
    await pool.query("SELECT 1");
    return true;
  } catch {
    return false;
  }
}
