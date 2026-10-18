import type { Pool, PoolClient } from "pg";
import { appendAuditEvent, type AuditEntry } from "@traceguard/audit-chain";

// The append-only hash chain itself lives in @traceguard/audit-chain, shared
// with the operator-side policy publisher so the hash formula cannot drift
// between writers. This wrapper keeps the app-facing call shape:
//
// Given a Pool it opens its own transaction; given an open PoolClient it
// joins the caller's transaction — that is what makes an approval transition
// and its execution-intent event atomic. Pass a PoolClient only inside
// BEGIN/COMMIT: the chain's advisory lock is transaction-scoped and autocommit
// would release it before the insert.
//
// Immutability is enforced at the database layer (migration 022 rejects
// UPDATE/DELETE on audit_events), so no-update is not merely convention.

export type { AuditEntry } from "@traceguard/audit-chain";

export async function audit(db: Pool | PoolClient, entry: AuditEntry): Promise<void> {
  if (typeof (db as PoolClient).release === "function") {
    await appendAuditEvent(db as PoolClient, entry);
    return;
  }
  const client = await (db as Pool).connect();
  try {
    await client.query("BEGIN");
    await appendAuditEvent(client, entry);
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}
