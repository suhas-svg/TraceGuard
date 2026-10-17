import type { Pool } from "pg";
import { sha256Hex, stableStringify } from "./policy.js";

// Append-only audit with a hash chain: each row commits to the previous hash,
// so silent edits break every later link. Tamper-evident, not tamper-proof.
// shortcut: the app connects as the table owner, so no-update is convention
// plus code review, not a revoked PG role. Create a least-privilege app role
// with REVOKE UPDATE, DELETE before multi-user use.
// Advisory-lock key for the audit chain. One appender at a time: without it,
// two concurrent writers read the same tail hash and append sibling rows, and
// a legitimate fork is indistinguishable from tampering.
const CHAIN_LOCK = 852100000001;

export async function audit(
  pool: Pool,
  entry: {
    actor_type: string;
    actor_id?: string;
    action: string;
    resource_type: string;
    resource_id?: string;
    result: string;
    metadata?: Record<string, unknown>;
  }
): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock($1)", [CHAIN_LOCK]);
    const prev = await client.query(
      "SELECT hash FROM audit_events ORDER BY timestamp DESC, id DESC LIMIT 1"
    );
    const prevHash: string = prev.rows[0]?.hash ?? "";
    const meta = stableStringify(entry.metadata ?? {});
    const timestamp = new Date().toISOString();
    const hash = sha256Hex(
      [prevHash, timestamp, entry.actor_type, entry.actor_id ?? "", entry.action,
       entry.resource_type, entry.resource_id ?? "", entry.result, meta].join("|")
    );
    await client.query(
      `INSERT INTO audit_events
         (timestamp, actor_type, actor_id, action, resource_type, resource_id,
          result, metadata, prev_hash, hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10)`,
      [timestamp, entry.actor_type, entry.actor_id ?? "", entry.action,
       entry.resource_type, entry.resource_id ?? "", entry.result, meta,
       prevHash, hash]
    );
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}
