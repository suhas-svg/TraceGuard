import { createHash } from "node:crypto";

// The audit chain has exactly one implementation. The API, the gateway and
// the operator-side policy publisher all append through these functions, and
// the verifier recomputes from the same formula — a second copy of the hash
// is how a chain silently stops being a chain.
//
// Append-only is tamper-evident, not tamper-proof: a database owner can
// rewrite the table. Only an externally stored checkpoint anchors history
// against that.

// Structural so that a pg Pool or PoolClient satisfies it without this
// package depending on pg.
export interface SqlClient {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>;
}

export interface AuditEntry {
  actor_type: string;
  actor_id?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  result: string;
  metadata?: Record<string, unknown>;
}

// Stable stringify: the same object always serializes the same way regardless
// of key order. Kept byte-identical to the historical implementation, because
// changing it would make every already-written event fail verification.
export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`);
  return `{${entries.join(",")}}`;
}

// Advisory-lock key for the audit chain. One appender at a time: without it,
// two concurrent writers read the same tail hash and append sibling rows, and
// a legitimate fork is indistinguishable from tampering.
export const CHAIN_LOCK = 852100000001;

export function auditHash(prevHash: string, timestamp: string, entry: AuditEntry): string {
  const meta = stableStringify(entry.metadata ?? {});
  return createHash("sha256")
    .update(
      [prevHash, timestamp, entry.actor_type, entry.actor_id ?? "", entry.action,
       entry.resource_type, entry.resource_id ?? "", entry.result, meta].join("|")
    )
    .digest("hex");
}

// Appends one event inside the caller's transaction. The advisory lock is
// transaction-scoped, so the caller must be inside BEGIN/COMMIT (that is also
// what lets an approval transition and its execution-intent event commit
// atomically with their audit link).
export async function appendAuditEvent(client: SqlClient, entry: AuditEntry): Promise<void> {
  await client.query("SELECT pg_advisory_xact_lock($1)", [CHAIN_LOCK]);
  const prev = await client.query(
    "SELECT hash FROM audit_events ORDER BY timestamp DESC, id DESC LIMIT 1"
  );
  const prevHash = (prev.rows[0] as { hash?: string } | undefined)?.hash ?? "";
  const timestamp = new Date().toISOString();
  const hash = auditHash(prevHash, timestamp, entry);
  await client.query(
    `INSERT INTO audit_events
       (timestamp, actor_type, actor_id, action, resource_type, resource_id,
        result, metadata, prev_hash, hash)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10)`,
    [timestamp, entry.actor_type, entry.actor_id ?? "", entry.action,
     entry.resource_type, entry.resource_id ?? "", entry.result,
     stableStringify(entry.metadata ?? {}), prevHash, hash]
  );
}

export interface AuditRow {
  id: string;
  timestamp: string | Date;
  actor_type: string;
  actor_id: string;
  action: string;
  resource_type: string;
  resource_id: string;
  result: string;
  metadata: Record<string, unknown> | null;
  prev_hash: string;
  hash: string;
}

export interface ChainProblem {
  id: string;
  problem: string;
}

export interface ChainVerification {
  ok: boolean;
  checked: number;
  problems: ChainProblem[];
}

// Recomputes every event hash and checks every link. Rows must be the full
// chain ordered by (timestamp, id) — the order the appender cites. A segment
// that starts mid-chain cannot be verified without an external checkpoint
// anchor, and this function will flag its first row; that is deliberate.
export function verifyAuditChain(rows: AuditRow[]): ChainVerification {
  const problems: ChainProblem[] = [];
  let prevHash = "";
  for (const row of rows) {
    const timestamp = new Date(row.timestamp).toISOString();
    const recomputed = auditHash(row.prev_hash, timestamp, {
      actor_type: row.actor_type,
      actor_id: row.actor_id,
      action: row.action,
      resource_type: row.resource_type,
      resource_id: row.resource_id,
      result: row.result,
      metadata: row.metadata ?? {}
    });
    if (row.prev_hash !== prevHash) {
      problems.push({ id: row.id, problem: "chain link broken (prev_hash does not match the previous event)" });
    }
    if (recomputed !== row.hash) {
      problems.push({ id: row.id, problem: "event hash mismatch (event content was modified)" });
    }
    prevHash = row.hash;
  }
  return { ok: problems.length === 0, checked: rows.length, problems };
}
