import { createHash, createPrivateKey, createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import { canonicalize } from "@traceguard/canonical-json";

// The audit chain has exactly one implementation. The API, the gateway and
// the operator-side policy publisher all append through these functions, and
// the verifier recomputes from the same formula — a second copy of the hash
// is how a chain silently stops being a chain.
//
// Two hash formats exist side by side:
//   hash_version 1 — the historical pipe-joined formula. Kept byte-identical
//     so already-written events keep verifying.
//   hash_version 2 — SHA-256 over the RFC 8785 (JCS) canonical JSON of the
//     event fields plus previous_hash (§10.1). New appends use v2 and carry
//     workspace attribution, policy-version attribution and a per-workspace
//     sequence.
//
// The per-workspace sequence is allocated by the database append function
// inside the chain lock, *after* the appender has computed the hash, so it is
// deliberately not part of the v2 hash input; chain integrity rests on the
// previous_hash linkage and the sequence exists for ordering/audit.
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
  // v2 attribution. The database allocates the sequence itself; these are
  // what the writer knows at append time.
  workspace_id?: string | null;
  policy_version_id?: string | null;
  matched_rule_ids?: string[] | null;
}

export const HASH_VERSION_LEGACY = 1;
export const HASH_VERSION_CANONICAL = 2;

// Stable stringify: the same object always serializes the same way regardless
// of key order. Kept byte-identical to the historical implementation, because
// changing it would make every already-written event fail verification. It
// also formats the metadata *column* so stored jsonb is deterministic.
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
// a legitimate fork is indistinguishable from tampering. The database
// function append_audit_event (migration 023, extended by migration 028)
// takes this lock now — it must keep matching this number.
export const CHAIN_LOCK = 852100000001;

// Historical hash format (hash_version 1). Do not change: every event
// written before the canonical format moved to v2 was hashed with this.
export function auditHash(prevHash: string, timestamp: string, entry: AuditEntry): string {
  const meta = stableStringify(entry.metadata ?? {});
  return createHash("sha256")
    .update(
      [prevHash, timestamp, entry.actor_type, entry.actor_id ?? "", entry.action,
       entry.resource_type, entry.resource_id ?? "", entry.result, meta].join("|")
    )
    .digest("hex");
}

// The exact field set that the canonical (v2) hash covers. Exported so tests
// can lock the bytes; the database function stores the same columns.
export interface CanonicalEventFields {
  timestamp: string;
  workspace_id: string | null;
  actor_type: string;
  actor_id: string;
  action: string;
  resource_type: string;
  resource_id: string;
  result: string;
  policy_version_id: string | null;
  matched_rule_ids: string[] | null;
  metadata: Record<string, unknown>;
  previous_hash: string;
}

export function canonicalEventFields(
  prevHash: string, timestamp: string, entry: AuditEntry
): CanonicalEventFields {
  return {
    timestamp,
    workspace_id: entry.workspace_id ?? null,
    actor_type: entry.actor_type,
    actor_id: entry.actor_id ?? "",
    action: entry.action,
    resource_type: entry.resource_type,
    resource_id: entry.resource_id ?? "",
    result: entry.result,
    policy_version_id: entry.policy_version_id ?? null,
    matched_rule_ids: entry.matched_rule_ids ?? null,
    metadata: entry.metadata ?? {},
    previous_hash: prevHash
  };
}

// §10.1: SHA-256 over the RFC 8785 canonical JSON of the event fields plus
// previous_hash. One byte sequence, or two implementations disagree.
export function auditHashV2(prevHash: string, timestamp: string, entry: AuditEntry): string {
  return createHash("sha256")
    .update(canonicalize(canonicalEventFields(prevHash, timestamp, entry)))
    .digest("hex");
}

// Version dispatcher used by the verifier: rows carry their format.
export function auditHashFor(
  version: number | null | undefined, prevHash: string, timestamp: string, entry: AuditEntry
): string {
  return (version ?? HASH_VERSION_LEGACY) >= HASH_VERSION_CANONICAL
    ? auditHashV2(prevHash, timestamp, entry)
    : auditHash(prevHash, timestamp, entry);
}

// Appends one event inside the caller's transaction, through the
// append_audit_event database function (migration 023, extended by 028). The
// function serializes writers, allocates the per-workspace sequence and
// refuses an append that does not link to the current head; the hash formula
// stays here, where the verifier can share it. A head that moved between our
// read and the call is a retry, not a fork — and the function returns false
// instead of raising precisely so the retry does not abort the caller's
// transaction (the approval execution-intent path appends in one).
export async function appendAuditEvent(client: SqlClient, entry: AuditEntry): Promise<void> {
  for (let attempt = 0; attempt < 8; attempt++) {
    const prev = await client.query(
      "SELECT hash FROM audit_events ORDER BY timestamp DESC, id DESC LIMIT 1"
    );
    const prevHash = (prev.rows[0] as { hash?: string } | undefined)?.hash ?? "";
    const timestamp = new Date().toISOString();
    const hash = auditHashV2(prevHash, timestamp, entry);
    const result = await client.query(
      `SELECT append_audit_event($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11::uuid,$12,$13::uuid,$14::jsonb) AS appended`,
      [timestamp, entry.actor_type, entry.actor_id ?? "", entry.action,
       entry.resource_type, entry.resource_id ?? "", entry.result,
       stableStringify(entry.metadata ?? {}), prevHash, hash,
       entry.workspace_id ?? null, HASH_VERSION_CANONICAL,
       entry.policy_version_id ?? null,
       entry.matched_rule_ids ? JSON.stringify(entry.matched_rule_ids) : null]
    );
    if ((result.rows[0] as { appended?: boolean } | undefined)?.appended) return;
  }
  throw new Error("audit append could not link to the chain head after 8 attempts");
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
  // Present from migration 028. Absent in rows selected by older callers.
  workspace_id?: string | null;
  seq?: string | number | null;
  hash_version?: number | null;
  policy_version_id?: string | null;
  matched_rule_ids?: string[] | null;
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
// chain ordered by (timestamp, id) — the order the appender cites. Each row
// is verified with the formula its hash_version names, so a chain that spans
// the v1→v2 transition still verifies end to end. A segment that starts
// mid-chain cannot be verified without an external checkpoint anchor, and
// this function will flag its first row; that is deliberate.
export function verifyAuditChain(rows: AuditRow[]): ChainVerification {
  const problems: ChainProblem[] = [];
  let prevHash = "";
  for (const row of rows) {
    const timestamp = new Date(row.timestamp).toISOString();
    const recomputed = auditHashFor(row.hash_version ?? HASH_VERSION_LEGACY, row.prev_hash, timestamp, {
      actor_type: row.actor_type,
      actor_id: row.actor_id,
      action: row.action,
      resource_type: row.resource_type,
      resource_id: row.resource_id,
      result: row.result,
      metadata: row.metadata ?? {},
      workspace_id: row.workspace_id ?? null,
      policy_version_id: row.policy_version_id ?? null,
      matched_rule_ids: Array.isArray(row.matched_rule_ids) ? row.matched_rule_ids : null
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

// ---------------------------------------------------------------------------
// Signed checkpoints (FR-019).
//
// Append-only is tamper-evident, not tamper-proof: the party holding the
// database can rewrite the whole table and recompute the hashes. A checkpoint
// signed with a key that never lives in the database or in the containers
// anchors the history externally. The verifier treats a chain whose first
// link is broken but covered by a valid checkpoint as anchored — a pruned
// prefix — never as corruption.

/** What a signed checkpoint commits to. v1 committed to the global head only;
 * v2 additionally names the per-workspace segments covered by the cut, so an
 * offline verifier can check the retained tail against each workspace's last
 * covered sequence instead of trusting a single global hash (§10.2, FR-019). */
export interface CheckpointSegment {
  /** null for events the migration left un-attributed. */
  workspace_id: string | null;
  up_to_sequence: number | null;
  up_to_hash: string;
}

export interface CheckpointPayloadV1 {
  v: 1;
  created_at: string;
  up_to_timestamp: string;
  up_to_hash: string;
  event_count: number;
}

export interface CheckpointPayloadV2 {
  v: 2;
  created_at: string;
  up_to_timestamp: string;
  up_to_hash: string;
  event_count: number;
  segments: CheckpointSegment[];
}

export type CheckpointPayload = CheckpointPayloadV1 | CheckpointPayloadV2;

export interface CheckpointSignature {
  signature: string;
  key_id: string;
}

function checkpointBytes(payload: CheckpointPayload): Buffer {
  return Buffer.from(canonicalize(payload as unknown as Record<string, unknown>), "utf8");
}

function asCheckpointPrivateKey(pem: string): KeyObject {
  const key = createPrivateKey(pem);
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error("checkpoint keys must be ed25519");
  }
  return key;
}

/** Stable id for a checkpoint key: the digest of its SPKI PEM. */
export function checkpointKeyId(publicKeyPem: string): string {
  return createHash("sha256").update(publicKeyPem.trim()).digest("hex");
}

export function signCheckpoint(payload: CheckpointPayload, privateKeyPem: string): CheckpointSignature {
  const key = asCheckpointPrivateKey(privateKeyPem);
  const signature = sign(null, checkpointBytes(payload), key).toString("base64");
  const publicPem = createPublicKey(key).export({ type: "spki", format: "pem" }).toString();
  return { signature, key_id: checkpointKeyId(publicPem) };
}

export function verifyCheckpoint(
  payload: CheckpointPayload,
  signature: string,
  publicKeyPem: string
): boolean {
  try {
    const key = createPublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== "ed25519") return false;
    return verify(null, checkpointBytes(payload), key, Buffer.from(signature, "base64"));
  } catch {
    return false;
  }
}
