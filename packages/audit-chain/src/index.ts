import { createHash, createPrivateKey, createPublicKey, randomUUID, sign, verify, type KeyObject } from "node:crypto";
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

/** A checked-out client. `release` distinguishes it from a Pool at runtime. */
export interface SqlPoolClient extends SqlClient {
  release(): void;
}

/** The subset of pg.Pool used here. Kept local so this package has no pg type dependency. */
export interface SqlPool extends SqlClient {
  connect(): Promise<SqlPoolClient>;
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
  project_id?: string | null;
  policy_version_id?: string | null;
  matched_rule_ids?: string[] | null;
}

export const HASH_VERSION_LEGACY = 1;
export const HASH_VERSION_CANONICAL = 2;
// v3 is the first format that hashes the event id and per-workspace sequence.
export const HASH_VERSION_EVENT = 3;
// v4 adds project attribution to the hashed event fields.
export const HASH_VERSION_PROJECT = 4;

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

export interface CanonicalEventFieldsV3 extends CanonicalEventFields {
  id: string;
  sequence: number;
}

export function canonicalEventFieldsV3(
  prevHash: string, timestamp: string, entry: AuditEntry, id: string, sequence: number
): CanonicalEventFieldsV3 {
  return {
    id,
    sequence,
    ...canonicalEventFields(prevHash, timestamp, entry)
  };
}

// §10.1: the v3 event hash covers the event ID and per-workspace sequence too.
export function auditHashV3(
  prevHash: string, timestamp: string, entry: AuditEntry, id: string, sequence: number
): string {
  return createHash("sha256")
    .update(canonicalize(canonicalEventFieldsV3(prevHash, timestamp, entry, id, sequence)))
    .digest("hex");
}

export interface CanonicalEventFieldsV4 extends CanonicalEventFieldsV3 {
  project_id: string | null;
}

export function canonicalEventFieldsV4(
  prevHash: string, timestamp: string, entry: AuditEntry, id: string, sequence: number
): CanonicalEventFieldsV4 {
  return {
    ...canonicalEventFieldsV3(prevHash, timestamp, entry, id, sequence),
    project_id: entry.project_id ?? null
  };
}

// v4 keeps the v3 id/sequence binding and adds the project the event happened
// in. Existing v1-v3 rows keep their original formulas.
export function auditHashV4(
  prevHash: string, timestamp: string, entry: AuditEntry, id: string, sequence: number
): string {
  return createHash("sha256")
    .update(canonicalize(canonicalEventFieldsV4(prevHash, timestamp, entry, id, sequence)))
    .digest("hex");
}

// Version dispatcher used by the verifier: rows carry their format.
export function auditHashFor(
  version: number | null | undefined, prevHash: string, timestamp: string, entry: AuditEntry,
  id?: string, sequence?: number | null
): string {
  const v = version ?? HASH_VERSION_LEGACY;
  if (v >= HASH_VERSION_PROJECT) {
    if (!id || sequence === null || sequence === undefined) {
      throw new Error("v4 audit event is missing its id or sequence");
    }
    return auditHashV4(prevHash, timestamp, entry, id, sequence);
  }
  if (v >= HASH_VERSION_EVENT) {
    if (!id || sequence === null || sequence === undefined) {
      throw new Error("v3 audit event is missing its id or sequence");
    }
    return auditHashV3(prevHash, timestamp, entry, id, sequence);
  }
  return v >= HASH_VERSION_CANONICAL
    ? auditHashV2(prevHash, timestamp, entry)
    : auditHash(prevHash, timestamp, entry);
}

// Appends one event through migration 033's two-step path. prepare allocates
// the per-workspace sequence and reads the chain head under a transaction-
// scoped advisory lock; the event is then hashed with its own ID and sequence
// and inserted before the transaction commits. A Pool gets its own
// transaction here; a PoolClient is expected to already be inside BEGIN.
async function appendOnce(client: SqlClient, entry: AuditEntry): Promise<void> {
  const prepared = await client.query(
    "SELECT prev_hash, seq FROM prepare_audit_append($1::uuid)",
    [entry.workspace_id ?? null]
  );
  const head = prepared.rows[0] as { prev_hash?: string; seq?: string | number } | undefined;
  if (!head) throw new Error("audit append did not receive a chain head");
  const prevHash = head.prev_hash ?? "";
  const sequence = Number(head.seq);
  if (!Number.isSafeInteger(sequence) || sequence < 1) {
    throw new Error("audit append received an invalid sequence");
  }
  const id = randomUUID();
  const timestamp = new Date().toISOString();
  const hash = auditHashV4(prevHash, timestamp, entry, id, sequence);
  const result = await client.query(
    `SELECT append_audit_event(
       $1::uuid,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,
       $12::uuid,$13::bigint,$14::smallint,$15::uuid,$16::jsonb,$17::uuid
     ) AS appended`,
    [id, timestamp, entry.actor_type, entry.actor_id ?? "", entry.action,
     entry.resource_type, entry.resource_id ?? "", entry.result,
     stableStringify(entry.metadata ?? {}), prevHash, hash,
     entry.workspace_id ?? null, sequence, HASH_VERSION_PROJECT,
     entry.policy_version_id ?? null,
     entry.matched_rule_ids ? JSON.stringify(entry.matched_rule_ids) : null,
     entry.project_id ?? null]
  );
  if ((result.rows[0] as { appended?: boolean } | undefined)?.appended !== true) {
    throw new Error("audit append could not link to the chain head");
  }
}

export async function appendAuditEvent(client: SqlClient, entry: AuditEntry): Promise<void> {
  // A pg.PoolClient has release(); a pg.Pool does not. Checking release first
  // matters because pg.Client also exposes connect(), so connect() alone
  // cannot tell a pool from an already-checked-out client.
  if (typeof (client as Partial<SqlPoolClient>).release === "function") {
    await appendOnce(client, entry);
    return;
  }
  const pool = client as Partial<SqlPool>;
  if (typeof pool.connect !== "function") {
    await appendOnce(client, entry);
    return;
  }
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    await appendOnce(c, entry);
    await c.query("COMMIT");
  } catch (err) {
    await c.query("ROLLBACK").catch(() => undefined);
    throw err;
  } finally {
    c.release();
  }
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
  // Present from migration 039; required to verify v4 hashes.
  project_id?: string | null;
  seq?: string | number | null;
  hash_version?: number | null;
  policy_version_id?: string | null;
  matched_rule_ids?: string[] | null;
}

export interface ChainProblem {
  id: string;
  problem: string;
}

export interface ChainGap {
  workspace_id: string | null;
  /** Missing sequences are `from` through `to`, inclusive. */
  from: number;
  to: number;
}

export interface ChainVerification {
  ok: boolean;
  checked: number;
  problems: ChainProblem[];
  gaps: ChainGap[];
}

export interface VerifyOptions {
  /**
   * Hash of the event immediately preceding the first row. A pruned retained
   * segment starts here; an unpruned chain starts at "". The verifier never
   * guesses: the caller must supply the signed checkpoint's cut hash.
   */
  anchorHash?: string;
  /**
   * Last sequence covered by the checkpoint for each workspace. The first
   * retained row must be exactly one greater, or the missing range is shown.
   */
  expectedSequences?: Array<{ workspace_id: string | null; up_to_sequence: number | null }>;
}

function workspaceKey(workspaceId: string | null | undefined): string {
  return workspaceId ?? "";
}

export interface ChainOrderRow {
  id: string;
  prev_hash: string;
  hash: string;
}

// Reads sort audit rows by (timestamp, id) because that is the only order the
// table exposes. Timestamps have millisecond precision, so two appends can
// share one; the random event id then says nothing about append order and the
// pair can come back reversed. The hash links do encode the true order, so
// callers that read a segment should put it back in chain order before
// verifying. Rows that do not form one linked segment (no unique root, or a
// fork) are returned unchanged: the verifier must report the damage rather
// than have this helper guess a plausible order.
export function orderAuditChain<T extends ChainOrderRow>(rows: readonly T[], anchorHash = ""): T[] {
  if (rows.length < 2) return [...rows];
  const byPrev = new Map<string, T[]>();
  for (const row of rows) {
    const bucket = byPrev.get(row.prev_hash);
    if (bucket) bucket.push(row);
    else byPrev.set(row.prev_hash, [row]);
  }
  let start: T | undefined;
  if (anchorHash) {
    const anchored = byPrev.get(anchorHash) ?? [];
    if (anchored.length !== 1) return [...rows];
    start = anchored[0];
  } else {
    const hashes = new Set(rows.map((row) => row.hash));
    const roots = rows.filter((row) => !hashes.has(row.prev_hash));
    if (roots.length !== 1) return [...rows];
    start = roots[0];
  }
  const ordered: T[] = [];
  const used = new Set<T>();
  let current: T | undefined = start;
  while (current && !used.has(current)) {
    ordered.push(current);
    used.add(current);
    const bucket = byPrev.get(current.hash);
    current = bucket?.find((row) => !used.has(row));
  }
  // Unreachable rows keep their caller order at the end so they are still
  // verified and reported instead of being dropped.
  for (const row of rows) {
    if (!used.has(row)) ordered.push(row);
  }
  return ordered;
}

// Recomputes every event hash and checks every link. Rows must be in chain
// order; when they were read by (timestamp, id), pass them through
// `orderAuditChain` first. Each row is verified with the formula its
// hash_version names, so a chain that spans v1 → v2 → v3 still verifies end to
// end. v3 hashes cover the event ID and per-workspace sequence; sequence
// continuity and gaps are reported separately so a missing range can never
// hide behind an otherwise intact hash chain.
export function verifyAuditChain(rows: AuditRow[], opts: VerifyOptions = {}): ChainVerification {
  const problems: ChainProblem[] = [];
  const gaps: ChainGap[] = [];
  const seenIds = new Set<string>();
  const byWorkspace = new Map<string, Array<{ seq: number; id: string }>>();
  let prevHash = opts.anchorHash ?? "";
  for (const row of rows) {
    const timestamp = new Date(row.timestamp).toISOString();
    const sequence = row.seq === null || row.seq === undefined ? null : Number(row.seq);
    let recomputed = "";
    try {
      recomputed = auditHashFor(
        row.hash_version ?? HASH_VERSION_LEGACY, row.prev_hash, timestamp, {
          actor_type: row.actor_type,
          actor_id: row.actor_id,
          action: row.action,
          resource_type: row.resource_type,
          resource_id: row.resource_id,
          result: row.result,
          metadata: row.metadata ?? {},
          workspace_id: row.workspace_id ?? null,
          project_id: row.project_id ?? null,
          policy_version_id: row.policy_version_id ?? null,
          matched_rule_ids: Array.isArray(row.matched_rule_ids) ? row.matched_rule_ids : null
        },
        row.id, sequence
      );
    } catch (err) {
      problems.push({ id: row.id, problem: (err as Error).message });
    }
    if (seenIds.has(row.id)) {
      problems.push({ id: row.id, problem: "duplicate event id" });
    }
    seenIds.add(row.id);
    if (row.prev_hash !== prevHash) {
      problems.push({ id: row.id, problem: "chain link broken (prev_hash does not match the previous event)" });
    }
    if (recomputed && recomputed !== row.hash) {
      problems.push({ id: row.id, problem: "event hash mismatch (event content was modified)" });
    }
    if (sequence !== null) {
      const key = workspaceKey(row.workspace_id);
      const list = byWorkspace.get(key) ?? [];
      list.push({ seq: sequence, id: row.id });
      byWorkspace.set(key, list);
    }
    prevHash = row.hash;
  }

  // §10.2: verification checks sequence continuity within retained segments.
  // A checkpoint tells us where the retained segment must begin; without one,
  // a workspace sequence may start at 1 or be explicitly anchored.
  const expected = new Map<string, number | null>();
  for (const item of opts.expectedSequences ?? []) {
    expected.set(workspaceKey(item.workspace_id), item.up_to_sequence);
  }
  for (const [key, list] of byWorkspace) {
    list.sort((a, b) => a.seq - b.seq);
    const first = list[0];
    const anchor = expected.get(key);
    if (anchor !== undefined && anchor !== null && first.seq !== anchor + 1) {
      if (first.seq > anchor + 1) {
        gaps.push({ workspace_id: key || null, from: anchor + 1, to: first.seq - 1 });
      }
      problems.push({
        id: first.id,
        problem: `sequence gap in workspace ${key || "(unattributed)"}: checkpoint ends at ${anchor}, first retained sequence is ${first.seq}`
      });
    } else if (!expected.has(key) && first.seq > 1) {
      problems.push({
        id: first.id,
        problem: `sequence starts at ${first.seq} without a signed checkpoint anchor`
      });
    }
    for (let i = 1; i < list.length; i += 1) {
      const previous = list[i - 1];
      const current = list[i];
      if (current.seq === previous.seq) {
        problems.push({ id: current.id, problem: `duplicate sequence ${current.seq} in workspace ${key || "(unattributed)"}` });
      } else if (current.seq !== previous.seq + 1) {
        const from = previous.seq + 1;
        const to = current.seq - 1;
        gaps.push({ workspace_id: key || null, from, to });
        problems.push({
          id: current.id,
          problem: `sequence gap in workspace ${key || "(unattributed)"}: ${from}-${to} missing`
        });
      }
    }
  }
  return { ok: problems.length === 0, checked: rows.length, problems, gaps };
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

/** v3 binds the exact last event in the pruned segment, not merely its hash
 * and time. The event id is also inside the v3 event hash. */
export interface CheckpointPayloadV3 {
  v: 3;
  created_at: string;
  up_to_timestamp: string;
  up_to_hash: string;
  up_to_event_id: string;
  event_count: number;
  segments: CheckpointSegment[];
}

export type CheckpointPayload = CheckpointPayloadV1 | CheckpointPayloadV2 | CheckpointPayloadV3;

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
