#!/usr/bin/env node
// §10.2 / FR-019 operator tooling.
//
// The checkpoint private key never enters the API or gateway. This script runs
// on the operator host, signs an exact global prefix ending at --cutoff, writes
// the signed artifact outside the database, and (separately) prunes only after
// re-verifying that artifact and matching it against the rows still present.
//
//   npm run audit:checkpoint -- create --cutoff <event-id> --out checkpoint.json \
//     --key checkpoint.key.pem
//   npm run audit:checkpoint -- prune --artifact checkpoint.json \
//     --public-key checkpoint.pub.pem --receipt s3://audit-vault/checkpoint.json
//
// `create` needs the retention role (SELECT audit events/checkpoints, INSERT
// checkpoints). `prune` needs the retention role's prune function. Neither
// operation is exposed on the gateway. An artifact created after a prune
// carries the prior signed checkpoint as its `anchor`; create/prune refuse if
// that anchor was signed by a different key (key rotation needs a trusted key
// history first).
import { readFileSync, writeFileSync } from "node:fs";
import { createPublicKey, type KeyObject } from "node:crypto";
import { Pool, type PoolClient } from "pg";
import {
  appendAuditEvent, checkpointKeyId, signCheckpoint, verifyAuditChain,
  verifyCheckpoint, type AuditRow, type CheckpointPayload, type CheckpointPayloadV3,
  type VerifyOptions
} from "@traceguard/audit-chain";

type Row = AuditRow & { seq: string | number | null };

function arg(name: string): string | null {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : null;
}

function required(name: string): string {
  const value = arg(name);
  if (!value) {
    console.error(`missing --${name}`);
    process.exit(2);
  }
  return value;
}

function databaseUrl(): string {
  const url = arg("database-url") ?? process.env.DATABASE_URL_RETENTION ?? process.env.DATABASE_URL;
  if (!url) {
    console.error("DATABASE_URL_RETENTION (or DATABASE_URL) is required");
    process.exit(2);
  }
  return url;
}

function privateKey(): string {
  const file = arg("key") ?? process.env.AUDIT_CHECKPOINT_KEY_FILE;
  if (file) return readFileSync(file, "utf8");
  const pem = process.env.AUDIT_CHECKPOINT_KEY;
  if (pem) return pem;
  console.error("provide --key <private.pem> or AUDIT_CHECKPOINT_KEY_FILE");
  process.exit(2);
}

function publicKey(): string {
  const file = arg("public-key") ?? process.env.AUDIT_CHECKPOINT_PUBLIC_KEY_FILE;
  if (file) return readFileSync(file, "utf8");
  const pem = process.env.AUDIT_CHECKPOINT_PUBLIC_KEY;
  if (pem) return pem;
  console.error("provide --public-key <public.pem> or AUDIT_CHECKPOINT_PUBLIC_KEY_FILE");
  process.exit(2);
}

function publicPemFromPrivate(pem: string): string {
  const key: KeyObject = createPublicKey(pem);
  return key.export({ type: "spki", format: "pem" }).toString();
}

const SELECT_EVENTS = `
  SELECT id, timestamp, actor_type, actor_id, action, resource_type, resource_id,
         result, metadata, prev_hash, hash, workspace_id, seq, hash_version,
         policy_version_id, matched_rule_ids, project_id
    FROM audit_events`;

interface RetainedAnchor {
  checkpoint_id: string;
  up_to_event_id: string | null;
  up_to_hash: string;
  event_count: number;
  signature: string;
  key_id: string;
  payload: CheckpointPayload;
  segments: CheckpointPayloadV3["segments"];
}

// After a prune, the oldest retained row links to the pruned checkpoint's hash
// and its workspace sequences resume above the signed segment. The latest
// prune is therefore the only valid starting anchor for this retained chain.
async function loadAnchor(client: PoolClient): Promise<RetainedAnchor | null> {
  const result = await client.query<{
    checkpoint_id: string;
    up_to_event_id: string | null;
    up_to_hash: string;
    event_count: number;
    signature: string;
    key_id: string;
    payload: CheckpointPayload;
  }>(
    `SELECT ap.checkpoint_id, ac.up_to_event_id, ac.up_to_hash, ac.event_count,
            ac.signature, ac.key_id, ac.payload
       FROM audit_prunes ap
       JOIN audit_checkpoints ac ON ac.id = ap.checkpoint_id
      ORDER BY ap.pruned_at DESC, ap.id DESC
      LIMIT 1`
  );
  const row = result.rows[0];
  if (!row) return null;
  return {
    checkpoint_id: row.checkpoint_id,
    up_to_event_id: row.up_to_event_id,
    up_to_hash: row.up_to_hash,
    event_count: Number(row.event_count),
    signature: row.signature,
    key_id: row.key_id,
    payload: row.payload,
    segments: row.payload.v === 1 ? [] : row.payload.segments
  };
}

function verifyOptions(anchor: RetainedAnchor | null, events: Row[]): VerifyOptions {
  // Only apply the anchor when the retained segment actually links to it. A
  // mismatched first link is a verification problem, not a reason to relax it.
  if (!anchor || events[0]?.prev_hash !== anchor.up_to_hash) return {};
  return {
    anchorHash: anchor.up_to_hash,
    expectedSequences: anchor.segments.map((segment) => ({
      workspace_id: segment.workspace_id,
      up_to_sequence: segment.up_to_sequence
    }))
  };
}

async function create(): Promise<void> {
  const cutoffId = required("cutoff");
  const out = required("out");
  const pool = new Pool({ connectionString: databaseUrl() });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    // The cutoff is the LAST event in the segment being signed. Every row
    // through it is the exact contiguous prefix the checkpoint covers.
    const cutoff = cutoffId === "latest"
      ? await client.query<{ id: string; timestamp: Date; hash: string }>(
          "SELECT id, timestamp, hash FROM audit_events ORDER BY timestamp DESC, id DESC LIMIT 1"
        )
      : await client.query<{ id: string; timestamp: Date; hash: string }>(
          "SELECT id, timestamp, hash FROM audit_events WHERE id = $1", [cutoffId]
        );
    if (!cutoff.rows[0]) throw new Error(`audit event ${cutoffId} not found`);
    const rows = await client.query<Row>(
      `${SELECT_EVENTS} WHERE (timestamp, id) <= ($1, $2) ORDER BY timestamp ASC, id ASC`,
      [cutoff.rows[0].timestamp, cutoff.rows[0].id]
    );
    const events = rows.rows;
    const anchor = await loadAnchor(client);
    const privatePem = privateKey();
    const publicPem = createPublicKey(privatePem)
      .export({ type: "spki", format: "pem" })
      .toString();
    if (anchor) {
      // The retained prefix is only anchored if the prior checkpoint's
      // signature verifies with the same key that is about to sign this one.
      // A database editor must not be able to invent a convenient anchor.
      if (anchor.key_id !== checkpointKeyId(publicPem)) {
        throw new Error(
          "latest pruned checkpoint was signed by a different key; re-anchor explicitly before continuing"
        );
      }
      if (!verifyCheckpoint(anchor.payload, anchor.signature, publicPem)) {
        throw new Error("latest pruned checkpoint signature does not verify");
      }
      if (events[0]?.prev_hash !== anchor.up_to_hash) {
        throw new Error("retained audit chain does not link to the latest pruned checkpoint");
      }
    }
    const verification = verifyAuditChain(events, verifyOptions(anchor, events));
    if (!verification.ok) {
      throw new Error(`refusing to checkpoint an invalid segment: ${verification.problems[0]?.problem}`);
    }

    const segments = new Map<string, { workspace_id: string | null; up_to_sequence: number | null; up_to_hash: string }>();
    // Carry forward the prior checkpoint's heads for workspaces that have no
    // event in this segment. Otherwise a later checkpoint would lose the only
    // signed proof of where a dormant workspace's sequence continues.
    if (anchor && events[0]?.prev_hash === anchor.up_to_hash) {
      for (const segment of anchor.segments) {
        segments.set(segment.workspace_id ?? "\u0000", { ...segment });
      }
    }
    for (const row of events) {
      if (row.seq === null || row.seq === undefined) continue;
      const key = row.workspace_id ?? "\u0000";
      const prior = segments.get(key);
      const seq = Number(row.seq);
      if (!prior || (prior.up_to_sequence ?? -1) < seq) {
        segments.set(key, {
          workspace_id: row.workspace_id ?? null,
          up_to_sequence: seq,
          up_to_hash: row.hash
        });
      }
    }

    const payload: CheckpointPayloadV3 = {
      v: 3,
      created_at: new Date().toISOString(),
      up_to_event_id: cutoff.rows[0].id,
      up_to_timestamp: new Date(cutoff.rows[0].timestamp).toISOString(),
      up_to_hash: cutoff.rows[0].hash,
      event_count: events.length,
      segments: [...segments.values()]
    };
    const signed = signCheckpoint(payload, privatePem);
    const inserted = await client.query<{ id: string; created_at: Date }>(
      `INSERT INTO audit_checkpoints
         (up_to_event_id, up_to_timestamp, up_to_hash, event_count, signature, key_id, payload)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, created_at`,
      [payload.up_to_event_id, payload.up_to_timestamp, payload.up_to_hash,
       payload.event_count, signed.signature, signed.key_id, JSON.stringify(payload)]
    );
    // The checkpoint row and its audit record commit together. The artifact
    // cannot be written until the row is durable, so a failed append rolls
    // back the checkpoint instead of leaving an unlogged anchor.
    await appendAuditEvent(client, {
      actor_type: "operator",
      actor_id: "audit-checkpoint",
      action: "audit.checkpoint.created",
      resource_type: "audit_checkpoint",
      resource_id: inserted.rows[0].id,
      result: "success",
      metadata: {
        up_to_event_id: payload.up_to_event_id,
        up_to_hash: payload.up_to_hash,
        event_count: payload.event_count,
        artifact: out,
        key_id: signed.key_id
      }
    });
    await client.query("COMMIT");

    // Write the external artifact only after the signed row exists. If the
    // write fails, no prune can proceed: prune requires the artifact.
    const artifact = {
      checkpoint: {
        id: inserted.rows[0].id,
        created_at: inserted.rows[0].created_at,
        up_to_event_id: payload.up_to_event_id,
        up_to_timestamp: payload.up_to_timestamp,
        up_to_hash: payload.up_to_hash,
        event_count: payload.event_count,
        signature: signed.signature,
        key_id: signed.key_id,
        payload
      },
      // The prior pruned checkpoint proves where this retained segment starts
      // and what each workspace's last covered sequence was. Without it an
      // offline verifier cannot distinguish a valid continuation from a gap.
      anchor: anchor ? {
        id: anchor.checkpoint_id,
        up_to_event_id: anchor.up_to_event_id,
        up_to_hash: anchor.up_to_hash,
        event_count: anchor.event_count,
        signature: anchor.signature,
        key_id: anchor.key_id,
        payload: anchor.payload
      } : null,
      events,
      truncated: false
    };
    writeFileSync(out, `${JSON.stringify(artifact, null, 2)}\n`, { mode: 0o600 });
    console.log(`checkpoint ${inserted.rows[0].id}: ${events.length} events through ${cutoffId}`);
    console.log(`artifact: ${out}`);
  } catch (err) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw err;
  } finally {
    client.release();
    await pool.end();
  }
}

interface Artifact {
  checkpoint?: {
    id?: string;
    created_at?: string;
    up_to_event_id?: string;
    up_to_timestamp?: string;
    up_to_hash?: string;
    event_count?: number;
    signature?: string;
    key_id?: string;
    payload?: CheckpointPayloadV3;
  };
  anchor?: unknown;
  events?: Row[];
  truncated?: boolean;
}

async function prune(): Promise<void> {
  const artifactPath = required("artifact");
  const receipt = required("receipt");
  if (!receipt.trim()) throw new Error("--receipt must name the external artifact storage");
  const doc = JSON.parse(readFileSync(artifactPath, "utf8")) as Artifact;
  const cp = doc.checkpoint;
  if (!cp?.id || !cp.payload || !cp.signature || !Array.isArray(doc.events)) {
    throw new Error("artifact is missing its checkpoint or events");
  }
  if (doc.truncated) throw new Error("refusing to prune from a truncated artifact");
  const pem = publicKey();
  if (cp.key_id && checkpointKeyId(pem) !== cp.key_id) {
    throw new Error("artifact key_id does not match the supplied public key");
  }
  if (!verifyCheckpoint(cp.payload, cp.signature, pem)) {
    throw new Error("checkpoint signature does not verify");
  }
  if (cp.payload.v !== 3 || cp.payload.up_to_event_id !== cp.up_to_event_id) {
    throw new Error("artifact is not a v3 checkpoint anchored at an event");
  }
  if (doc.events.length !== cp.payload.event_count) {
    throw new Error(`artifact has ${doc.events.length} events but the checkpoint signed ${cp.payload.event_count}`);
  }

  const pool = new Pool({ connectionString: databaseUrl() });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const stored = await client.query<{
      up_to_event_id: string | null;
      up_to_hash: string;
      event_count: number;
      signature: string;
      key_id: string;
    }>(
      `SELECT up_to_event_id, up_to_hash, event_count, signature, key_id
         FROM audit_checkpoints WHERE id = $1`,
      [cp.id]
    );
    const storedCp = stored.rows[0];
    if (!storedCp) throw new Error(`checkpoint ${cp.id} is not in the database`);
    if (storedCp.up_to_event_id !== cp.payload.up_to_event_id ||
        storedCp.up_to_hash !== cp.payload.up_to_hash ||
        Number(storedCp.event_count) !== cp.payload.event_count ||
        storedCp.signature !== cp.signature ||
        storedCp.key_id !== cp.key_id) {
      throw new Error("artifact does not match the stored checkpoint");
    }

    const anchor = await loadAnchor(client);
    if (anchor) {
      // The database's claimed anchor is only meaningful if the prior
      // checkpoint signature verifies with the operator key.
      if (anchor.key_id !== checkpointKeyId(pem)) {
        throw new Error(
          "latest pruned checkpoint was signed by a different key; re-anchor explicitly before pruning"
        );
      }
      if (!verifyCheckpoint(anchor.payload, anchor.signature, pem)) {
        throw new Error("latest pruned checkpoint signature does not verify");
      }
      if (doc.events[0]?.prev_hash !== anchor.up_to_hash) {
        throw new Error("artifact does not link to the latest pruned checkpoint");
      }
    }
    const verification = verifyAuditChain(doc.events, verifyOptions(anchor, doc.events));
    if (!verification.ok) {
      throw new Error(`artifact chain does not verify: ${verification.problems[0]?.problem}`);
    }

    // The database must still contain exactly the signed prefix. This is the
    // check that makes a checkpoint boundary, not a caller-supplied hash,
    // decide what gets deleted.
    const dbRows = await client.query<Row>(
      `${SELECT_EVENTS} WHERE (timestamp, id) <= ($1, $2) ORDER BY timestamp ASC, id ASC`,
      [cp.payload.up_to_timestamp, cp.payload.up_to_event_id]
    );
    if (dbRows.rows.length !== doc.events.length) {
      throw new Error(`database prefix has ${dbRows.rows.length} events; artifact has ${doc.events.length}`);
    }
    for (let i = 0; i < dbRows.rows.length; i += 1) {
      const db = dbRows.rows[i];
      const exported = doc.events[i];
      if (db.id !== exported.id || db.hash !== exported.hash || Number(db.seq) !== Number(exported.seq)) {
        throw new Error(`database event ${i} does not match the signed artifact`);
      }
    }

    // Deleting the segment and recording the prune event commit atomically:
    // a crash cannot leave rows deleted without an audit trail.
    const pruned = await client.query<{ deleted: string }>(
      "SELECT prune_audit_events($1, $2) AS deleted", [cp.id, receipt]
    );
    const deleted = Number(pruned.rows[0]?.deleted);
    if (deleted < 0) throw new Error("checkpoint does not cover the database prefix");
    await appendAuditEvent(client, {
      actor_type: "operator",
      actor_id: "audit-checkpoint",
      action: "audit.segment.pruned",
      resource_type: "audit_checkpoint",
      resource_id: cp.id,
      result: "success",
      metadata: {
        up_to_event_id: cp.up_to_event_id,
        up_to_hash: cp.up_to_hash,
        deleted,
        external_ref: receipt
      }
    });
    await client.query("COMMIT");
    console.log(`pruned ${deleted} events through ${cp.up_to_event_id} (checkpoint ${cp.id})`);
  } catch (err) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw err;
  } finally {
    client.release();
    await pool.end();
  }
}

const command = process.argv[2];
try {
  if (command === "create") await create();
  else if (command === "prune") await prune();
  else {
    console.error("usage: audit-checkpoint <create|prune> ...");
    process.exit(2);
  }
} catch (err) {
  console.error(`audit-checkpoint: ${(err as Error).message}`);
  process.exit(1);
}
