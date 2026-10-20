#!/usr/bin/env node
// §10.2 / FR-019: offline verification of the audit chain against a signed
// checkpoint that lives outside the database and outside the API/gateway
// containers.
//
// Inputs:
//   --export <file>      JSON from GET /v1/audit/checkpoints/:id/export
//                        (covered prefix) or an equivalent dump of the
//                        retained events (tail).
//   --public-key <file>  PEM of the operator-controlled checkpoint key.
//
// The verifier never calls the API and trusts nothing it reads from the
// database: it checks the checkpoint signature, the event hashes and links
// with the same code the gateway appends with, the cut the checkpoint names,
// and the per-workspace sequences. A partial or truncated history is
// reported as partial — never as fully verified (§10.2).
//
// Build first (`npm run build`), then:
//   npm run audit:verify -- --export export.json --public-key checkpoint.pub.pem
import { readFileSync } from "node:fs";
import {
  verifyAuditChain, verifyCheckpoint, checkpointKeyId,
  type AuditRow, type CheckpointPayload
} from "@traceguard/audit-chain";

const args = process.argv.slice(2);
function flag(name: string): string | null {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : null;
}

const exportPath = flag("export");
const keyPath = flag("public-key");
if (!exportPath || !keyPath) {
  console.error("usage: verify-audit --export <export.json> --public-key <checkpoint.pub.pem>");
  process.exit(2);
}

let problems = 0;
const fail = (msg: string) => { problems += 1; console.error(`FAIL  ${msg}`); };
const ok = (msg: string) => console.log(`ok    ${msg}`);

interface ExportedCheckpoint {
  id?: string; created_at?: string; up_to_timestamp?: string; up_to_hash?: string;
  event_count?: number; signature?: string; key_id?: string; payload?: CheckpointPayload;
}

let doc: { checkpoint?: ExportedCheckpoint; events?: AuditRow[]; truncated?: boolean };
try {
  doc = JSON.parse(readFileSync(exportPath, "utf8")) as typeof doc;
} catch (err) {
  console.error(`cannot read export: ${(err as Error).message}`);
  process.exit(2);
}
const checkpoint = doc.checkpoint;
const events = Array.isArray(doc.events) ? doc.events : [];
if (!checkpoint || typeof checkpoint !== "object") {
  console.error("export carries no checkpoint object");
  process.exit(2);
}
if (doc.truncated) fail("export is truncated; the checkpoint's segment is not fully present");

let publicKeyPem: string;
try {
  publicKeyPem = readFileSync(keyPath, "utf8");
} catch (err) {
  console.error(`cannot read public key: ${(err as Error).message}`);
  process.exit(2);
}

// 1. The checkpoint names its key; the supplied key must be that key.
if (checkpoint.key_id && checkpointKeyId(publicKeyPem) !== checkpoint.key_id) {
  fail(`public key does not match the checkpoint's key_id ${checkpoint.key_id}`);
} else {
  ok("checkpoint key id matches the supplied public key");
}

// 2. The signature over the canonical payload.
const payload = checkpoint.payload;
if (!payload || typeof payload !== "object" || typeof checkpoint.signature !== "string") {
  fail("export carries no signed payload");
} else if (!verifyCheckpoint(payload, checkpoint.signature, publicKeyPem)) {
  fail("checkpoint signature does not verify");
} else {
  ok(`checkpoint ${checkpoint.id ?? "?"} signature verifies (v${payload.v}, ${payload.event_count} events signed)`);
}

if (payload && typeof payload === "object") {
  // 3. The cut the checkpoint signed must be present and match.
  const upToHash = payload.up_to_hash;
  const lastHash = events.length > 0 ? events[events.length - 1].hash : null;
  const firstEvent = events[0];
  const coveredByCheckpoint = lastHash === upToHash;
  const anchoredToCheckpoint = !!firstEvent &&
    (firstEvent.hash === upToHash || firstEvent.prev_hash === upToHash);

  if (!coveredByCheckpoint && !anchoredToCheckpoint) {
    fail("export is neither the signed segment (last hash matches) nor the retained tail anchored to it");
  } else if (coveredByCheckpoint) {
    // Covered-prefix export: the whole signed segment must be here.
    if (typeof payload.event_count === "number" && events.length !== payload.event_count && !doc.truncated) {
      fail(`export has ${events.length} events but the checkpoint signed ${payload.event_count}`);
    } else {
      ok(`signed segment present: ${events.length} events cut at ${String(upToHash).slice(0, 12)}…`);
    }
    // v2: every workspace's last covered sequence must be the one signed.
    if (payload.v === 2) {
      const byWorkspace = new Map<string, { seq: number | null; hash: string }>();
      for (const row of events) {
        const ws = row.workspace_id ?? null;
        const key = ws ?? "(unattributed)";
        const seq = row.seq === null || row.seq === undefined ? null : Number(row.seq);
        const prior = byWorkspace.get(key);
        if (prior === undefined || (seq !== null && (prior.seq === null || seq > prior.seq))) {
          byWorkspace.set(key, { seq, hash: row.hash });
        }
      }
      for (const segment of payload.segments ?? []) {
        const key = segment.workspace_id ?? "(unattributed)";
        const found = byWorkspace.get(key);
        if (!found) {
          fail(`segment for workspace ${key} is missing from the export`);
        } else if (found.hash !== segment.up_to_hash ||
                   (segment.up_to_sequence !== null && found.seq !== segment.up_to_sequence)) {
          fail(`segment for workspace ${key} does not match the signed head (sequence/hash)`);
        }
      }
      ok(`checked ${(payload.segments ?? []).length} per-workspace segment head(s) against the export`);
    }
  } else {
    // Retained-tail export: the first row must link back to the cut, and no
    // retained sequence may predate its signed segment head.
    ok(`retained tail is anchored to checkpoint ${checkpoint.id ?? "?"} at ${String(upToHash).slice(0, 12)}…`);
    if (payload.v === 2) {
      const firstSeq = new Map<string, number>();
      for (const row of events) {
        if (row.seq === null || row.seq === undefined) continue;
        const key = row.workspace_id ?? "(unattributed)";
        const seq = Number(row.seq);
        if (!firstSeq.has(key) || seq < firstSeq.get(key)!) firstSeq.set(key, seq);
      }
      for (const segment of payload.segments ?? []) {
        const key = segment.workspace_id ?? "(unattributed)";
        if (segment.up_to_sequence === null) continue;
        const first = firstSeq.get(key);
        if (first === undefined) {
          fail(`retained events for workspace ${key} are missing; cannot prove continuity past the cut`);
        } else if (first <= segment.up_to_sequence) {
          fail(`retained event for workspace ${key} (seq ${first}) is already covered by the checkpoint (seq ${segment.up_to_sequence})`);
        }
      }
    }
  }

  // 4. Sequence continuity within every retained workspace segment.
  const seqs = new Map<string, number[]>();
  let nullSeqs = 0;
  for (const row of events) {
    if (row.seq === null || row.seq === undefined) { nullSeqs += 1; continue; }
    const key = row.workspace_id ?? "(unattributed)";
    if (!seqs.has(key)) seqs.set(key, []);
    seqs.get(key)!.push(Number(row.seq));
  }
  for (const [key, list] of seqs) {
    list.sort((a, b) => a - b);
    for (let i = 1; i < list.length; i += 1) {
      if (list[i] !== list[i - 1] + 1) {
        fail(`sequence gap in workspace ${key}: ${list[i - 1]} then ${list[i]}`);
      }
    }
  }
  ok(`sequence continuity checked${nullSeqs > 0 ? ` (${nullSeqs} legacy row(s) carry no sequence)` : ""}`);

  // 5. Every event hash and chain link, verified with the append formula.
  const verification = verifyAuditChain(events);
  const remaining = [...verification.problems];
  if (remaining.length > 0 && anchoredToCheckpoint && !coveredByCheckpoint) {
    // The broken first link of a pruned tail is expected once the checkpoint
    // anchors it; every other problem stands.
    const first = remaining[0];
    if (first.id === events[0]?.id && first.problem.startsWith("chain link broken")) {
      remaining.shift();
    }
  }
  if (remaining.length > 0) {
    for (const p of remaining.slice(0, 20)) fail(`event ${p.id}: ${p.problem}`);
    if (remaining.length > 20) fail(`…and ${remaining.length - 20} more problem(s)`);
  } else {
    ok(`all ${events.length} event hash(es) and chain link(s) verified`);
  }
}

// §10.2: only a fully present, fully intact chain may call itself verified.
if (problems === 0) {
  console.log(doc.truncated
    ? "PARTIAL: everything present verifies, but the export was truncated"
    : "PASS: audit history verifies against the signed checkpoint");
  process.exit(0);
}
console.error(`\n${problems} problem(s): audit history does NOT verify against the signed checkpoint`);
process.exit(1);
