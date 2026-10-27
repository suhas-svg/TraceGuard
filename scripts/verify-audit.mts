#!/usr/bin/env node
// §10.2 / FR-019: offline verification of the audit chain against a signed
// checkpoint that lives outside the database and outside the API/gateway
// containers.
//
// Inputs:
//   --export <file>      JSON artifact written by `audit:checkpoint create`
//                        (covered prefix) or an equivalent dump of the
//                        retained events (tail).
//   --public-key <file>  PEM of the operator-controlled checkpoint key.
//
// The verifier never calls the API and trusts nothing it reads from the
// database: it checks the checkpoint signature, any prior signed checkpoint
// carried as the artifact's `anchor`, the event hashes and links
// with the same code the gateway appends with, the cut the checkpoint names,
// and the per-workspace sequences. A partial or truncated history is
// reported as partial — never as fully verified (§10.2).
//
// Build first (`pnpm build`), then:
//   pnpm audit:verify -- --export export.json --public-key checkpoint.pub.pem
import { readFileSync } from "node:fs";
import {
  orderAuditChain, verifyAuditChain, verifyCheckpoint, checkpointKeyId,
  type AuditRow, type CheckpointPayload, type CheckpointSegment
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

interface ExportDoc {
  checkpoint?: ExportedCheckpoint;
  /** The prior pruned checkpoint, carried by `audit:checkpoint create` so a
   * retained segment after a prune can still be verified offline. */
  anchor?: ExportedCheckpoint;
  events?: AuditRow[];
  truncated?: boolean;
}

let doc: ExportDoc;
try {
  doc = JSON.parse(readFileSync(exportPath, "utf8")) as ExportDoc;
} catch (err) {
  console.error(`cannot read export: ${(err as Error).message}`);
  process.exit(2);
}
const checkpoint = doc.checkpoint;
// The export is written in (timestamp, id) order, which is ambiguous when two
// appends share a millisecond. Restore the order the hash links define before
// any check reads a "first" or "last" event.
const events = orderAuditChain(Array.isArray(doc.events) ? doc.events : []);
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

// 2a. A retained segment after a prune must carry the prior signed checkpoint.
// That signature, not an unsigned artifact field, proves where the segment
// starts and which workspace sequences it continues.
let priorAnchorHash: string | null = null;
let priorAnchorSegments: CheckpointSegment[] | undefined;
const priorAnchor = doc.anchor;
if (priorAnchor && typeof priorAnchor === "object") {
  const anchorPayload = priorAnchor.payload;
  if (!anchorPayload || typeof priorAnchor.signature !== "string") {
    fail("prior anchor checkpoint is incomplete");
  } else if (priorAnchor.key_id && checkpointKeyId(publicKeyPem) !== priorAnchor.key_id) {
    fail(`prior anchor checkpoint key_id ${priorAnchor.key_id} does not match the supplied public key`);
  } else if (!verifyCheckpoint(anchorPayload, priorAnchor.signature, publicKeyPem)) {
    fail("prior anchor checkpoint signature does not verify");
  } else if (!events[0] || events[0].prev_hash !== anchorPayload.up_to_hash) {
    fail("prior anchor checkpoint does not link to the first exported event");
  } else {
    priorAnchorHash = anchorPayload.up_to_hash;
    priorAnchorSegments = anchorPayload.v === 1 ? undefined : anchorPayload.segments;
    ok(`prior anchor checkpoint ${priorAnchor.id ?? "?"} verifies and links the retained segment`);
  }
}

if (payload && typeof payload === "object") {
  // 3. The cut the checkpoint signed must be present and match.
  const upToHash = payload.up_to_hash;
  // v1 checkpoints predate per-workspace segments. Narrowing on the literal
  // version keeps TypeScript from treating `segments` as optional on v2/v3.
  const segments = payload.v === 1 ? [] : payload.segments;
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
    if (payload.v === 3 && payload.up_to_event_id !== events[events.length - 1]?.id) {
      fail("checkpoint names a different last event than the exported segment");
    }
    // v2+: every workspace's last covered sequence must be the one signed.
    if (payload.v >= 2) {
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
      // A workspace with no event in this segment inherits the prior
      // checkpoint's head. The inherited value must still match exactly.
      const carried = new Map<string, { seq: number | null; hash: string }>();
      for (const segment of priorAnchorSegments ?? []) {
        carried.set(segment.workspace_id ?? "(unattributed)", {
          seq: segment.up_to_sequence,
          hash: segment.up_to_hash
        });
      }
      for (const segment of segments) {
        const key = segment.workspace_id ?? "(unattributed)";
        const found = byWorkspace.get(key);
        if (!found) {
          const inherited = carried.get(key);
          if (!inherited) {
            fail(`segment for workspace ${key} is missing from the export`);
          } else if (inherited.hash !== segment.up_to_hash ||
                     (segment.up_to_sequence !== null && inherited.seq !== segment.up_to_sequence)) {
            fail(`carried segment for workspace ${key} does not match the prior signed head`);
          }
        } else if (found.hash !== segment.up_to_hash ||
                   (segment.up_to_sequence !== null && found.seq !== segment.up_to_sequence)) {
          fail(`segment for workspace ${key} does not match the signed head (sequence/hash)`);
        }
      }
      ok(`checked ${segments.length} per-workspace segment head(s) against the export`);
    }
  } else {
    // Retained-tail export: the first row must link back to the cut, and each
    // workspace's retained sequence must continue exactly at the signed head.
    ok(`retained tail is anchored to checkpoint ${checkpoint.id ?? "?"} at ${String(upToHash).slice(0, 12)}…`);
    if (payload.v >= 2) {
      const firstSeq = new Map<string, number>();
      for (const row of events) {
        if (row.seq === null || row.seq === undefined) continue;
        const key = row.workspace_id ?? "(unattributed)";
        const seq = Number(row.seq);
        if (!firstSeq.has(key) || seq < firstSeq.get(key)!) firstSeq.set(key, seq);
      }
      for (const segment of segments) {
        const key = segment.workspace_id ?? "(unattributed)";
        if (segment.up_to_sequence === null) continue;
        const first = firstSeq.get(key);
        if (first === undefined) {
          // No event for this workspace in the retained tail. That is not a
          // gap; the next event must continue from the signed head.
          continue;
        } else if (first <= segment.up_to_sequence) {
          fail(`retained event for workspace ${key} (seq ${first}) is already covered by the checkpoint (seq ${segment.up_to_sequence})`);
        } else if (first !== segment.up_to_sequence + 1) {
          fail(`sequence gap in workspace ${key}: checkpoint ends at ${segment.up_to_sequence}, retained starts at ${first}`);
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
  // A retained tail is checked against the signed cut so its first sequence
  // is not mistaken for a gap. A covered prefix after an earlier prune uses
  // the prior checkpoint carried in the artifact.
  let anchorForVerify = priorAnchorHash;
  let sequencesForVerify = priorAnchorSegments;
  if (!anchorForVerify && anchoredToCheckpoint && !coveredByCheckpoint && typeof upToHash === "string") {
    anchorForVerify = upToHash;
    sequencesForVerify = payload.v === 1 ? undefined : segments;
  }
  const verification = verifyAuditChain(
    events,
    anchorForVerify
      ? { anchorHash: anchorForVerify, expectedSequences: sequencesForVerify }
      : {}
  );
  if (verification.problems.length > 0) {
    for (const p of verification.problems.slice(0, 20)) fail(`event ${p.id}: ${p.problem}`);
    if (verification.problems.length > 20) fail(`…and ${verification.problems.length - 20} more problem(s)`);
  } else {
    ok(`all ${events.length} event hash(es) and chain link(s) verified`);
  }
  for (const gap of verification.gaps) {
    fail(`missing sequence range in ${gap.workspace_id ?? "(unattributed)"}: ${gap.from}..${gap.to}`);
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
