import { createHash, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalize } from "@traceguard/canonical-json";
import {
  auditHash, auditHashFor, auditHashV2, auditHashV3, auditHashV4, canonicalEventFields,
  checkpointKeyId, orderAuditChain, signCheckpoint, stableStringify, verifyAuditChain,
  verifyCheckpoint, HASH_VERSION_CANONICAL, HASH_VERSION_EVENT, HASH_VERSION_PROJECT,
  type AuditRow, type CheckpointPayload
} from "../src/index.js";

describe("checkpoint signing", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const payload: CheckpointPayload = {
    v: 1,
    created_at: "2026-10-17T10:00:00.000Z",
    up_to_timestamp: "2026-10-17T10:00:01.000Z",
    up_to_hash: "ab".repeat(32),
    event_count: 2
  };

  it("signs a checkpoint that verifies with the matching public key", () => {
    const signed = signCheckpoint(payload, privatePem);
    expect(signed.key_id).toBe(checkpointKeyId(publicPem));
    expect(verifyCheckpoint(payload, signed.signature, publicPem)).toBe(true);
  });

  it("refuses a tampered payload, a foreign key, and a public PEM as a signing key", () => {
    const signed = signCheckpoint(payload, privatePem);
    expect(verifyCheckpoint({ ...payload, event_count: 3 }, signed.signature, publicPem)).toBe(false);
    const other = generateKeyPairSync("ed25519");
    const otherPublic = other.publicKey.export({ type: "spki", format: "pem" }).toString();
    expect(verifyCheckpoint(payload, signed.signature, otherPublic)).toBe(false);
    expect(() => signCheckpoint(payload, otherPublic)).toThrow();
  });

  // §10.2: a v2 checkpoint names the workspace segments covered by the prune,
  // and those segments are signed material — editing them after the fact must
  // invalidate the signature like any other payload byte.
  it("covers the workspace segments inside the signed v2 payload", () => {
    const v2: CheckpointPayload = {
      ...payload,
      v: 2,
      segments: [
        { workspace_id: "ws-1", up_to_sequence: 3, up_to_hash: "cd".repeat(32) },
        { workspace_id: null, up_to_sequence: null, up_to_hash: "ef".repeat(32) }
      ]
    };
    const signed = signCheckpoint(v2, privatePem);
    expect(signed.key_id).toBe(checkpointKeyId(publicPem));
    expect(verifyCheckpoint(v2, signed.signature, publicPem)).toBe(true);
    expect(verifyCheckpoint({ ...v2, segments: [] }, signed.signature, publicPem)).toBe(false);
    expect(verifyCheckpoint(
      { ...v2, segments: [{ ...v2.segments[0], up_to_sequence: 4 }, v2.segments[1]] },
      signed.signature, publicPem
    )).toBe(false);
  });
});

// The chain's value is entirely in recomputation: everything here modifies an
// event and demands the verifier notice.
describe("audit chain", () => {
  const base = {
    actor_type: "admin",
    actor_id: "user-1",
    action: "policy.published",
    resource_type: "policy_version",
    resource_id: "pv-1",
    result: "success"
  };
  const ts1 = "2026-10-17T10:00:00.000Z";
  const ts2 = "2026-10-17T10:00:01.000Z";

  function chain(): AuditRow[] {
    const first: AuditRow = {
      id: "11111111-1111-1111-1111-111111111111",
      timestamp: ts1,
      ...base,
      metadata: { version: 1 },
      prev_hash: "",
      hash: auditHash("", ts1, { ...base, metadata: { version: 1 } })
    };
    const second: AuditRow = {
      id: "22222222-2222-2222-2222-222222222222",
      timestamp: ts2,
      ...base,
      actor_id: "user-2",
      resource_id: "pv-2",
      metadata: { version: 2 },
      prev_hash: first.hash,
      hash: auditHash(first.hash, ts2, { ...base, actor_id: "user-2", resource_id: "pv-2", metadata: { version: 2 } })
    };
    return [first, second];
  }

  it("verifies an intact chain", () => {
    const result = verifyAuditChain(chain());
    expect(result.ok).toBe(true);
    expect(result.checked).toBe(2);
    expect(result.problems).toEqual([]);
  });

  it("detects a modified event", () => {
    const rows = chain();
    rows[0].metadata = { version: 1, injected: true };
    const result = verifyAuditChain(rows);
    expect(result.ok).toBe(false);
    expect(result.problems).toHaveLength(1);
    expect(result.problems[0].id).toBe(rows[0].id);
    expect(result.problems[0].problem).toMatch(/modified/);
  });

  it("detects a modified event whose hash was recomputed to match", () => {
    // The stronger tamper: edit the content and fix up the row's own hash.
    // The next row still cites the original hash, so the link breaks.
    const rows = chain();
    rows[0].metadata = { version: 99 };
    rows[0].hash = auditHash("", ts1, {
      ...base, metadata: rows[0].metadata as Record<string, unknown>
    });
    const result = verifyAuditChain(rows);
    expect(result.ok).toBe(false);
    expect(result.problems.some((p) => /chain link broken/.test(p.problem))).toBe(true);
  });

  it("flags a chain that no longer starts at the beginning", () => {
    const rows = chain().filter((r) => !r.id.startsWith("1111"));
    const result = verifyAuditChain(rows);
    expect(result.ok).toBe(false);
    expect(result.problems[0].problem).toMatch(/chain link broken/);
  });

  it("cannot see a removed tail without an external anchor", () => {
    // A prefix of an intact chain is internally consistent — only a signed,
    // externally stored checkpoint can prove the tail ever existed. This is
    // a documented property, not a verifier gap.
    expect(verifyAuditChain(chain().slice(0, 1)).ok).toBe(true);
  });

  it("detects reordered events", () => {
    const rows = chain().reverse();
    const result = verifyAuditChain(rows);
    expect(result.ok).toBe(false);
  });

  // Appends share a millisecond under load; the id is random, so reading by
  // (timestamp, id) can invert a pair the hash links put in order.
  it("restores chain order when two appends share a millisecond", () => {
    const firstContent = { ...base, metadata: { version: 1 } };
    const secondContent = { ...base, actor_id: "user-2", resource_id: "pv-2", metadata: { version: 2 } };
    const first: AuditRow = {
      id: "11111111-1111-1111-1111-111111111111",
      timestamp: ts1,
      ...base,
      metadata: { version: 1 },
      prev_hash: "",
      hash: auditHash("", ts1, firstContent)
    };
    const second: AuditRow = {
      id: "22222222-2222-2222-2222-222222222222",
      timestamp: ts1,
      ...base,
      actor_id: "user-2",
      resource_id: "pv-2",
      metadata: { version: 2 },
      prev_hash: first.hash,
      hash: auditHash(first.hash, ts1, secondContent)
    };
    expect(verifyAuditChain([second, first]).ok).toBe(false);
    const ordered = orderAuditChain([second, first]);
    expect(ordered.map((row) => row.id)).toEqual([first.id, second.id]);
    expect(verifyAuditChain(ordered).ok).toBe(true);
  });

  it("leaves a fork in caller order so the verifier still reports it", () => {
    const rows = chain();
    const forkContent = { ...base, actor_id: "user-2", resource_id: "pv-2", metadata: { version: 3 } };
    const fork: AuditRow = {
      ...rows[1],
      id: "33333333-3333-3333-3333-333333333333",
      metadata: { version: 3 },
      hash: auditHash(rows[0].hash, ts2, forkContent)
    };
    const ordered = orderAuditChain([rows[0], rows[1], fork]);
    expect(ordered).toHaveLength(3);
    expect(verifyAuditChain(ordered).ok).toBe(false);
  });

  it("is order-independent over metadata keys", () => {
    expect(stableStringify({ b: 2, a: [1, { y: 1, x: 0 }] }))
      .toBe(stableStringify({ a: [1, { x: 0, y: 1 }], b: 2 }));
  });

  // §10.1: the canonical (v2) chain — RFC 8785 JSON over the event fields
  // plus previous_hash, with workspace/policy attribution and a per-row
  // hash_version. The byte string below is the contract; if the serializer,
  // the field set, or the key order drifts, this test names it.
  describe("canonical (v2) format", () => {
    const v2Entry = {
      ...base,
      workspace_id: "ws-1",
      policy_version_id: "pv-1",
      matched_rule_ids: ["rule-a", "rule-b"],
      metadata: { version: 1 }
    };
    const v2Bytes =
      '{"action":"policy.published","actor_id":"user-1","actor_type":"admin",' +
      '"matched_rule_ids":["rule-a","rule-b"],"metadata":{"version":1},' +
      '"policy_version_id":"pv-1","previous_hash":"abc",' +
      '"resource_id":"pv-1","resource_type":"policy_version","result":"success",' +
      '"timestamp":"2026-10-17T10:00:00.000Z","workspace_id":"ws-1"}';

    function v2Chain(): AuditRow[] {
      const firstEntry = { ...base, metadata: { version: 1 }, workspace_id: "ws-1", policy_version_id: "pv-1", matched_rule_ids: ["rule-a", "rule-b"] };
      const first: AuditRow = {
        id: "33333333-3333-3333-3333-333333333333",
        timestamp: ts1,
        ...base,
        metadata: { version: 1 },
        workspace_id: "ws-1",
        hash_version: HASH_VERSION_CANONICAL,
        policy_version_id: "pv-1",
        matched_rule_ids: ["rule-a", "rule-b"],
        prev_hash: "",
        hash: auditHashV2("", ts1, firstEntry)
      };
      const secondEntry = { ...base, actor_id: "user-2", resource_id: "pv-2", metadata: { version: 2 }, workspace_id: "ws-1", policy_version_id: "pv-2", matched_rule_ids: ["rule-b"] };
      const second: AuditRow = {
        id: "44444444-4444-4444-4444-444444444444",
        timestamp: ts2,
        ...base,
        actor_id: "user-2",
        resource_id: "pv-2",
        metadata: { version: 2 },
        workspace_id: "ws-1",
        hash_version: HASH_VERSION_CANONICAL,
        policy_version_id: "pv-2",
        matched_rule_ids: ["rule-b"],
        prev_hash: first.hash,
        hash: auditHashV2(first.hash, ts2, secondEntry)
      };
      return [first, second];
    }

    it("locks the canonical field bytes and the dispatcher", () => {
      expect(canonicalize(canonicalEventFields("abc", ts1, v2Entry))).toBe(v2Bytes);
      expect(auditHashV2("abc", ts1, v2Entry))
        .toBe(createHash("sha256").update(v2Bytes).digest("hex"));
      expect(auditHashFor(2, "abc", ts1, v2Entry)).toBe(auditHashV2("abc", ts1, v2Entry));
      expect(auditHashFor(1, "", ts1, v2Entry)).toBe(auditHash("", ts1, v2Entry));
    });

    it("verifies a canonical chain and detects v2 tampering", () => {
      expect(verifyAuditChain(v2Chain()).ok).toBe(true);
      const rows = v2Chain();
      rows[1].metadata = { version: 3 };
      const result = verifyAuditChain(rows);
      expect(result.ok).toBe(false);
      expect(result.problems.some((p) => /modified/.test(p.problem))).toBe(true);
    });

    it("verifies a chain spanning the v1 to v2 transition", () => {
      const legacy = chain()[0];
      const entry = { ...base, metadata: { version: 2 }, workspace_id: "ws-1" };
      const second: AuditRow = {
        id: "55555555-5555-5555-5555-555555555555",
        timestamp: ts2,
        ...base,
        metadata: { version: 2 },
        workspace_id: "ws-1",
        hash_version: HASH_VERSION_CANONICAL,
        prev_hash: legacy.hash,
        hash: auditHashV2(legacy.hash, ts2, entry)
      };
      expect(verifyAuditChain([legacy, second]).ok).toBe(true);
    });
  });

  // §10.1/§10.2: v3 binds the event ID and per-workspace sequence, and the
  // verifier must report missing ranges instead of accepting a truncated
  // segment as complete.
  describe("v3 ID + sequence format", () => {
    function v3Row(seq: number, id: string, prevHash: string, timestamp = ts1): AuditRow {
      const metadata = { version: seq };
      const entry = { ...base, metadata, workspace_id: "ws-1" };
      return {
        id,
        timestamp,
        ...base,
        metadata,
        workspace_id: "ws-1",
        seq,
        hash_version: HASH_VERSION_EVENT,
        prev_hash: prevHash,
        hash: auditHashV3(prevHash, timestamp, entry, id, seq)
      };
    }

    function v3Chain(): AuditRow[] {
      const first = v3Row(1, "66666666-6666-6666-6666-666666666666", "");
      const second = v3Row(2, "77777777-7777-7777-7777-777777777777", first.hash, ts2);
      return [first, second];
    }

    it("hashes the event ID and sequence, and verifies an intact v3 chain", () => {
      const entry = { ...base, metadata: { version: 1 }, workspace_id: "ws-1" };
      expect(auditHashV3("", ts1, entry, "66666666-6666-6666-6666-666666666666", 1))
        .not.toBe(auditHashV3("", ts1, entry, "88888888-8888-8888-8888-888888888888", 1));
      expect(auditHashV3("", ts1, entry, "66666666-6666-6666-6666-666666666666", 1))
        .not.toBe(auditHashV3("", ts1, entry, "66666666-6666-6666-6666-666666666666", 2));
      expect(auditHashFor(HASH_VERSION_EVENT, "", ts1, entry,
        "66666666-6666-6666-6666-666666666666", 1))
        .toBe(auditHashV3("", ts1, entry, "66666666-6666-6666-6666-666666666666", 1));
      expect(verifyAuditChain(v3Chain()).ok).toBe(true);
    });

    it("reports a missing sequence inside a retained segment", () => {
      const first = v3Row(1, "66666666-6666-6666-6666-666666666666", "");
      const third = v3Row(3, "99999999-9999-9999-9999-999999999999", first.hash, ts2);
      const result = verifyAuditChain([first, third]);
      expect(result.ok).toBe(false);
      expect(result.gaps).toEqual([{ workspace_id: "ws-1", from: 2, to: 2 }]);
      expect(result.problems[0].problem).toMatch(/sequence gap/);
    });

    it("anchors a pruned segment at the signed workspace sequence", () => {
      const [first, second] = v3Chain();
      const opts = {
        anchorHash: first.hash,
        expectedSequences: [{ workspace_id: "ws-1", up_to_sequence: 1 }]
      };
      expect(verifyAuditChain([second], opts).ok).toBe(true);
      const withoutAnchor = verifyAuditChain([second]);
      expect(withoutAnchor.ok).toBe(false);
      expect(withoutAnchor.problems.some((p) => /without a signed checkpoint anchor/.test(p.problem))).toBe(true);
    });

    it("detects a renumbered sequence and a duplicate event ID", () => {
      const first = v3Row(1, "66666666-6666-6666-6666-666666666666", "");
      const duplicateId = v3Row(2, first.id, first.hash, ts2);
      expect(verifyAuditChain([first, duplicateId]).problems
        .some((p) => /duplicate event id/.test(p.problem))).toBe(true);

      const sameSequence = v3Row(1, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", first.hash, ts2);
      const result = verifyAuditChain([first, sameSequence]);
      expect(result.ok).toBe(false);
      expect(result.problems.some((p) => /duplicate sequence 1/.test(p.problem))).toBe(true);
    });
  });

  // Project attribution is part of the v4 hash. Changing it without
  // re-signing the chain changes the digest, and the verifier catches that.
  describe("v4 project attribution format", () => {
    const projectId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    function v4Row(
      seq: number, id: string, prevHash: string, project: string | null, timestamp = ts1
    ): AuditRow {
      const metadata = { version: seq };
      const entry = { ...base, metadata, workspace_id: "ws-1", project_id: project };
      return {
        id,
        timestamp,
        ...base,
        metadata,
        workspace_id: "ws-1",
        project_id: project,
        seq,
        hash_version: HASH_VERSION_PROJECT,
        prev_hash: prevHash,
        hash: auditHashV4(prevHash, timestamp, entry, id, seq)
      };
    }

    it("hashes the project and verifies an intact v4 chain", () => {
      const first = v4Row(1, "66666666-6666-6666-6666-666666666666", "", projectId);
      const second = v4Row(2, "77777777-7777-7777-7777-777777777777", first.hash, projectId, ts2);
      expect(verifyAuditChain([first, second]).ok).toBe(true);

      const entry = { ...base, metadata: { version: 1 }, workspace_id: "ws-1" };
      expect(auditHashV4("", ts1, { ...entry, project_id: projectId },
        "66666666-6666-6666-6666-666666666666", 1))
        .not.toBe(auditHashV4("", ts1, { ...entry, project_id: null },
          "66666666-6666-6666-6666-666666666666", 1));
      expect(auditHashFor(HASH_VERSION_PROJECT, "", ts1, { ...entry, project_id: projectId },
        "66666666-6666-6666-6666-666666666666", 1))
        .toBe(auditHashV4("", ts1, { ...entry, project_id: projectId },
          "66666666-6666-6666-6666-666666666666", 1));
    });

    it("rejects a v4 row whose stored project no longer matches the hash", () => {
      const first = v4Row(1, "66666666-6666-6666-6666-666666666666", "", projectId);
      const second = v4Row(2, "77777777-7777-7777-7777-777777777777", first.hash, projectId, ts2);
      const tampered = { ...second, project_id: "cccccccc-cccc-cccc-cccc-cccccccccccc" };
      const result = verifyAuditChain([first, tampered]);
      expect(result.ok).toBe(false);
      expect(result.problems.some((p) => /modified/.test(p.problem))).toBe(true);
    });
  });
});
