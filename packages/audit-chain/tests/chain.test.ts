import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalize } from "@traceguard/canonical-json";
import {
  auditHash, auditHashFor, auditHashV2, canonicalEventFields, stableStringify,
  verifyAuditChain, HASH_VERSION_CANONICAL, type AuditRow
} from "../src/index.js";

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
});
