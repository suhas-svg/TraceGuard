import { afterAll, describe, expect, it } from "vitest";
import { appendAuditEvent } from "@traceguard/audit-chain";
import { pool } from "../src/db.js";
import { loadActivePolicy } from "../src/policy-bundle.js";

// §15: policy storage failures must fail closed. The signed-policy suite
// covers the "no active policy" state; this pins the "storage is down" half:
// the loader propagates the database error (the gateway's callers treat a
// throw as refusal — no 200, no upstream contact), and never invents an
// empty allow-everything policy.
describe("policy storage failure", () => {
  afterAll(async () => {
    await pool.end();
  });

  it("propagates a database failure instead of loading or allowing", async () => {
    const refusing = {
      query: async () => {
        throw new Error("connection refused");
      }
    };
    await expect(
      loadActivePolicy(refusing as never, "00000000-0000-0000-0000-000000000000")
    ).rejects.toThrow("connection refused");
  });

  // The audit write is the other half of the same rule: an append that cannot
  // reach the chain must throw, never return as if the event were recorded.
  it("refuses to append when the audit store is unavailable", async () => {
    const failing = {
      query: async () => {
        throw new Error("audit store unavailable");
      }
    };
    await expect(
      appendAuditEvent(failing as never, {
        actor_type: "system",
        action: "test.write",
        resource_type: "test",
        result: "success"
      })
    ).rejects.toThrow("audit store unavailable");
  });
});
