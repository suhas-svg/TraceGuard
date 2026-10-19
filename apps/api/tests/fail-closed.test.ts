import { afterAll, describe, expect, it } from "vitest";
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
});
