import { afterAll, describe, expect, it } from "vitest";
import { buildApp } from "../src/index.js";
import { pool } from "../src/db.js";

// The retention sweep changed shape when the least-privilege roles landed:
// its deletes now run on a separate connection so a deployment can point the
// sweep at the retention_job credentials (DATABASE_URL_RETENTION). This
// drives the real routes end to end - rules in, sweep out, counts and a
// successful run row - which is also the only test that covers the
// restructured transaction.
describe("retention sweep", () => {
  const app = buildApp();
  const key = { authorization: "Bearer test_key" };

  afterAll(async () => {
    await app.close();
    await pool.end();
  });

  it("runs every rule type and records the run", async () => {
    for (const target of ["runs", "approvals", "webhook_deliveries"]) {
      const res = await app.inject({
        method: "POST", url: "/v1/retention/rules", headers: key,
        payload: { name: `sweep-${target}`, target, older_than_days: 1 }
      });
      expect(res.statusCode).toBe(201);
    }

    const run = await app.inject({ method: "POST", url: "/v1/retention/run", headers: key });
    expect(run.statusCode).toBe(200);
    const body = run.json() as { run_id: string; deleted: Record<string, number> };
    expect(Object.keys(body.deleted).sort())
      .toEqual(["sweep-approvals", "sweep-runs", "sweep-webhook_deliveries"]);

    const row = await pool.query<{ status: string }>(
      "SELECT status FROM retention_runs WHERE id = $1", [body.run_id]
    );
    expect(row.rows[0]?.status).toBe("success");
  });
});
