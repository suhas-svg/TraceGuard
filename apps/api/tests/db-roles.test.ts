import { Pool, type PoolClient } from "pg";
import { afterAll, describe, expect, it } from "vitest";
import { appendAuditEvent, verifyAuditChain, type AuditRow } from "@traceguard/audit-chain";

// §13.4 / NFR-008: the least-privilege boundary is a database privilege, and
// this file proves it at the database layer. Each probe runs as the role with
// SET ROLE inside a transaction that is always rolled back, so nothing the
// tests do survives. SET ROLE needs the connecting user to be a member of the
// target role (or a superuser) — true for the owner that runs migrations
// locally and in CI, which is also how the roles are meant to be exercised;
// a deployment connects with the role's own credentials instead.
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
afterAll(async () => {
  await pool.end();
});

const ROLES = ["api_runtime", "gateway_runtime", "policy_publisher", "retention_job", "audit_owner", "migration_owner"];

async function asRole<T>(role: string, fn: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(`SET LOCAL ROLE ${role}`);
    return await fn(client);
  } finally {
    await client.query("ROLLBACK").catch(() => undefined);
    client.release();
  }
}

// Runs one statement as the role and returns the SQLSTATE, or "ok" when it
// succeeded. Denied must be 42501 (insufficient_privilege); anything else -
// including "ok" for an update matching zero rows - means the grant exists.
// A failed statement aborts the surrounding transaction, so every probe is
// bracketed in a savepoint that is rolled back whatever the outcome.
async function attempt(client: PoolClient, db: () => Promise<unknown>): Promise<string> {
  await client.query("SAVEPOINT probe");
  try {
    await db();
    return "ok";
  } catch (err) {
    return (err as { code?: string }).code ?? "unknown";
  } finally {
    await client.query("ROLLBACK TO SAVEPOINT probe");
  }
}

const DENIED = "42501";

describe("least-privilege database roles", () => {
  it("creates all six roles, none privileged, and the audit owner can never log in", async () => {
    const res = await pool.query<{ rolname: string; rolcanlogin: boolean; rolsuper: boolean }>(
      "SELECT rolname, rolcanlogin, rolsuper FROM pg_roles WHERE rolname = ANY($1)",
      [ROLES]
    );
    expect(res.rows.map((r) => r.rolname).sort()).toEqual([...ROLES].sort());
    for (const row of res.rows) expect(row.rolsuper).toBe(false);
    // Roles are cluster-wide, and enabling a login is a deployment decision
    // (compose's db-roles service enables the four runtime logins), so this
    // asserts only what must always hold: the audit owner and the migration
    // identity cannot connect.
    for (const row of res.rows) {
      if (row.rolname === "audit_owner" || row.rolname === "migration_owner") {
        expect(row.rolcanlogin).toBe(false);
      }
    }
  });

  it("owns the audit table and append function from a non-login role", async () => {
    const table = await pool.query<{ owner: string }>(
      "SELECT pg_get_userbyid(relowner) AS owner FROM pg_class WHERE relname = 'audit_events'"
    );
    expect(table.rows[0]?.owner).toBe("audit_owner");
    // The function is SECURITY DEFINER: whoever owns it is the identity the
    // append body runs as, so a migration role owning it would silently
    // restore a superuser execution context for every append.
    const fn = await pool.query<{ owner: string }>(
      "SELECT pg_get_userbyid(proowner) AS owner FROM pg_proc WHERE proname = 'append_audit_event'"
    );
    expect(fn.rows[0]?.owner).toBe("audit_owner");
  });

  it("api_runtime cannot alter signed policy, trust state, audit, or approvals", async () => {
    await asRole("api_runtime", async (c) => {
      expect(await attempt(c, () => c.query("UPDATE policy_versions SET content_hash = 'x' WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("DELETE FROM policy_versions WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query(
        "INSERT INTO policy_signing_keys (workspace_id, key_id, public_key_pem) VALUES (gen_random_uuid(), 'k', 'p')"
      ))).toBe(DENIED);
      expect(await attempt(c, () => c.query("UPDATE active_config SET updated_at = now() WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query(
        "INSERT INTO audit_events (actor_type, action, resource_type, result) VALUES ('a','a','a','ok')"
      ))).toBe(DENIED);
      expect(await attempt(c, () => c.query("UPDATE audit_events SET result = 'x' WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("UPDATE approvals SET status = status WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("DELETE FROM approvals WHERE false"))).toBe(DENIED);
    });
  });

  it("api_runtime keeps reads and its draft/operational writes", async () => {
    await asRole("api_runtime", async (c) => {
      expect(await attempt(c, () => c.query("SELECT count(*) FROM policy_versions"))).toBe("ok");
      expect(await attempt(c, () => c.query("SELECT count(*) FROM approvals"))).toBe("ok");
      expect(await attempt(c, () => c.query("UPDATE policies SET name = name WHERE false"))).toBe("ok");
      expect(await attempt(c, () => c.query("UPDATE users SET role = role WHERE false"))).toBe("ok");
    });
  });

  it("gateway_runtime cannot publish or alter trusted configuration", async () => {
    await asRole("gateway_runtime", async (c) => {
      expect(await attempt(c, () => c.query("INSERT INTO policy_versions (workspace_id, version) VALUES (gen_random_uuid(), 1)"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("UPDATE policy_versions SET content_hash = 'x' WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("UPDATE active_config SET updated_at = now() WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("DELETE FROM policy_signing_keys WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query(
        "INSERT INTO audit_events (actor_type, action, resource_type, result) VALUES ('a','a','a','ok')"
      ))).toBe(DENIED);
    });
  });

  it("gateway_runtime can enforce: approvals, decisions, pins", async () => {
    await asRole("gateway_runtime", async (c) => {
      expect(await attempt(c, () => c.query("UPDATE approvals SET status = status WHERE false"))).toBe("ok");
      expect(await attempt(c, () => c.query("UPDATE server_tools SET quarantined = quarantined WHERE false"))).toBe("ok");
      expect(await attempt(c, () => c.query("SELECT count(*) FROM policy_versions"))).toBe("ok");
      expect(await attempt(c, () => c.query("SELECT count(*) FROM policy_signing_keys"))).toBe("ok");
    });
  });

  it("policy_publisher appends versions and trust, never rewrites them", async () => {
    await asRole("policy_publisher", async (c) => {
      expect(await attempt(c, () => c.query("UPDATE policy_versions SET content_hash = 'x' WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("DELETE FROM policy_versions WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("UPDATE audit_events SET result = 'x' WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("UPDATE active_config SET updated_at = active_config.updated_at WHERE false"))).toBe("ok");
      expect(await attempt(c, () => c.query("UPDATE policy_signing_keys SET retired_at = retired_at WHERE false"))).toBe("ok");
    });
  });

  it("retention_job deletes trace data and prunes terminal approvals", async () => {
    await asRole("retention_job", async (c) => {
      expect(await attempt(c, () => c.query("DELETE FROM spans WHERE false"))).toBe("ok");
      expect(await attempt(c, () => c.query("DELETE FROM approvals WHERE false"))).toBe("ok");
      // ...but holds nothing on the audit chain at all.
      expect(await attempt(c, () => c.query("SELECT count(*) FROM audit_events"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("DELETE FROM audit_events WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("DELETE FROM policy_versions WHERE false"))).toBe(DENIED);
    });
  });

  it("the append function refuses an append that does not link to the head", async () => {
    await asRole("api_runtime", async (c) => {
      const res = await c.query<{ appended: boolean }>(
        `SELECT append_audit_event(now(), 'test', 'db-roles', 'audit.probe', 'audit_event', '', 'success',
          '{}'::jsonb, 'not-the-head', repeat('f', 64)) AS appended`
      );
      expect(res.rows[0]?.appended).toBe(false);
    });
  });

  it("the append function is not callable by roles it was not granted to", async () => {
    await asRole("retention_job", async (c) => {
      expect(await attempt(c, () => c.query(
        `SELECT append_audit_event(now(), 'test', '', 'a', 'r', '', 'success', '{}'::jsonb, '', repeat('a', 64))`
      ))).toBe(DENIED);
    });
  });

  it("a runtime role appends through the function and the chain still verifies", async () => {
    await asRole("api_runtime", async (c) => {
      // The role cannot INSERT, but appendAuditEvent lands a linked event.
      await appendAuditEvent(c, {
        actor_type: "test",
        actor_id: "db-roles",
        action: "audit.probe",
        resource_type: "audit_event",
        result: "success",
        metadata: { file: "db-roles.test.ts" }
      });
      const head = await c.query<{ hash: string }>(
        "SELECT hash FROM audit_events ORDER BY timestamp DESC, id DESC LIMIT 1"
      );
      expect(head.rows[0]?.hash).toMatch(/^[0-9a-f]{64}$/);

      const rows = await c.query<AuditRow>("SELECT * FROM audit_events ORDER BY timestamp, id");
      const verification = verifyAuditChain(rows.rows);
      expect(verification.ok).toBe(true);
      expect(verification.checked).toBeGreaterThan(0);
      // The appended event is linked, not orphaned.
      const last = rows.rows[rows.rows.length - 1];
      expect(last.prev_hash).toBe(rows.rows[rows.rows.length - 2]?.hash ?? "");
    });
  });
});
