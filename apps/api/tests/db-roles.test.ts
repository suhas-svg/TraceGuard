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

const ROLES = ["api_runtime", "gateway_runtime", "policy_publisher", "retention_job", "approval_owner", "policy_owner", "audit_owner", "identity_owner", "migration_owner"];

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
  it("creates all nine roles, none privileged, and the owner roles can never log in", async () => {
    const res = await pool.query<{ rolname: string; rolcanlogin: boolean; rolsuper: boolean }>(
      "SELECT rolname, rolcanlogin, rolsuper FROM pg_roles WHERE rolname = ANY($1)",
      [ROLES]
    );
    expect(res.rows.map((r) => r.rolname).sort()).toEqual([...ROLES].sort());
    for (const row of res.rows) expect(row.rolsuper).toBe(false);
    // Roles are cluster-wide, and enabling a login is a deployment decision
    // (compose's db-roles service enables the four runtime logins), so this
    // asserts only what must always hold: the owner identities cannot connect.
    for (const row of res.rows) {
      if (row.rolname === "audit_owner" || row.rolname === "migration_owner" ||
          row.rolname === "approval_owner" || row.rolname === "policy_owner" ||
          row.rolname === "identity_owner") {
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

  it("owns the identity procedures from a non-login role", async () => {
    const fns = await pool.query<{ proname: string; owner: string }>(
      `SELECT proname, pg_get_userbyid(proowner) AS owner
         FROM pg_proc
        WHERE proname LIKE 'identity_%'
        ORDER BY proname`
    );
    expect(fns.rows.map((r) => r.proname)).toEqual([
      "identity_bootstrap", "identity_create_key", "identity_create_login_key",
      "identity_create_user", "identity_grant_membership", "identity_revoke_key",
      "identity_revoke_key_by_hash", "identity_revoke_membership", "identity_touch_key"
    ]);
    for (const fn of fns.rows) expect(fn.owner).toBe("identity_owner");
  });

  it("api_runtime cannot mint identity rows but can execute the narrow procedures", async () => {
    await asRole("api_runtime", async (c) => {
      expect(await attempt(c, () => c.query(
        "INSERT INTO users (email, password_hash, role) VALUES ('nfr008@example.invalid', 'h', 'admin')"
      ))).toBe(DENIED);
      expect(await attempt(c, () => c.query("UPDATE users SET role = role WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("DELETE FROM users WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query(
        "INSERT INTO api_keys (user_id, name, key_hash) VALUES (gen_random_uuid(), 'k', 'h')"
      ))).toBe(DENIED);
      expect(await attempt(c, () => c.query("UPDATE api_keys SET scopes = scopes WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("DELETE FROM api_keys WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query(
        "INSERT INTO memberships (user_id, workspace_id) VALUES (gen_random_uuid(), gen_random_uuid())"
      ))).toBe(DENIED);
      expect(await attempt(c, () => c.query("DELETE FROM memberships WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query(
        "SELECT identity_bootstrap('probe@example.invalid', 'h')"
      ))).toBe("ok");
    });
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
      expect(await attempt(c, () => c.query(
        "SELECT policy_activate_version(NULL, NULL)"
      ))).toBe(DENIED);
    });
  });

  it("api_runtime keeps reads and its draft/operational writes", async () => {
    await asRole("api_runtime", async (c) => {
      expect(await attempt(c, () => c.query("SELECT count(*) FROM policy_versions"))).toBe("ok");
      expect(await attempt(c, () => c.query("SELECT count(*) FROM approvals"))).toBe("ok");
      expect(await attempt(c, () => c.query("UPDATE policies SET name = name WHERE false"))).toBe("ok");
      expect(await attempt(c, () => c.query("UPDATE mcp_servers SET name = name WHERE false"))).toBe("ok");
      expect(await attempt(c, () => c.query("UPDATE server_tools SET quarantined = quarantined WHERE false"))).toBe("ok");
    });
  });

  it("stamped server configuration is immutable to the API but can still be disabled", async () => {
    const ws = await pool.query<{ id: string }>(
      "INSERT INTO workspaces (name) VALUES ('signed-config-probe') RETURNING id"
    );
    const project = await pool.query<{ id: string }>(
      "INSERT INTO projects (workspace_id, name) VALUES ($1, 'probe') RETURNING id",
      [ws.rows[0].id]
    );
    const server = await pool.query<{ id: string }>(
      `INSERT INTO mcp_servers
         (workspace_id, project_id, name, base_url, gateway_alias, secret_ref, signed_bundle_version)
       VALUES ($1, $2, 'signed-probe', 'https://upstream.invalid/mcp', 'signed-probe',
               'env:TEST_UPSTREAM_TOKEN', 1)
       RETURNING id`,
      [ws.rows[0].id, project.rows[0].id]
    );
    const id = server.rows[0].id;

    await asRole("api_runtime", async (c) => {
      // The signed fields are frozen once the publisher stamps the row.
      expect(await attempt(c, () => c.query(
        "UPDATE mcp_servers SET base_url = 'https://evil.invalid/mcp' WHERE id = $1", [id]
      ))).toBe("P0001");
      expect(await attempt(c, () => c.query(
        "UPDATE mcp_servers SET gateway_alias = 'evil' WHERE id = $1", [id]
      ))).toBe("P0001");
      expect(await attempt(c, () => c.query(
        "UPDATE mcp_servers SET secret_ref = 'env:OTHER_TOKEN' WHERE id = $1", [id]
      ))).toBe("P0001");
      expect(await attempt(c, () => c.query(
        "UPDATE mcp_servers SET signed_bundle_version = 2 WHERE id = $1", [id]
      ))).toBe("P0001");
      // Disabling is the one operational mutation the API may still perform.
      await c.query("UPDATE mcp_servers SET disabled_at = now() WHERE id = $1", [id]);
      expect(await attempt(c, () => c.query(
        "UPDATE mcp_servers SET disabled_at = NULL WHERE id = $1", [id]
      ))).toBe("P0001");
      // Only the publisher's SECURITY DEFINER procedure may stamp versions.
      expect(await attempt(c, () => c.query(
        "SELECT stamp_signed_servers($1, 1)", [project.rows[0].id]
      ))).toBe(DENIED);
    });

    const fn = await pool.query<{ owner: string; secdef: boolean }>(
      `SELECT pg_get_userbyid(proowner) AS owner, prosecdef AS secdef
         FROM pg_proc WHERE proname = 'stamp_signed_servers'`
    );
    expect(fn.rows[0]).toMatchObject({ owner: "policy_owner", secdef: true });
  });

  it("gateway_runtime cannot publish or alter trusted configuration", async () => {
    await asRole("gateway_runtime", async (c) => {
      expect(await attempt(c, () => c.query("INSERT INTO policy_versions (workspace_id, version) VALUES (gen_random_uuid(), 1)"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("UPDATE policy_versions SET content_hash = 'x' WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("UPDATE active_config SET updated_at = now() WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("UPDATE mcp_servers SET name = name WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("UPDATE server_tools SET quarantined = quarantined WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("UPDATE policies SET name = name WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("DELETE FROM policy_signing_keys WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query(
        "INSERT INTO audit_events (actor_type, action, resource_type, result) VALUES ('a','a','a','ok')"
      ))).toBe(DENIED);
    });
  });

  it("gateway_runtime enforces through narrow approval procedures, not table DML", async () => {
    await asRole("gateway_runtime", async (c) => {
      expect(await attempt(c, () => c.query("UPDATE approvals SET status = status WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("DELETE FROM approvals WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query(
        "INSERT INTO approvals (request_id, workspace_id, caller, server_id, tool_name, args_hash, args, requested_by, expires_at) VALUES ('x', gen_random_uuid(), 'c', gen_random_uuid(), 't', 'h', '{}', 'c', now())"
      ))).toBe(DENIED);
      // The transition procedure is executable, but a CAS miss returns zero
      // rows rather than a NULL composite row.
      const miss = await c.query(
        "SELECT * FROM approval_transition('00000000-0000-0000-0000-000000000000', 'expire_pending')"
      );
      expect(miss.rows).toEqual([]);
      expect(await attempt(c, () => c.query("SELECT count(*) FROM policy_versions"))).toBe("ok");
      expect(await attempt(c, () => c.query("SELECT count(*) FROM policy_signing_keys"))).toBe("ok");
    });
  });

  it("approval transitions are owned by the non-login approval_owner", async () => {
    const res = await pool.query<{ proname: string; owner: string; secdef: boolean }>(
      `SELECT proname, pg_get_userbyid(proowner) AS owner, prosecdef AS secdef
         FROM pg_proc
        WHERE proname IN ('approval_request', 'approval_decide', 'approval_transition')
        ORDER BY proname`
    );
    expect(res.rows.map((r) => r.proname)).toEqual(["approval_decide", "approval_request", "approval_transition"]);
    for (const row of res.rows) {
      expect(row.owner).toBe("approval_owner");
      expect(row.secdef).toBe(true);
    }
  });

  it("api_runtime cannot execute approval procedures", async () => {
    await asRole("api_runtime", async (c) => {
      expect(await attempt(c, () => c.query(
        "SELECT * FROM approval_transition('00000000-0000-0000-0000-000000000000', 'expire_pending')"
      ))).toBe(DENIED);
    });
  });

  it("policy trust and activation procedures are owned by non-login policy_owner", async () => {
    const res = await pool.query<{ proname: string; owner: string; secdef: boolean }>(
      `SELECT proname, pg_get_userbyid(proowner) AS owner, prosecdef AS secdef
         FROM pg_proc
        WHERE proname IN ('policy_trust_key', 'policy_activate_version')
        ORDER BY proname`
    );
    expect(res.rows.map((r) => r.proname)).toEqual(["policy_activate_version", "policy_trust_key"]);
    for (const row of res.rows) {
      expect(row.owner).toBe("policy_owner");
      expect(row.secdef).toBe(true);
    }
  });

  it("serializes on active_config through the definer helper without write access", async () => {
    // §9.2's consume-time row lock needs FOR SHARE, which PostgreSQL checks
    // against UPDATE privilege — a privilege gateway_runtime deliberately
    // lacks. Migration 036's SECURITY DEFINER helper is owned by policy_owner,
    // and the row lock still lands on the calling transaction, so serialization
    // holds while the runtime stays read-only.
    const fn = await pool.query<{ owner: string }>(
      "SELECT pg_get_userbyid(proowner) AS owner FROM pg_proc WHERE proname = 'lock_active_config_share'"
    );
    expect(fn.rows[0]?.owner).toBe("policy_owner");
    await asRole("gateway_runtime", async (c) => {
      expect(await attempt(c, () => c.query(
        "SELECT lock_active_config_share('00000000-0000-0000-0000-000000000000')"
      ))).toBe("ok");
      expect(await attempt(c, () => c.query("UPDATE active_config SET updated_at = now() WHERE false"))).toBe(DENIED);
    });
  });

  it("policy_publisher appends versions and trust through narrow procedures", async () => {
    await asRole("policy_publisher", async (c) => {
      expect(await attempt(c, () => c.query("UPDATE policy_versions SET content_hash = 'x' WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("DELETE FROM policy_versions WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("UPDATE audit_events SET result = 'x' WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("UPDATE active_config SET updated_at = active_config.updated_at WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("UPDATE policy_signing_keys SET retired_at = retired_at WHERE false"))).toBe(DENIED);
      // Execute is granted; the procedures validate their inputs before any
      // table write, so these calls prove the grant without leaving rows.
      // P0001 is the procedures' own raise_exception, not a privilege error.
      expect(await attempt(c, () => c.query(
        "SELECT * FROM policy_trust_key(NULL, NULL, NULL, false)"
      ))).toBe("P0001");
      expect(await attempt(c, () => c.query(
        "SELECT policy_activate_version(NULL, NULL)"
      ))).toBe("P0001");
    });
  });

  it("retention_job deletes trace data but never approval history", async () => {
    await asRole("retention_job", async (c) => {
      expect(await attempt(c, () => c.query("DELETE FROM spans WHERE false"))).toBe("ok");
      expect(await attempt(c, () => c.query("DELETE FROM approvals WHERE false"))).toBe(DENIED);
      // ...and may read the chain only to produce/check an operator
      // checkpoint; it still cannot delete or rewrite the log itself.
      expect(await attempt(c, () => c.query("SELECT count(*) FROM audit_events"))).toBe("ok");
      expect(await attempt(c, () => c.query("DELETE FROM audit_events WHERE false"))).toBe(DENIED);
      expect(await attempt(c, () => c.query("DELETE FROM policy_versions WHERE false"))).toBe(DENIED);
    });
  });

  it("prune refuses a blank external receipt even for the retention role", async () => {
    await asRole("retention_job", async (c) => {
      await expect(c.query(
        "SELECT prune_audit_events(gen_random_uuid(), '   ')"
      )).rejects.toThrow(/non-empty external receipt/);
    });
  });

  it("the append function refuses an append that does not link to the head", async () => {
    await asRole("api_runtime", async (c) => {
      const res = await c.query<{ appended: boolean }>(
        `SELECT append_audit_event(gen_random_uuid(), now(), 'test', 'db-roles', 'audit.probe',
          'audit_event', '', 'success', '{}'::jsonb, 'not-the-head', repeat('f', 64),
          NULL, 999) AS appended`
      );
      expect(res.rows[0]?.appended).toBe(false);
    });
  });

  it("the append function is not callable by roles it was not granted to", async () => {
    await asRole("migration_owner", async (c) => {
      // Only the four append roles hold EXECUTE. The migration role owns the
      // schema but has no runtime grant on the append function.
      expect(await attempt(c, () => c.query(
        `SELECT append_audit_event(gen_random_uuid(), now(), 'test', '', 'a', 'r', '', 'success',
          '{}'::jsonb, '', repeat('a', 64), NULL, 1)`
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
