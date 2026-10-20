import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";
import { generateSigningKey } from "@traceguard/policy-signing";
import { randomUUID } from "node:crypto";
import { assembleBundle, publish, trustKey, writeKeyPair } from "../src/index.js";

// Test-only defaults, mirroring the API suite. CI passes real values through
// the environment.
process.env.DATABASE_URL ??=
  process.env.TEST_DATABASE_URL ??
  "postgres://traceguard:traceguard_dev_only@localhost:5432/traceguard";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
let workspaceId = "";
let serverId = "";
const publisherKey = generateSigningKey();

beforeAll(async () => {
  const { rows } = await pool.query<{ tablename: string }>(
    "select tablename from pg_tables where schemaname = 'public'"
  );
  if (rows.length > 0) {
    const tables = rows.map((row) => `"${row.tablename}"`).join(", ");
    await pool.query(`TRUNCATE ${tables} RESTART IDENTITY CASCADE`);
  }
  const ws = await pool.query("INSERT INTO workspaces (name) VALUES ('default') RETURNING id");
  workspaceId = String(ws.rows[0].id);
});

afterAll(async () => {
  await pool.end();
});

describe("policy publisher", () => {
  it("writes a key pair once and refuses to overwrite a signing key", () => {
    const dir = mkdtempSync(join(tmpdir(), "tg-keys-"));
    try {
      const written = writeKeyPair(dir);
      expect(written.keyId).toMatch(/^[0-9a-f]{64}$/);
      expect(() => writeKeyPair(dir)).toThrow(/refusing to overwrite/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("trusts a key once, refuses a silent replacement, and audits rotation", async () => {
    const first = await trustKey(pool, { workspaceId, publicKeyPem: publisherKey.publicKeyPem });
    expect(first.alreadyTrusted).toBe(false);
    expect(first.retired).toEqual([]);

    const again = await trustKey(pool, { workspaceId, publicKeyPem: publisherKey.publicKeyPem });
    expect(again.alreadyTrusted).toBe(true);

    const stranger = generateSigningKey();
    await expect(
      trustKey(pool, { workspaceId, publicKeyPem: stranger.publicKeyPem })
    ).rejects.toThrow(/already trusts/);

    const rotated = await trustKey(pool, {
      workspaceId, publicKeyPem: stranger.publicKeyPem, rotate: true, trustedBy: "operator"
    });
    expect(rotated.retired).toEqual([publisherKey.keyId]);

    const audited = await pool.query(
      "SELECT action, result FROM audit_events WHERE action LIKE 'policy.signing_key.%' ORDER BY timestamp, id"
    );
    expect(audited.rows.map((r) => r.action)).toEqual([
      "policy.signing_key.trusted",
      "policy.signing_key.retired",
      "policy.signing_key.trusted"
    ]);
    expect(audited.rows.every((r) => r.result === "success")).toBe(true);

    // Rotate back to the original key: the retired row is re-activated, never
    // duplicated.
    const back = await trustKey(pool, {
      workspaceId, publicKeyPem: publisherKey.publicKeyPem, rotate: true
    });
    expect(back.retired).toEqual([stranger.keyId]);
    const rows = await pool.query(
      "SELECT count(*)::int AS n FROM policy_signing_keys WHERE workspace_id = $1 AND retired_at IS NULL",
      [workspaceId]
    );
    expect(rows.rows[0].n).toBe(1);
  });

  it("publishes drafts as an immutable version and advances the active pointer", async () => {
    const srv = await pool.query(
      `INSERT INTO mcp_servers (workspace_id, name, gateway_alias, base_url, auth_secret)
       VALUES ($1,'files','files','http://127.0.0.1:9/mcp','secret') RETURNING id`,
      [workspaceId]
    );
    serverId = String(srv.rows[0].id);
    const hash = "a".repeat(64);
    await pool.query(
      `INSERT INTO server_tools (server_id, tool_name, description, input_schema, definition, definition_hash)
       VALUES ($1,'read_file','read a file','{}'::jsonb,'{}'::jsonb,$2)`,
      [serverId, hash]
    );
    await pool.query(
      `INSERT INTO policies (workspace_id, name, server_id, tool_name, effect)
       VALUES ($1,'allow-read',$2,'read_file','allow')`,
      [workspaceId, serverId]
    );

    const first = await publish(pool, {
      workspaceId, privateKeyPem: publisherKey.privateKeyPem, publishedBy: "operator"
    });
    expect(first.published).toBe(true);
    expect(first.version).toBe(1);
    expect(first.bundle.rules).toHaveLength(1);
    expect(first.bundle.servers).toEqual([
      { server_id: serverId, alias: "files", base_url: "http://127.0.0.1:9/mcp", auth_mode: "gateway_secret" }
    ]);
    expect(first.bundle.pins).toEqual([{ server_id: serverId, tool_name: "read_file", definition_hash: hash }]);
    expect(first.bundle.previous_version_hash).toBeNull();

    const active = await pool.query(
      `SELECT pv.version, pv.content_hash, pv.published_by FROM active_config ac
         JOIN policy_versions pv ON pv.id = ac.policy_version_id WHERE ac.workspace_id = $1`,
      [workspaceId]
    );
    expect(Number(active.rows[0].version)).toBe(1);
    expect(active.rows[0].content_hash).toBe(first.contentHash);
    expect(active.rows[0].published_by).toBe("operator");

    // A second publish after a draft change is a new edition that cites the
    // first one's hash: editing history is impossible, chaining is explicit.
    await pool.query(
      `INSERT INTO policies (workspace_id, name, server_id, tool_name, effect)
       VALUES ($1,'deny-other',$2,'other','deny')`,
      [workspaceId, serverId]
    );
    const second = await publish(pool, {
      workspaceId, privateKeyPem: publisherKey.privateKeyPem, publishedBy: "operator"
    });
    expect(second.version).toBe(2);
    expect(second.bundle.previous_version_hash).toBe(first.contentHash);

    const audited = await pool.query(
      "SELECT metadata FROM audit_events WHERE action = 'policy.published' ORDER BY timestamp, id"
    );
    expect(audited.rows).toHaveLength(2);
    expect(audited.rows[1].metadata).toMatchObject({
      version: 2, content_hash: second.contentHash, pins: 1, servers: 1, rules: 2
    });
    expect(audited.rows[0].metadata.pins).toBe(1);
  });

  it("refuses a draft whose rule targets a server outside the manifest", async () => {
    // The reachable case: the FK allows any existing server row, including
    // one that belongs to another workspace, but that server is not in this
    // workspace's manifest and the rule could never fire.
    const otherWs = await pool.query(
      "INSERT INTO workspaces (name) VALUES ($1) RETURNING id", [`other-${randomUUID().slice(0, 8)}`]
    );
    const foreign = await pool.query(
      `INSERT INTO mcp_servers (workspace_id, name, gateway_alias, base_url)
       VALUES ($1,'foreign','foreign','http://127.0.0.1:9/mcp') RETURNING id`,
      [String(otherWs.rows[0].id)]
    );
    await pool.query(
      `INSERT INTO policies (workspace_id, name, server_id, effect)
       VALUES ($1,'ghost-rule',$2,'deny')`,
      [workspaceId, String(foreign.rows[0].id)]
    );
    await expect(
      publish(pool, { workspaceId, privateKeyPem: publisherKey.privateKeyPem })
    ).rejects.toThrow(/not in the server manifest/);
    await pool.query("DELETE FROM policies WHERE name = 'ghost-rule'");
  });

  it("refuses to publish with a key the workspace does not trust", async () => {
    const stranger = generateSigningKey();
    await expect(
      publish(pool, { workspaceId, privateKeyPem: stranger.privateKeyPem })
    ).rejects.toThrow(/not trusted/);
  });

  it("excludes quarantined tools, and a dry run changes nothing", async () => {
    await pool.query("UPDATE server_tools SET quarantined = true WHERE server_id = $1", [serverId]);
    const dry = await publish(pool, {
      workspaceId, privateKeyPem: publisherKey.privateKeyPem, dryRun: true
    });
    expect(dry.published).toBe(false);
    expect(dry.bundle.pins).toHaveLength(0);
    expect(dry.version).toBe(3);

    const stillTwo = await pool.query(
      "SELECT count(*)::int AS n FROM policy_versions WHERE workspace_id = $1", [workspaceId]
    );
    expect(stillTwo.rows[0].n).toBe(2);

    const client = await pool.connect();
    try {
      const assembled = await assembleBundle(client, workspaceId);
      expect(assembled.problems).toEqual([]);
      expect(assembled.counts).toEqual({ rules: 2, servers: 1, pins: 0 });
    } finally {
      client.release();
    }
  });

  // FR-010 / §16.3 T9: path_within is enforceable only inside an executor that
  // attests confinement in its pinned definition. The publisher is the last
  // gate before signing, so it refuses what the gateway would have to
  // second-guess.
  it("refuses path_within drafts the executor cannot enforce", async () => {
    await pool.query(
      "UPDATE server_tools SET quarantined = false, quarantine_reason = NULL WHERE server_id = $1",
      [serverId]
    );
    const insertRule = (name: string, p: string) => pool.query(
      `INSERT INTO policies (workspace_id, name, server_id, tool_name, effect, conditions)
       VALUES ($1,$2,$3,'read_file','allow',$4::jsonb)`,
      [workspaceId, name, serverId, JSON.stringify({ arguments: { path: { path_within: p } } })]
    );

    // Pinned definition with no attestation at all.
    await insertRule("path-no-meta", "/data");
    await expect(publish(pool, { workspaceId, privateKeyPem: publisherKey.privateKeyPem }))
      .rejects.toThrow(/path-confinement attestation/);
    await pool.query("DELETE FROM policies WHERE name = 'path-no-meta'");

    // Attested executor, but the constraint sits outside the attested root.
    await pool.query(
      "UPDATE server_tools SET definition = $2::jsonb WHERE server_id = $1 AND tool_name = 'read_file'",
      [serverId, JSON.stringify({
        _meta: { "io.traceguard/path-confinement": { root: "/data", enforcement: "executor" } }
      })]
    );
    await insertRule("path-outside", "/etc");
    await expect(publish(pool, { workspaceId, privateKeyPem: publisherKey.privateKeyPem }))
      .rejects.toThrow(/outside the executor's attested root/);
    await pool.query("DELETE FROM policies WHERE name = 'path-outside'");

    // Inside the attested root: assembly passes and the dry run stays
    // unpublished (nothing changes until a real publish).
    await insertRule("path-ok", "/data/reports");
    const dry = await publish(pool, { workspaceId, privateKeyPem: publisherKey.privateKeyPem, dryRun: true });
    expect(dry.published).toBe(false);
    expect(dry.bundle.rules.some((r) => r.name === "path-ok")).toBe(true);
    await pool.query("DELETE FROM policies WHERE name = 'path-ok'");
  });
});
