import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Pool, type PoolClient } from "pg";
import { appendAuditEvent } from "@traceguard/audit-chain";
import { contentHashOf, generateSigningKey, keyIdFor, signPayload } from "@traceguard/policy-signing";
import {
  BUNDLE_VERSION,
  PROTOCOL_PROFILE,
  policyBundleSchema,
  type PolicyBundle
} from "@traceguard/schemas";

// The operator-side trust boundary (§13.3). This tool is the only thing that
// signs a policy bundle, and it runs on the operator's host holding the
// private key — never inside the API or gateway containers. The gateway
// verifies whatever this tool signs and enforces nothing else.
//
// Everything it publishes is assembled from the untrusted draft surfaces
// (the versioned `policies` table, server registrations, reviewed tool
// pins). Signing is what turns a draft into trusted content.

export interface PublishCounts {
  rules: number;
  servers: number;
  pins: number;
}

export interface Assembly {
  bundle: PolicyBundle;
  counts: PublishCounts;
  // Empty when the draft is publishable. A non-empty list is what `publish`
  // refuses on, with every problem named.
  problems: string[];
}

export async function resolveWorkspaceId(db: PoolClient | Pool, ref: string | undefined): Promise<string> {
  const wanted = ref ?? "default";
  const res = await db.query(
    "SELECT id FROM workspaces WHERE name = $1 OR id::text = $1", [wanted]
  );
  if (!res.rows[0]) {
    throw new Error(`workspace "${wanted}" not found; create it through the control API first`);
  }
  return String(res.rows[0].id);
}

// Builds the candidate bundle from current drafts. It never signs anything;
// publish() validates the result and refuses on problems.
export async function assembleBundle(client: PoolClient, workspaceId: string): Promise<Assembly> {
  const versionRow = await client.query(
    "SELECT coalesce(max(version), 0) AS v FROM policy_versions WHERE workspace_id = $1",
    [workspaceId]
  );
  const nextVersion = Number(versionRow.rows[0].v) + 1;
  const activeRow = await client.query(
    `SELECT pv.content_hash FROM active_config ac
       JOIN policy_versions pv ON pv.id = ac.policy_version_id
      WHERE ac.workspace_id = $1`,
    [workspaceId]
  );
  const previous = (activeRow.rows[0]?.content_hash as string | undefined) ?? null;

  const servers = await client.query(
    "SELECT id, gateway_alias, base_url, auth_secret FROM mcp_servers WHERE workspace_id = $1 ORDER BY gateway_alias",
    [workspaceId]
  );
  const pins = await client.query(
    `SELECT t.server_id, t.tool_name, t.definition_hash
       FROM server_tools t JOIN mcp_servers s ON s.id = t.server_id
      WHERE s.workspace_id = $1 AND t.quarantined = false AND t.quarantine_reason IS NULL
      ORDER BY t.server_id, t.tool_name`,
    [workspaceId]
  );
  const rules = await client.query(
    `SELECT id, name, enabled, priority, agent_id, server_id, tool_name, effect, conditions
       FROM policies WHERE workspace_id = $1 AND superseded_by IS NULL
      ORDER BY name, id`,
    [workspaceId]
  );

  const counts: PublishCounts = {
    rules: rules.rows.length,
    servers: servers.rows.length,
    pins: pins.rows.length
  };
  const candidate = {
    bundle_version: BUNDLE_VERSION,
    protocol_profile: PROTOCOL_PROFILE,
    workspace_id: workspaceId,
    version: nextVersion,
    previous_version_hash: previous,
    rules: rules.rows.map((r) => ({
      id: r.id,
      name: r.name,
      enabled: r.enabled,
      priority: r.priority,
      agent_id: r.agent_id ?? null,
      server_id: r.server_id ?? null,
      tool_name: r.tool_name ?? null,
      effect: r.effect,
      conditions: r.conditions ?? {}
    })),
    servers: servers.rows.map((s) => ({
      server_id: s.id,
      alias: s.gateway_alias,
      base_url: s.base_url,
      // The secret value never enters the bundle, only how it is used.
      auth_mode: s.auth_secret ? "gateway_secret" : "none"
    })),
    pins: pins.rows.map((p) => ({
      server_id: p.server_id,
      tool_name: p.tool_name,
      definition_hash: p.definition_hash
    }))
  };

  const problems: string[] = [];
  // A rule scoped to a server the manifest does not carry could never fire;
  // publishing it would ship a policy that reads one way and acts another.
  const serverIds = new Set(servers.rows.map((s) => String(s.id)));
  for (const rule of candidate.rules) {
    if (rule.server_id && !serverIds.has(String(rule.server_id))) {
      problems.push(`rule "${rule.name}" targets a server that is not in the server manifest`);
    }
  }
  const parsed = policyBundleSchema.safeParse(candidate);
  if (parsed.success) {
    return { bundle: parsed.data, counts, problems };
  }
  for (const issue of parsed.error.issues) {
    problems.push(`${issue.path.join(".") || "(bundle)"}: ${issue.message}`);
  }
  // The candidate is returned for inspection only when it failed to parse;
  // publish() refuses on any problem before touching it.
  return { bundle: candidate as unknown as PolicyBundle, counts, problems };
}

export interface TrustOptions {
  workspaceId: string;
  publicKeyPem: string;
  rotate?: boolean;
  trustedBy?: string;
}

export interface TrustResult {
  keyId: string;
  retired: string[];
  alreadyTrusted: boolean;
}

// Trust store for verification keys. Keys are insert-or-retire: a runtime
// write cannot swap the pinned public key, only add one, and only retirement
// marks a key unusable (migration 022 enforces this in the database).
export async function trustKey(pool: Pool, opts: TrustOptions): Promise<TrustResult> {
  const keyId = keyIdFor(opts.publicKeyPem);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    // Serialized per workspace: without the lock, two concurrent trusts on a
    // fresh workspace can both see "no live key" and both insert, leaving two
    // live keys the gateway would equally trust.
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`policy-keys:${opts.workspaceId}`]);
    const existing = await client.query(
      "SELECT id, key_id, retired_at FROM policy_signing_keys WHERE workspace_id = $1", [opts.workspaceId]
    );
    const forThisKey = existing.rows.find((r) => r.key_id === keyId);
    const live = existing.rows.filter((r) => !r.retired_at);
    if (forThisKey && !forThisKey.retired_at) {
      await client.query("COMMIT");
      return { keyId, retired: [], alreadyTrusted: true };
    }
    if (live.length > 0 && !opts.rotate) {
      throw new Error(
        "this workspace already trusts a different signing key; pass --rotate to replace it"
      );
    }
    const retired: string[] = [];
    for (const row of live) {
      await client.query("UPDATE policy_signing_keys SET retired_at = now() WHERE id = $1", [row.id]);
      await appendAuditEvent(client, {
        actor_type: "admin", actor_id: opts.trustedBy ?? "operator",
        action: "policy.signing_key.retired", resource_type: "policy_signing_key",
        resource_id: String(row.key_id), result: "success"
      });
      retired.push(String(row.key_id));
    }
    if (forThisKey) {
      // A previously retired key coming back: re-activate the same row, never
      // a second row for the same key material (the unique index would refuse
      // it, and two rows would make retirement ambiguous).
      await client.query(
        "UPDATE policy_signing_keys SET retired_at = NULL WHERE id = $1", [forThisKey.id]
      );
    } else {
      await client.query(
        "INSERT INTO policy_signing_keys (workspace_id, key_id, public_key_pem) VALUES ($1,$2,$3)",
        [opts.workspaceId, keyId, opts.publicKeyPem.trim()]
      );
    }
    await appendAuditEvent(client, {
      actor_type: "admin", actor_id: opts.trustedBy ?? "operator",
      action: "policy.signing_key.trusted", resource_type: "policy_signing_key",
      resource_id: keyId, result: "success",
      metadata: forThisKey ? { reactivated: true } : {}
    });
    await client.query("COMMIT");
    return { keyId, retired, alreadyTrusted: false };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}

export interface PublishOptions {
  workspaceId: string;
  privateKeyPem: string;
  publishedBy?: string;
  dryRun?: boolean;
}

export interface PublishResult {
  published: boolean;
  version: number;
  contentHash: string;
  keyId: string;
  counts: PublishCounts;
  bundle: PolicyBundle;
}

export async function publish(pool: Pool, opts: PublishOptions): Promise<PublishResult> {
  const client = await pool.connect();
  try {
    const { bundle, counts, problems } = await assembleBundle(client, opts.workspaceId);
    if (problems.length > 0) {
      throw new Error(`refusing to publish:\n  - ${problems.join("\n  - ")}`);
    }
    const { signature, keyId } = signPayload(bundle, opts.privateKeyPem);
    const contentHash = contentHashOf(bundle);

    // The key must already be trusted for this workspace and not retired;
    // publish never bootstraps trust implicitly.
    const keyRow = await client.query(
      "SELECT id, retired_at FROM policy_signing_keys WHERE workspace_id = $1 AND key_id = $2",
      [opts.workspaceId, keyId]
    );
    if (!keyRow.rows[0]) {
      throw new Error(
        `signing key ${keyId.slice(0, 12)}... is not trusted for this workspace; run trust first`
      );
    }
    if (keyRow.rows[0].retired_at) {
      throw new Error("the signing key is retired; trust a new key before publishing");
    }

    if (opts.dryRun) {
      return { published: false, version: bundle.version, contentHash, keyId, counts, bundle };
    }

    await client.query("BEGIN");
    let inserted: { rows: Record<string, unknown>[] };
    try {
      inserted = await client.query(
        `INSERT INTO policy_versions
           (workspace_id, version, bundle, content_hash, signature, signing_key_id,
            previous_version_hash, published_by)
         VALUES ($1,$2,$3::jsonb,$4,$5,$6,$7,$8)
         RETURNING id`,
        [opts.workspaceId, bundle.version, JSON.stringify(bundle), contentHash, signature,
         keyRow.rows[0].id, bundle.previous_version_hash, opts.publishedBy ?? "operator"]
      );
    } catch (err) {
      if ((err as { code?: string }).code === "23505") {
        throw new Error(
          `another publish won the race for version ${bundle.version}; re-run to pick up the new history`
        );
      }
      throw err;
    }
    await client.query(
      `INSERT INTO active_config (workspace_id, policy_version_id, updated_at)
       VALUES ($1,$2,now())
       ON CONFLICT (workspace_id) DO UPDATE
         SET policy_version_id = EXCLUDED.policy_version_id, updated_at = now()`,
      [opts.workspaceId, inserted.rows[0].id]
    );
    await appendAuditEvent(client, {
      actor_type: "admin", actor_id: opts.publishedBy ?? "operator",
      action: "policy.published", resource_type: "policy_version",
      resource_id: String(inserted.rows[0].id), result: "success",
      metadata: {
        version: bundle.version,
        content_hash: contentHash,
        key_id: keyId,
        rules: counts.rules,
        servers: counts.servers,
        pins: counts.pins
      }
    });
    await client.query("COMMIT");
    return { published: true, version: bundle.version, contentHash, keyId, counts, bundle };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}

export interface KeyPairFiles {
  privateKeyPath: string;
  publicKeyPath: string;
  keyId: string;
}

// Writes a fresh Ed25519 pair. Refuses to overwrite an existing private key:
// silently replacing a signing key would orphan every bundle it signed.
export function writeKeyPair(outDir: string): KeyPairFiles {
  const keys = generateSigningKey();
  mkdirSync(outDir, { recursive: true });
  const privateKeyPath = join(outDir, "signing-key.pem");
  const publicKeyPath = join(outDir, "signing-key.pub.pem");
  if (existsSync(privateKeyPath)) {
    throw new Error(`${privateKeyPath} already exists; refusing to overwrite a signing key`);
  }
  writeFileSync(privateKeyPath, keys.privateKeyPem, { mode: 0o600 });
  writeFileSync(publicKeyPath, keys.publicKeyPem);
  try {
    chmodSync(privateKeyPath, 0o600);
  } catch {
    // Windows ignores POSIX modes; the operator's host controls access.
  }
  return { privateKeyPath, publicKeyPath, keyId: keys.keyId };
}

// ---- CLI -----------------------------------------------------------------

function parseFlags(argv: string[]): { command: string; flags: Record<string, string | boolean> } {
  const [command, ...rest] = argv;
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (!arg.startsWith("--")) continue;
    const name = arg.slice(2);
    const next = rest[i + 1];
    if (next !== undefined && !next.startsWith("--")) {
      flags[name] = next;
      i++;
    } else {
      flags[name] = true;
    }
  }
  return { command: command ?? "help", flags };
}

function usage(): void {
  process.stdout.write(
    [
      "policy-publisher - signs and publishes immutable policy bundles",
      "",
      "Commands:",
      "  keygen  --out <dir>                Generate an Ed25519 signing key pair (default ./policy-keys)",
      "  trust   --workspace <id|name>      Trust a public key for a workspace [--public-key <file>] [--rotate]",
      "  publish --workspace <id|name>      Sign and publish the current drafts as the active policy",
      "          --key <file>               Private key PEM (or POLICY_SIGNING_KEY_FILE)",
      "          [--dry-run] [--by <name>]",
      "  status  --workspace <id|name>      Show the active version, its key, and what a publish would contain",
      "",
      "Environment: DATABASE_URL (or --database-url). The private key never belongs",
      "in the API or gateway containers; run this tool on the operator's host.",
      ""
    ].join("\n")
  );
}

function readKey(privateKeyFile: string): string {
  if (!existsSync(privateKeyFile)) {
    throw new Error(`private key ${privateKeyFile} does not exist`);
  }
  return readFileSync(privateKeyFile, "utf8");
}

function connect(flags: Record<string, string | boolean>): Pool {
  const databaseUrl = (flags["database-url"] as string | undefined) ?? process.env.DATABASE_URL;
  if (!databaseUrl) {
    throw new Error("DATABASE_URL is required (or pass --database-url)");
  }
  return new Pool({ connectionString: databaseUrl });
}

async function main(): Promise<void> {
  const { command, flags } = parseFlags(process.argv.slice(2));
  const by = (flags["by"] as string | undefined) ?? "operator";

  if (command === "keygen") {
    const outDir = (flags.out as string | undefined) ?? "./policy-keys";
    const written = writeKeyPair(outDir);
    process.stdout.write(
      [
        `private key: ${written.privateKeyPath}`,
        `public key:  ${written.publicKeyPath}`,
        `key id:      ${written.keyId}`,
        "",
        "Keep the private key on this host. Next: trust the public key for a workspace, then publish.",
        ""
      ].join("\n")
    );
    return;
  }

  if (command === "trust") {
    const pool = connect(flags);
    try {
      const workspaceId = await resolveWorkspaceId(pool, flags.workspace as string | undefined);
      const publicKeyFile = (flags["public-key"] as string | undefined) ?? "./policy-keys/signing-key.pub.pem";
      if (!existsSync(publicKeyFile)) throw new Error(`public key ${publicKeyFile} does not exist`);
      const result = await trustKey(pool, {
        workspaceId,
        publicKeyPem: readFileSync(publicKeyFile, "utf8"),
        rotate: flags.rotate === true,
        trustedBy: by
      });
      if (result.alreadyTrusted) {
        process.stdout.write(`key ${result.keyId.slice(0, 12)}... is already trusted for this workspace\n`);
      } else {
        for (const retired of result.retired) {
          process.stdout.write(`retired key ${retired.slice(0, 12)}...\n`);
        }
        process.stdout.write(`trusted key ${result.keyId.slice(0, 12)}... for workspace ${workspaceId}\n`);
        if (result.retired.length > 0) {
          process.stdout.write("publish a new bundle now: a retired key stops verifying its versions\n");
        }
      }
      return;
    } finally {
      await pool.end();
    }
  }

  if (command === "publish") {
    const keyFile = (flags.key as string | undefined) ??
      process.env.POLICY_SIGNING_KEY_FILE ?? "./policy-keys/signing-key.pem";
    const privateKeyPem = readKey(keyFile);
    const pool = connect(flags);
    try {
      const workspaceId = await resolveWorkspaceId(pool, flags.workspace as string | undefined);
      const result = await publish(pool, {
        workspaceId,
        privateKeyPem,
        publishedBy: by,
        dryRun: flags["dry-run"] === true
      });
      process.stdout.write(
        [
          `${result.published ? "published" : "dry run"}: version ${result.version}`,
          `content hash: ${result.contentHash}`,
          `key id:       ${result.keyId.slice(0, 12)}...`,
          `manifest:     ${result.counts.rules} rules, ${result.counts.servers} servers, ${result.counts.pins} tool pins`,
          ""
        ].join("\n")
      );
      return;
    } finally {
      await pool.end();
    }
  }

  if (command === "status") {
    const pool = connect(flags);
    const client = await pool.connect();
    try {
      const workspaceId = await resolveWorkspaceId(client, flags.workspace as string | undefined);
      const active = await client.query(
        `SELECT pv.version, pv.content_hash, pv.published_at, pv.published_by,
                pk.key_id, (pk.retired_at IS NOT NULL) AS key_retired
           FROM active_config ac
           JOIN policy_versions pv ON pv.id = ac.policy_version_id
           JOIN policy_signing_keys pk ON pk.id = pv.signing_key_id
          WHERE ac.workspace_id = $1`,
        [workspaceId]
      );
      if (active.rows[0]) {
        const row = active.rows[0];
        process.stdout.write(
          `active: version ${row.version} (${String(row.content_hash).slice(0, 12)}...) published ${row.published_at?.toISOString?.() ?? row.published_at} by ${row.published_by}\n` +
          `key:    ${String(row.key_id).slice(0, 12)}...${row.key_retired ? " (RETIRED - republish)" : ""}\n`
        );
      } else {
        process.stdout.write("active: nothing published yet\n");
      }
      const { counts, problems } = await assembleBundle(client, workspaceId);
      process.stdout.write(
        `draft:  ${counts.rules} rules, ${counts.servers} servers, ${counts.pins} reviewed tool pins\n`
      );
      for (const problem of problems) {
        process.stdout.write(`problem: ${problem}\n`);
      }
      return;
    } finally {
      client.release();
      await pool.end();
    }
  }

  usage();
}

const isMain = process.argv[1]?.endsWith("index.js") || process.argv[1]?.endsWith("index.ts");
if (isMain) {
  main().catch((err: unknown) => {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}
