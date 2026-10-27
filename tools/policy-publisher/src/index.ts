import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, posix } from "node:path";
import { Pool, type PoolClient } from "pg";
import { appendAuditEvent } from "@traceguard/audit-chain";
import { contentHashOf, generateSigningKey, keyIdFor, signPayload } from "@traceguard/policy-signing";
import {
  BUNDLE_VERSION,
  PATH_CONFINEMENT_META_KEY,
  PROTOCOL_PROFILE,
  hasPathWithin,
  pathConfinementMetaSchema,
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

// Signed policy is published per project. Omitting the ref selects the
// workspace's default project, which is what every pre-039 workflow used.
export async function resolveProjectId(
  db: PoolClient | Pool,
  workspaceId: string,
  ref: string | undefined
): Promise<string> {
  const wanted = ref ?? "default";
  const res = await db.query(
    `SELECT id FROM projects
      WHERE workspace_id = $1 AND (name = $2 OR id::text = $2)`,
    [workspaceId, wanted]
  );
  if (!res.rows[0]) {
    throw new Error(`project "${wanted}" not found in workspace ${workspaceId}`);
  }
  return String(res.rows[0].id);
}

// FR-010: same normalization as the gateway's pathWithin — posix.normalize
// both sides, then a boundary-aware prefix test. Kept local so the publisher
// does not depend on the API package at runtime; the two must agree, and the
// publisher is the stricter gate because it refuses at signing time.
function withinRoot(value: string, root: string): boolean {
  const clean = (p: string) => (p.startsWith("/") ? posix.normalize(p) : posix.normalize("/" + p));
  const v = clean(value);
  const base = clean(root);
  return v === base || v.startsWith(base.endsWith("/") ? base : base + "/");
}

// Builds the candidate bundle from current drafts. It never signs anything;
// publish() validates the result and refuses on problems.
export async function assembleBundle(
  client: PoolClient,
  workspaceId: string,
  projectId: string
): Promise<Assembly> {
  const project = await client.query(
    "SELECT id FROM projects WHERE id = $1 AND workspace_id = $2",
    [projectId, workspaceId]
  );
  if (!project.rows[0]) {
    throw new Error(`project ${projectId} does not belong to workspace ${workspaceId}`);
  }
  const versionRow = await client.query(
    "SELECT coalesce(max(version), 0) AS v FROM policy_versions WHERE project_id = $1",
    [projectId]
  );
  const nextVersion = Number(versionRow.rows[0].v) + 1;
  const activeRow = await client.query(
    `SELECT pv.content_hash FROM active_config ac
       JOIN policy_versions pv ON pv.id = ac.policy_version_id
      WHERE ac.project_id = $1`,
    [projectId]
  );
  const previous = (activeRow.rows[0]?.content_hash as string | undefined) ?? null;

  const servers = await client.query(
    "SELECT id, gateway_alias, base_url, secret_ref FROM mcp_servers WHERE project_id = $1 ORDER BY gateway_alias",
    [projectId]
  );
  const pins = await client.query(
    `SELECT st.server_id, st.tool_name,
            COALESCE(cp.id, ap.id) AS pin_id,
            COALESCE(cp.version, ap.version) AS pin_version,
            COALESCE(cp.definition_hash, ap.definition_hash) AS definition_hash,
            COALESCE(cp.definition, ap.definition) AS definition
       FROM server_tools st
       JOIN mcp_servers s ON s.id = st.server_id
       JOIN tool_pins ap ON ap.id = st.active_pin_id
       LEFT JOIN tool_pins cp ON cp.id = st.candidate_pin_id AND cp.status = 'approved'
      WHERE s.project_id = $1
        AND ((st.quarantined = false AND st.quarantine_reason IS NULL) OR cp.status = 'approved')
      ORDER BY st.server_id, st.tool_name`,
    [projectId]
  );
  const rules = await client.query(
    `SELECT id, name, enabled, priority, agent_id, server_id, tool_name, effect, conditions
       FROM policies WHERE project_id = $1 AND superseded_by IS NULL
      ORDER BY name, id`,
    [projectId]
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
    project_id: projectId,
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
      // The reference is signed; the secret value never enters the bundle.
      secret_ref: s.secret_ref ?? null,
      auth_mode: s.secret_ref ? "gateway_secret" : "none"
    })),
    pins: pins.rows.map((p) => ({
      server_id: p.server_id,
      tool_name: p.tool_name,
      pin_id: p.pin_id,
      pin_version: Number(p.pin_version),
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
  // FR-010 / §16.3 T9: a path_within rule is publishable only against a tool
  // whose pinned definition carries the executor confinement attestation, and
  // only when the constrained path is inside the attested root. Refusing here
  // means an unenforceable rule never reaches the signed bundle.
  const pinByTarget = new Map(
    pins.rows.map((p) => [`${p.server_id}/${p.tool_name}`, p] as const)
  );
  for (const rule of candidate.rules) {
    if (!hasPathWithin(rule.conditions)) continue;
    if (!rule.server_id || !rule.tool_name) {
      problems.push(`rule "${rule.name}" uses path_within without a server- and tool-scoped target`);
      continue;
    }
    const pin = pinByTarget.get(`${rule.server_id}/${rule.tool_name}`);
    if (!pin) {
      problems.push(`rule "${rule.name}" uses path_within but tool "${rule.tool_name}" is not in the reviewed pin manifest`);
      continue;
    }
    const definition = pin.definition as { _meta?: Record<string, unknown> } | null;
    const attestation = definition?._meta?.[PATH_CONFINEMENT_META_KEY];
    const parsedMeta = pathConfinementMetaSchema.safeParse(attestation);
    if (!parsedMeta.success) {
      problems.push(`rule "${rule.name}" uses path_within but tool "${rule.tool_name}" has no pinned executor path-confinement attestation (${PATH_CONFINEMENT_META_KEY})`);
      continue;
    }
    const conditions = rule.conditions as {
      arguments?: Record<string, { path_within?: unknown } | undefined>;
    } | null;
    for (const constraint of Object.values(conditions?.arguments ?? {})) {
      const allowed = constraint?.path_within;
      if (typeof allowed === "string" && !withinRoot(allowed, parsedMeta.data.root)) {
        problems.push(`rule "${rule.name}" path_within "${allowed}" is outside the executor's attested root "${parsedMeta.data.root}"`);
      }
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
    // The procedure serializes per workspace and owns the only INSERT/UPDATE
    // path on policy_signing_keys. It returns the exact rows it changed so the
    // publisher can append matching audit events in the same transaction.
    const changed = await client.query<{ action: string; out_key_id: string }>(
      "SELECT action, out_key_id FROM policy_trust_key($1,$2,$3,$4)",
      [opts.workspaceId, keyId, opts.publicKeyPem.trim(), opts.rotate ?? false]
    );
    if (changed.rows.some((row) => row.action === "already_trusted")) {
      await client.query("COMMIT");
      return { keyId, retired: [], alreadyTrusted: true };
    }
    const retired: string[] = [];
    for (const row of changed.rows.filter((entry) => entry.action === "retired")) {
      await appendAuditEvent(client, {
        actor_type: "admin", actor_id: opts.trustedBy ?? "operator",
        action: "policy.signing_key.retired", resource_type: "policy_signing_key",
        resource_id: String(row.out_key_id), result: "success"
      });
      retired.push(String(row.out_key_id));
    }
    const trusted = changed.rows.find(
      (entry) => entry.action === "trusted" || entry.action === "reactivated"
    );
    if (!trusted) {
      throw new Error("trust procedure returned no trusted key state");
    }
    await appendAuditEvent(client, {
      actor_type: "admin", actor_id: opts.trustedBy ?? "operator",
      action: "policy.signing_key.trusted", resource_type: "policy_signing_key",
      resource_id: keyId, result: "success",
      metadata: trusted.action === "reactivated" ? { reactivated: true } : {}
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
  /** Project name or id. Defaults to the workspace's `default` project. */
  projectId?: string;
  privateKeyPem: string;
  publishedBy?: string;
  dryRun?: boolean;
}

export interface PublishResult {
  published: boolean;
  projectId: string;
  version: number;
  contentHash: string;
  keyId: string;
  counts: PublishCounts;
  bundle: PolicyBundle;
}

export async function publish(pool: Pool, opts: PublishOptions): Promise<PublishResult> {
  const client = await pool.connect();
  try {
    const projectId = await resolveProjectId(client, opts.workspaceId, opts.projectId);
    const { bundle, counts, problems } = await assembleBundle(client, opts.workspaceId, projectId);
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
      return { published: false, projectId, version: bundle.version, contentHash, keyId, counts, bundle };
    }

    await client.query("BEGIN");
    let inserted: { rows: Record<string, unknown>[] };
    try {
      inserted = await client.query(
        `INSERT INTO policy_versions
           (workspace_id, project_id, version, bundle, content_hash, signature, signing_key_id,
            previous_version_hash, published_by)
         VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9)
         RETURNING id`,
        [opts.workspaceId, projectId, bundle.version, JSON.stringify(bundle), contentHash, signature,
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
    // Activation is a narrow procedure: it verifies that the signed version
    // belongs to this workspace and owns the only active_config write.
    await client.query("SELECT policy_activate_version($1,$2)", [
      opts.workspaceId, inserted.rows[0].id
    ]);
    // The bundle carries the approved pin versions, but a pin becomes callable
    // only in this same transaction. If this fails, the policy activation rolls
    // back too, so the signed policy and the callable definitions cannot drift.
    const activated = await client.query(
      "SELECT activate_approved_tool_pins($1) AS activated",
      [projectId]
    );
    // Stamp the server rows with the exact signed bundle version. The gateway
    // refuses any server whose row was not stamped by this same transaction.
    const stamped = await client.query(
      "SELECT stamp_signed_servers($1,$2) AS stamped",
      [projectId, bundle.version]
    );
    await appendAuditEvent(client, {
      actor_type: "admin", actor_id: opts.publishedBy ?? "operator",
      action: "policy.published", resource_type: "policy_version",
      resource_id: String(inserted.rows[0].id), result: "success",
      workspace_id: opts.workspaceId,
      project_id: projectId,
      metadata: {
        project_id: projectId,
        version: bundle.version,
        content_hash: contentHash,
        key_id: keyId,
        rules: counts.rules,
        servers: counts.servers,
        servers_signed: Number(stamped.rows[0]?.stamped ?? 0),
        pins: counts.pins,
        pins_activated: Number(activated.rows[0]?.activated ?? 0)
      }
    });
    await client.query("COMMIT");
    return { published: true, projectId, version: bundle.version, contentHash, keyId, counts, bundle };
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
      "          [--project <id|name>]      Project to publish (default: the workspace default project)",
      "          --key <file>               Private key PEM (or POLICY_SIGNING_KEY_FILE)",
      "          [--dry-run] [--by <name>]",
      "  status  --workspace <id|name>      Show the active version, its key, and what a publish would contain",
      "          [--project <id|name>]      Project to inspect (default: the workspace default project)",
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
        projectId: flags.project as string | undefined,
        privateKeyPem,
        publishedBy: by,
        dryRun: flags["dry-run"] === true
      });
      process.stdout.write(
        [
          `${result.published ? "published" : "dry run"}: version ${result.version}`,
          `project:      ${result.projectId}`,
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
      const projectId = await resolveProjectId(client, workspaceId, flags.project as string | undefined);
      const active = await client.query(
        `SELECT pv.version, pv.content_hash, pv.published_at, pv.published_by,
                pk.key_id, (pk.retired_at IS NOT NULL) AS key_retired
           FROM active_config ac
           JOIN policy_versions pv ON pv.id = ac.policy_version_id
           JOIN policy_signing_keys pk ON pk.id = pv.signing_key_id
          WHERE ac.project_id = $1`,
        [projectId]
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
      const { counts, problems } = await assembleBundle(client, workspaceId, projectId);
      process.stdout.write(
        `project: ${projectId}\n` +
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
