#!/usr/bin/env node
// One-command demo (§22) and the §21.16 checkpoint walk.
//
//   npm run demo          # .env + keys, build the stack, wait, run the agent,
//                         # print the live trace URL
//   npm run demo:audit    # signed checkpoint -> export -> offline verify ->
//                         # prove retention refuses an unsigned prune
//   npm run demo:reset    # remove demo/bench fixtures, keep history
//
// The script only uses Node built-ins and the docker CLI. It never prints a
// private key. The checkpoint key pair lives in .demo-keys/ (gitignored); only
// the public key is passed to compose, while the operator CLI reads the private
// key directly from the host.

import { spawnSync } from "node:child_process";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const ROOT = process.cwd();
const ENV_FILE = resolve(ROOT, ".env");
const ENV_EXAMPLE = resolve(ROOT, ".env.example");
const KEYS_DIR = resolve(ROOT, ".demo-keys");
const PRIVATE_KEY_FILE = resolve(KEYS_DIR, "audit-checkpoint.key");
const PUBLIC_KEY_FILE = resolve(KEYS_DIR, "audit-checkpoint.pub.pem");
const EXPORT_FILE = resolve(KEYS_DIR, "checkpoint-export.json");

const API_URL = "http://127.0.0.1:8090";
const GATEWAY_URL = "http://127.0.0.1:8091";
const CONTROL_URL = "http://127.0.0.1:8093";
const WEB_URL = "http://127.0.0.1:5173";

function log(message = "") {
  console.log(message);
}

function fail(message) {
  console.error(`\nFAIL  ${message}`);
  process.exit(1);
}

function parseEnv(text) {
  const values = {};
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const index = trimmed.indexOf("=");
    if (index <= 0) continue;
    const key = trimmed.slice(0, index).trim();
    let value = trimmed.slice(index + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    values[key] = value;
  }
  return values;
}

function ensureEnvFile() {
  if (!existsSync(ENV_FILE)) {
    if (!existsSync(ENV_EXAMPLE)) fail("missing .env and .env.example");
    copyFileSync(ENV_EXAMPLE, ENV_FILE);
    log("created .env from .env.example");
  }
  return parseEnv(readFileSync(ENV_FILE, "utf8"));
}

function upsertEnv(key, value) {
  const text = readFileSync(ENV_FILE, "utf8");
  const pattern = new RegExp(`^${key}=.*$`, "m");
  const next = pattern.test(text)
    ? text.replace(pattern, `${key}=${value}`)
    : `${text}${text.endsWith("\n") ? "" : "\n"}${key}=${value}\n`;
  writeFileSync(ENV_FILE, next);
}

function value(env, key, fallback = "") {
  return process.env[key] || env[key] || fallback;
}

function loadOrCreateCheckpointKeys(env) {
  const envPrivate = process.env.AUDIT_CHECKPOINT_KEY || env.AUDIT_CHECKPOINT_KEY;
  const envPublic = process.env.AUDIT_CHECKPOINT_PUBLIC_KEY || env.AUDIT_CHECKPOINT_PUBLIC_KEY;
  if (existsSync(PRIVATE_KEY_FILE) && existsSync(PUBLIC_KEY_FILE)) {
    return {
      privateKey: readFileSync(PRIVATE_KEY_FILE, "utf8"),
      publicKey: readFileSync(PUBLIC_KEY_FILE, "utf8"),
      source: ".demo-keys/",
    };
  }
  if (envPrivate && envPublic) {
    return { privateKey: envPrivate, publicKey: envPublic, source: "environment" };
  }
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  mkdirSync(KEYS_DIR, { recursive: true, mode: 0o700 });
  writeFileSync(PRIVATE_KEY_FILE, privatePem, { mode: 0o600 });
  writeFileSync(PUBLIC_KEY_FILE, publicPem, { mode: 0o644 });
  return { privateKey: privatePem, publicKey: publicPem, source: ".demo-keys/ (new ed25519 key)" };
}

function docker(args, options = {}) {
  return spawnSync("docker", args, { cwd: ROOT, encoding: "utf8", ...options });
}

function compose(args, env, options = {}) {
  return docker(["compose", ...args], { env, ...options });
}

async function waitFor(url, label, timeoutMs = 90_000) {
  const started = Date.now();
  let lastError = "";
  while (Date.now() - started < timeoutMs) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(2_000) });
      if (response.ok) return;
      lastError = `HTTP ${response.status}`;
    } catch (error) {
      lastError = error.message;
    }
    await new Promise((done) => setTimeout(done, 1_000));
  }
  fail(`${label} did not become ready at ${url} (${lastError})`);
}

async function json(url, init) {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(15_000) });
  const text = await response.text();
  let body;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  return { response, body };
}

async function up(argv) {
  const env = ensureEnvFile();
  const approvalKey = value(env, "APPROVAL_ARGS_KEY");
  if (!approvalKey) {
    const generated = randomBytes(32).toString("hex");
    upsertEnv("APPROVAL_ARGS_KEY", generated);
    env.APPROVAL_ARGS_KEY = generated;
    log("generated APPROVAL_ARGS_KEY in .env");
  }
  const checkpoint = loadOrCreateCheckpointKeys(env);
  log(`checkpoint signing key: ${checkpoint.source}`);

  const childEnv = {
    ...process.env,
    APPROVAL_ARGS_KEY: value(env, "APPROVAL_ARGS_KEY"),
    // The gateway verifies checkpoints; the operator-side CLI holds the
    // private key. Never put the signing key in a container environment.
    AUDIT_CHECKPOINT_PUBLIC_KEY: checkpoint.publicKey,
  };

  const composeArgs = ["up", "-d", "--wait"];
  if (!argv.includes("--no-build")) composeArgs.push("--build");
  log(`\n$ docker compose ${composeArgs.join(" ")}`);
  const started = compose(composeArgs, childEnv, { stdio: "inherit" });
  if (started.status !== 0) {
    fail("docker compose did not come up; is Docker Desktop running? See `docker compose logs`.");
  }

  log("\nwaiting for the api, gateway, control listener, and dashboard");
  await waitFor(`${API_URL}/readyz`, "api ready check");
  await waitFor(`${GATEWAY_URL}/healthz`, "gateway");
  await waitFor(`${CONTROL_URL}/healthz`, "approval control listener");
  await waitFor(`${WEB_URL}/`, "dashboard");

  log("\nrunning the demo agent through the boundary");
  const run = compose(["exec", "-T", "agent", "python", "main.py"], childEnv);
  if (run.status !== 0) {
    fail("the demo agent failed; check `docker compose logs api gateway agent`");
  }
  const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
  log(output.trimEnd());
  const match = output.match(/^run:\s*([0-9a-f-]{36})\s*$/m);
  const runId = match?.[1] ?? null;
  if (!runId) fail("the demo agent did not print a run id");

  // Telemetry is submitted through the gateway (agent_edge) and forwarded by
  // the gateway to the API. Read it back over the API to prove the whole path
  // before declaring the demo healthy.
  const apiKey = value(env, "API_KEY", "dev_key_change_me");
  const trace = await json(`${API_URL}/v1/runs/${runId}/trace`, {
    headers: { authorization: `Bearer ${apiKey}` },
  });
  if (!trace.response.ok) {
    fail(
      `the run was not visible over the API (HTTP ${trace.response.status}); ` +
        "check the gateway ingest forward: `docker compose logs gateway api`",
    );
  }

  log("\nTraceGuard demo is up.");
  log(`  dashboard: ${WEB_URL}/${runId ? `#/runs/${runId}` : ""}`);
  if (runId) log(`  run:       ${runId}`);
  log(`  api:       ${API_URL}`);
  log(`  gateway:   ${GATEWAY_URL}  (control listener ${CONTROL_URL})`);
  log("\nnext:");
  log("  npm run demo:audit   # checkpoint -> export -> offline verify -> refused prune");
  log("  npm run demo:reset   # remove demo/bench fixtures, keep history");
}

function reset() {
  ensureEnvFile();
  const env = parseEnv(readFileSync(ENV_FILE, "utf8"));
  const user = value(env, "POSTGRES_USER", "traceguard");
  const database = value(env, "POSTGRES_DB", "traceguard");
  const sql = readFileSync(resolve(ROOT, "scripts", "clean-demo-data.sql"), "utf8");
  log(`removing demo fixtures from ${database} as ${user}`);
  const result = spawnSync(
    "docker",
    ["compose", "exec", "-T", "postgres", "psql", "-U", user, "-d", database, "-v", "ON_ERROR_STOP=1"],
    { cwd: ROOT, input: sql, encoding: "utf8" },
  );
  if (result.stdout) log(result.stdout.trimEnd());
  if (result.stderr) console.error(result.stderr.trimEnd());
  if (result.status !== 0) fail("demo reset failed");
  log("\ndemo fixtures removed; runs, spans, audit events, and other history are untouched.");
}

function shellQuote(part) {
  return /\s/.test(part) ? `"${part}"` : part;
}

function npx(args, options = {}) {
  if (process.platform === "win32") {
    return spawnSync(`npx ${args.map(shellQuote).join(" ")}`, {
      cwd: ROOT,
      encoding: "utf8",
      shell: true,
      ...options,
    });
  }
  return spawnSync("npx", args, { cwd: ROOT, encoding: "utf8", ...options });
}

function operatorDatabaseUrl(env) {
  const raw = value(env, "DATABASE_URL",
    "postgres://traceguard:traceguard_dev_only@127.0.0.1:5432/traceguard");
  try {
    const url = new URL(raw);
    // The app containers use the compose service name; this CLI runs on the
    // operator host, where the same database is published on localhost.
    if (url.hostname === "postgres") url.hostname = "127.0.0.1";
    return url.toString();
  } catch {
    return raw;
  }
}

function checkpointCli(args, env) {
  return npx(
    ["tsx", "scripts/audit-checkpoint.mts", ...args,
      "--database-url", operatorDatabaseUrl(env)],
    { stdio: "inherit" },
  );
}

async function audit() {
  const env = ensureEnvFile();
  const publicPem = existsSync(PUBLIC_KEY_FILE)
    ? readFileSync(PUBLIC_KEY_FILE, "utf8")
    : process.env.AUDIT_CHECKPOINT_PUBLIC_KEY || env.AUDIT_CHECKPOINT_PUBLIC_KEY;
  if (!publicPem) {
    fail("no checkpoint public key; run `npm run demo` first (or set AUDIT_CHECKPOINT_PUBLIC_KEY)");
  }

  log("1. create a signed checkpoint over the exact prefix ending at the current tip");
  const created = checkpointCli(
    ["create", "--cutoff", "latest", "--out", EXPORT_FILE, "--key", PRIVATE_KEY_FILE],
    env,
  );
  if (created.status !== 0) fail("checkpoint creation failed");
  const artifact = JSON.parse(readFileSync(EXPORT_FILE, "utf8"));
  const checkpoint = artifact.checkpoint;
  const payload = checkpoint?.payload ?? {};
  const segments = Array.isArray(payload.segments) ? payload.segments : [];
  log(`   checkpoint ${checkpoint.id}`);
  log(`   ${payload.event_count ?? "?"} events, ${segments.length} workspace segment(s), key ${String(checkpoint.key_id ?? "").slice(0, 16)}`);
  log(`   wrote ${EXPORT_FILE} (${artifact.events?.length ?? 0} events)`);

  log("\n2. verify the checkpoint and chain offline (no API or database trust)");
  const build = npx(["tsc", "-p", "packages/canonical-json/tsconfig.json"]);
  if (build.status !== 0) fail("could not build packages/canonical-json");
  const buildChain = npx(["tsc", "-p", "packages/audit-chain/tsconfig.json"]);
  if (buildChain.status !== 0) fail("could not build packages/audit-chain");
  const verify = npx(
    ["tsx", "scripts/verify-audit.mts", "--export", EXPORT_FILE, "--public-key", PUBLIC_KEY_FILE],
    { stdio: "inherit" },
  );
  if (verify.status !== 0) fail("offline verification failed; the export or key does not match the chain");

  log("\n3. prove prune refuses a tampered signed artifact (§10.2)");
  const tamperedFile = resolve(KEYS_DIR, "checkpoint-export.tampered.json");
  const tampered = JSON.parse(JSON.stringify(artifact));
  tampered.checkpoint.payload.up_to_hash = "00".repeat(32);
  writeFileSync(tamperedFile, `${JSON.stringify(tampered, null, 2)}\n`);
  const refused = checkpointCli(
    ["prune", "--artifact", tamperedFile, "--public-key", PUBLIC_KEY_FILE,
      "--receipt", "demo://refused-tampered"],
    env,
  );
  if (refused.status === 0) fail("a tampered checkpoint was accepted for pruning");
  log("   refused; no events were deleted.");

  log("\ncheckpoint walk complete.");
  log(`  export:   ${EXPORT_FILE}`);
  log("  receipt:  store the export outside PostgreSQL and the api/gateway containers.");
  log("  to prune (operator step, not run by the demo):");
  log(`    npm run audit:checkpoint -- prune \\`);
  log(`      --artifact ${EXPORT_FILE} --public-key ${PUBLIC_KEY_FILE} \\`);
  log(`      --receipt s3://audit-vault/${checkpoint.id}.json`);
}

const command = process.argv[2] ?? "up";
const argv = process.argv.slice(3);

try {
  if (command === "up" || command === "start") await up(argv);
  else if (command === "reset") reset();
  else if (command === "audit") await audit();
  else {
    console.error("usage: demo.mjs [up|reset|audit] [--no-build]");
    process.exit(2);
  }
} catch (error) {
  fail(error?.stack ?? String(error));
}
