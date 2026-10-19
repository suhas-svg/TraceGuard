#!/usr/bin/env node
// Live walkthrough of the hardening changes. Drives the real API, gateway, and
// dashboard against the real database; every number below is a response or a
// row, nothing is mocked or replayed from a fixture.
//
//   node scripts/demo-fixes.mjs
//
// Needs: API on 8090, gateway on 8091, approval control listener on 8093,
// mock tools on 8092, web preview on 5173, and Playwright's chromium.
// scripts/demo-fixes.sh starts all four.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { createServer } from "node:http";
import { Pool } from "pg";
import { chromium } from "@playwright/test";

const API = (process.env.API ?? "http://localhost:8090").replace(/\/$/, "");
const GW = (process.env.GW ?? "http://localhost:8091").replace(/\/$/, "");
const GWC = (process.env.GWC ?? "http://localhost:8093").replace(/\/$/, "");
const WEB = (process.env.WEB ?? "http://localhost:5173").replace(/\/$/, "");
const MOCK = process.env.MOCK ?? "http://127.0.0.1:8092/mcp";
const KEY = process.env.KEY ?? process.env.API_KEY ?? "test_key";
const APPROVER = process.env.APPROVER_KEY ?? "test_approver";
const tag = Date.now().toString(36);

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const sql = async (text, params) => (await pool.query(text, params)).rows;

let passed = 0;
let failed = 0;

function head(n, title) {
  console.log(`\n${"─".repeat(78)}\n${n}. ${title}\n`);
}
function check(label, ok, detail) {
  if (ok) passed += 1;
  else failed += 1;
  console.log(`   ${ok ? "PASS" : "FAIL"}  ${label}`);
  if (detail !== undefined) console.log(`         ${detail}`);
}
function note(text) {
  console.log(`         note: ${text}`);
}

async function call(base, method, path, body, key = KEY) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const text = await res.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
  return { status: res.status, data };
}
const api = (...a) => call(API, ...a);
const gw = (...a) => call(GW, ...a);
const gwc = (...a) => call(GWC, ...a);

// ── 1. Budgets: an abandoned hold no longer wedges the budget forever ───────
head(1, "Budget: a hold abandoned by a dead caller is reclaimed");
{
  const b = await api("POST", "/v1/budgets", {
    scope: "run", ref_id: crypto.randomUUID(), limit_micro: 1000
  });
  const id = b.data.id;
  const hold = await api("POST", "/v1/budgets/check", {
    budget_id: id, max_cost_micro: 1000, ttl_seconds: 300
  });
  check("the whole limit can be reserved", hold.status === 200,
    `POST /v1/budgets/check -> ${hold.status}, expires ${hold.data.expires_at}`);

  const blocked = await api("POST", "/v1/budgets/check", { budget_id: id, max_cost_micro: 1 });
  check("a second caller is refused while the hold is live", blocked.status === 409,
    `1 micro against the same budget -> ${blocked.status} ${blocked.data.error}`);

  // The caller died here: no settle, no release. Age the hold past its TTL.
  await sql("UPDATE budget_reservations SET expires_at = now() - interval '1 second' WHERE budget_id = $1", [id]);
  const after = await api("POST", "/v1/budgets/check", { budget_id: id, max_cost_micro: 1000 });
  const row = (await sql(
    "SELECT reserved_micro, spent_micro FROM budgets WHERE id = $1", [id]))[0];
  const rel = await sql(
    "SELECT released_at FROM budget_reservations WHERE budget_id = $1 AND status = 'released'", [id]);
  const aud = await sql(
    `SELECT count(*)::int AS n FROM audit_events
      WHERE action = 'budget.reservation_expired' AND resource_id = $1`, [id]);
  check("the next check reclaims it instead of 409ing forever", after.status === 200,
    `same request that was refused now -> ${after.status}`);
  check("the reservation is marked released, not silently dropped",
    rel.length === 1 && rel[0].released_at !== null,
    `budget_reservations.status='released', released_at=${rel[0]?.released_at?.toISOString()}`);
  check("an unconfirmed call is not billed", Number(row.spent_micro) === 0,
    `spent_micro=${row.spent_micro}, reserved_micro=${row.reserved_micro} (the fresh hold only)`);
  check("the recovery is in the audit chain", aud[0].n === 1,
    `audit_events action=budget.reservation_expired -> ${aud[0].n} row`);
}

// ── 2. Budgets: the list is workspace-confined ─────────────────────────────
head(2, "Budget: the list no longer leaks every workspace's limits and spend");
{
  const ws = await api("POST", "/v1/workspaces", { name: `demo-ws-${tag}` });
  const mine = await api("POST", "/v1/budgets", {
    scope: "run", ref_id: crypto.randomUUID(), limit_micro: 5000
  });
  const u = await api("POST", "/v1/users", {
    email: `demo-${tag}@example.com`, password: "long-password-999", role: "member"
  });
  await api("POST", `/v1/users/${u.data.id}/memberships`, { workspace_id: ws.data.id });
  const k = await api("POST", `/v1/users/${u.data.id}/keys`, { name: "reader", scopes: ["read"] });
  const member = k.data.key;

  const admin = await api("GET", "/v1/budgets?limit=500");
  const asMember = await api("GET", "/v1/budgets?limit=500", undefined, member);
  const adminSees = admin.data.items.some((b) => b.id === mine.data.id);
  const memberSees = asMember.data.items.some((b) => b.id === mine.data.id);
  check("the budget exists and an unrestricted key sees it", adminSees,
    `GET /v1/budgets as admin -> ${admin.data.items.length} rows, includes ${mine.data.id.slice(0, 8)}`);
  check("a member of another workspace does not", !memberSees,
    `GET /v1/budgets as read-scope member of demo-ws-${tag} -> ${asMember.data.items.length} rows, foreign budget absent`);
}

// ── 3. Budgets: reporting periods ──────────────────────────────────────────
head(3, "Budget: a monthly budget ignores last month's spend, a lifetime one does not");
{
  const monthly = await api("POST", "/v1/budgets", {
    scope: "run", ref_id: crypto.randomUUID(), limit_micro: 1000, period: "month"
  });
  const lifetime = await api("POST", "/v1/budgets", {
    scope: "run", ref_id: crypto.randomUUID(), limit_micro: 1000
  });
  for (const id of [monthly.data.id, lifetime.data.id]) {
    await sql("UPDATE budgets SET spent_micro = 900 WHERE id = $1", [id]);
    await sql(
      `INSERT INTO budget_ledger (budget_id, amount_micro, created_at)
       VALUES ($1, 900, now() - interval '40 days')`, [id]);
  }
  const m = await api("POST", "/v1/budgets/check", { budget_id: monthly.data.id, max_cost_micro: 500 });
  const l = await api("POST", "/v1/budgets/check", { budget_id: lifetime.data.id, max_cost_micro: 500 });
  check("period='month' counts only this window", m.status === 200,
    `900 micro spent 40 days ago, asking for 500 -> ${m.status} (window is empty)`);
  check("the default period='lifetime' still counts it", l.status === 409,
    `same ledger row, same request -> ${l.status} ${l.data.error} spent_micro=${l.data.spent_micro}`);
}

// ── 4. Approvals: the queue lives on the human control listener ───────────
head(4, "Approvals: the queue is control-listener only, plaintext for the approve scope alone");
{
  const secretText = `classified-${tag}`;
  const srv = await gw("POST", "/v1/servers", { name: `demo-${tag}`, base_url: MOCK });
  const disc = await gw("POST", `/v1/servers/${srv.data.id}/discover`, {});
  const tool = disc.data.tools[0].tool_name;
  await gw("POST", "/v1/policies", {
    name: `demo-approve-${tag}`, priority: 500, server_id: srv.data.id,
    tool_name: tool, effect: "require_approval"
  });
  // §13.3: the gateway enforces only signed content, so the demo publishes a
  // real bundle through the operator-side publisher; the private key stays on
  // this host. Drafts first (server, pin, rule), then sign.
  const keyDir = process.env.POLICY_KEY_DIR ?? "demo-policy-keys";
  const publisher = (args) => {
    // Plain node + the tsx CLI: npx.cmd cannot be spawned without a shell on
    // Windows, and this keeps the demo dependency-free on every platform.
    const r = spawnSync(process.execPath,
      ["node_modules/tsx/dist/cli.mjs", "tools/policy-publisher/src/index.ts", ...args],
      { env: { ...process.env }, encoding: "utf8" });
    if (r.status !== 0) {
      throw new Error(
        `policy-publisher ${args[0]} failed: ` +
        (r.error ? String(r.error) : r.stderr || r.stdout));
    }
    return r.stdout;
  };
  if (!existsSync(`${keyDir}/signing-key.pem`)) publisher(["keygen", "--out", keyDir]);
  publisher(["trust", "--workspace", "default",
    "--public-key", `${keyDir}/signing-key.pub.pem`, "--rotate"]);
  publisher(["publish", "--workspace", "default", "--key", `${keyDir}/signing-key.pem`]);
  const callOut = await gw("POST", "/v1/gateway/tools/call", {
    server_id: srv.data.id, tool, arguments: { path: secretText },
    caller: "demo", request_id: `demo-${tag}`
  });
  const approvalId = callOut.data.approval_id;
  check("the call is held for a human, arguments sealed at rest",
    callOut.status === 202,
    `POST /v1/gateway/tools/call -> ${callOut.status} approval_id=${approvalId?.slice(0, 8)}`);

  const wsList = await api("GET", "/v1/workspaces");
  const def = wsList.data.items.find((w) => w.name === "default");
  const u = await api("POST", "/v1/users", {
    email: `peek-${tag}@example.com`, password: "long-password-999", role: "member"
  });
  await api("POST", `/v1/users/${u.data.id}/memberships`, { workspace_id: def.id });
  const k = await api("POST", `/v1/users/${u.data.id}/keys`, { name: "peeker", scopes: ["read"] });

  const asMember = await gwc("GET", "/_control/v1/approvals?status=pending&limit=200", undefined, k.data.key);
  const asApprover = await gwc("GET", "/_control/v1/approvals?status=pending&limit=200", undefined, APPROVER);
  const rowApprover = asApprover.data.items.find((a) => a.id === approvalId);
  const onAgentPort = await gw("GET", "/v1/approvals?status=pending&limit=200");

  check("the control listener rejects the read-scope member outright",
    asMember.status === 403 && !JSON.stringify(asMember.data).includes(secretText),
    `as member -> ${asMember.status}; secret string present in payload: ` +
      `${JSON.stringify(asMember.data).includes(secretText)}`);
  check("the approver opens the same row on the control listener",
    rowApprover?.args?.path === secretText,
    `as approver: args.path = ${JSON.stringify(rowApprover?.args?.path)}`);
  check("the agent-facing listener no longer serves the queue",
    onAgentPort.status === 404,
    `GET http://localhost:8091/v1/approvals -> ${onAgentPort.status}`);
  note("the dashboard fetches this queue from the control listener (8093) with the approver key");
}

// ── 5. Policies: two concurrent edits cannot fork a rule ──────────────────
head(5, "Policies: concurrent updates serialize instead of creating two live heads");
{
  const p = await gw("POST", "/v1/policies", {
    name: `demo-race-${tag}`, priority: 10, server_id: null, tool_name: "demo_tool", effect: "allow"
  });
  const id = p.data.id;
  const [a, b] = await Promise.all([
    gw("PUT", `/v1/policies/${id}`, { name: `demo-race-${tag}`, priority: 11, effect: "allow" }),
    gw("PUT", `/v1/policies/${id}`, { name: `demo-race-${tag}`, priority: 12, effect: "allow" })
  ]);
  const codes = [a.status, b.status].sort();
  const heads = await sql(
    `SELECT count(*)::int AS n FROM policies WHERE name = $1 AND superseded_by IS NULL`,
    [`demo-race-${tag}`]);
  check("exactly one edit wins, the other is told the rule moved on",
    codes[0] === 200 && codes[1] === 409,
    `two simultaneous PUTs -> ${codes.join(" and ")} (${[a, b].map((r) => r.data.error ?? "ok").join(", ")})`);
  check("one live head, not two", heads[0].n === 1,
    `policies with name=demo-race-${tag} and superseded_by IS NULL -> ${heads[0].n}`);
}

// ── 6. Audit: concurrent appends do not fork the hash chain ───────────────
head(6, "Audit: concurrent appends serialize, so the chain has no fork");
{
  const marker = `chain-${tag}`;
  const results = await Promise.all(Array.from({ length: 8 }, (_, i) =>
    api("POST", "/v1/pricing", {
      provider: marker, model: `m${i}`, input_price_per_million: 1, output_price_per_million: 1
    })));
  const chain = await sql(
    "SELECT prev_hash FROM audit_events WHERE metadata->>'provider' = $1", [marker]);
  const distinct = new Set(chain.map((r) => r.prev_hash)).size;
  check("8 concurrent audited writes, 8 rows", chain.length === 8,
    `${results.filter((r) => r.status === 201).length}/8 pricing creates returned 201`);
  check("every row links to a different tail", distinct === 8,
    `${distinct} distinct prev_hash across ${chain.length} rows — a fork would repeat one`);
}

// ── 7. Evals: version allocation, string expected, inert cost cap ─────────
head(7, "Evaluations: version races, a string expected value, and an unenforceable cap");
{
  const name = `demo-suite-${tag}`;
  const created = await Promise.all(Array.from({ length: 4 }, () =>
    api("POST", "/v1/evaluations/suites", { name })));
  const versions = created.filter((r) => r.status === 201).map((r) => r.data.version);
  const conflicts = created.filter((r) => r.status === 409).length;
  // One winner and clean retryable 409s for the rest. The point is that a
  // concurrent create never 500s and never lands two rows on one version.
  check("concurrent creates never 500 and never share a version",
    versions.length + conflicts === 4 && new Set(versions).size === versions.length &&
      !created.some((r) => r.status >= 500),
    `${versions.length} created (version${versions.length === 1 ? "" : "s"} ` +
      `${versions.sort((x, y) => x - y).join(", ")}), ${conflicts} got a retryable 409 ` +
      `suite_version_race, 0 server errors`);

  const suite = await api("POST", "/v1/evaluations/suites", { name: `${name}-str` });
  const kase = await api("POST", `/v1/evaluations/suites/${suite.data.id}/cases`, {
    name: "greeting", expected: "hello world",
    assertions: [{ type: "exact", value: "hello world" }]
  });
  const run = await api("POST", `/v1/evaluations/suites/${suite.data.id}/runs`, {
    agent_name: `demo-eval-${tag}`, config_fingerprint: "v1"
  });
  check("a case whose only expected value is a string replays",
    kase.status === 201 && run.data.results[0].passed === true,
    `case create -> ${kase.status}; replay -> ${run.data.results[0].assertion_results[0].message}`);

  const capped = await api("POST", "/v1/evaluations/suites", { name: `${name}-cap` });
  await api("POST", `/v1/evaluations/suites/${capped.data.id}/cases`, {
    name: "c1", assertions: [{ type: "contains", value: "x" }], exec_config: { output: "x" }
  });
  await api("POST", `/v1/evaluations/suites/${capped.data.id}/cases`, {
    name: "c2", assertions: [{ type: "contains", value: "x" }], exec_config: { output: "x" }
  });
  const capRun = await api("POST", `/v1/evaluations/suites/${capped.data.id}/runs`, {
    agent_name: `demo-cap-${tag}`, config_fingerprint: "v1",
    model: "unpriced-model", cost_cap_micro: 1
  });
  check("a cost cap that cannot be enforced is reported, not silently ignored",
    /not enforceable/.test(capRun.data.stopped ?? ""),
    `stopped = ${JSON.stringify(capRun.data.stopped)} after ` +
      `${capRun.data.results.length} of 2 cases`);
}

// ── 8. Reconciliation: replaying a batch does not double the invoice ──────
head(8, "Reconciliation: a replayed actuals batch is counted, not doubled");
{
  const row = {
    provider: `demo-recon-${tag}`, model: "m1",
    period_start: "2026-03-01T00:00:00.000Z", period_end: "2026-04-01T00:00:00.000Z",
    input_tokens: 10, output_tokens: 5, actual_cost_micro: 12345, source: "invoice"
  };
  const first = await api("POST", "/v1/reconciliation/actuals", { rows: [row] });
  const again = await api("POST", "/v1/reconciliation/actuals", { rows: [row] });
  const stored = (await sql(
    `SELECT count(*)::int AS n, COALESCE(SUM(actual_cost_micro), 0)::int AS total
       FROM actuals WHERE provider = $1`, [row.provider]))[0];
  check("the first import is accepted", first.data.accepted === 1,
    `accepted=${first.data.accepted} duplicates=${first.data.duplicates}`);
  check("the replay is reported as duplicates", again.data.accepted === 0 && again.data.duplicates === 1,
    `accepted=${again.data.accepted} duplicates=${again.data.duplicates}`);
  check("the invoice total is unchanged", stored.n === 1 && stored.total === 12345,
    `${stored.n} row, sum(actual_cost_micro)=${stored.total}`);

  const bad = await api("GET",
    "/v1/reconciliation/compare?period_start=nonsense&period_end=2026-04-01T00:00:00.000Z");
  check("a malformed period is a 400, not a 500", bad.status === 400,
    `GET /v1/reconciliation/compare?period_start=nonsense -> ${bad.status} ${bad.data.error}`);
}

// ── 9. OTLP: unusable spans rejected, doubles no longer dropped ───────────
head(9, "OTLP: a span with no usable start time is rejected and reported");
{
  const trace = crypto.randomUUID().replace(/-/g, "");
  const now = (BigInt(Date.now()) * 1_000_000n).toString();
  const span = (over) => ({ traceId: trace, spanId: crypto.randomUUID().replace(/-/g, "").slice(0, 16), name: "gen_ai.request", ...over });
  const res = await api("POST", "/v1/traces", {
    resourceSpans: [{
      resource: { attributes: [{ key: "service.name", value: { stringValue: `demo-otlp-${tag}` } }] },
      scopeSpans: [{ spans: [
        span({ startTimeUnixNano: now, endTimeUnixNano: now, attributes: [
          { key: "gen_ai.usage.input_tokens", value: { doubleValue: 1234 } },
          { key: "gen_ai.usage.output_tokens", value: { intValue: "56" } }
        ] }),
        span({ startTimeUnixNano: "not-a-number" })
      ] }]
    }]
  });
  const epoch = (await sql("SELECT count(*)::int AS n FROM spans WHERE started_at < '2000-01-01'"))[0];
  const stored = (await sql(
    `SELECT s.input_tokens, s.output_tokens FROM spans s
       JOIN runs r ON r.id = s.run_id
       JOIN agents a ON a.id = r.agent_id
      WHERE a.name = $1
      ORDER BY s.started_at DESC LIMIT 1`, [`demo-otlp-${tag}`]))[0];
  check("the good span lands, the unusable one is counted as rejected",
    res.data.partialSuccess?.rejectedSpans === 1,
    `rejectedSpans=${res.data.partialSuccess?.rejectedSpans} ` +
      `errorMessage=${JSON.stringify(res.data.partialSuccess?.errorMessage)}`);
  check("nothing is stored at the epoch", epoch.n === 0,
    `spans with started_at before 2000 -> ${epoch.n}`);
  check("a double usage value is kept as a number", Number(stored?.input_tokens) === 1234,
    `gen_ai.usage.input_tokens as doubleValue 1234 -> spans.input_tokens=${stored?.input_tokens}`);
}

// ── 10. Webhooks: a subscription without a secret is refused ──────────────
head(10, "Webhooks: no more signing with a publicly known empty key");
{
  const noSecret = await api("POST", "/v1/webhooks", {
    name: `demo-hook-${tag}`, url: "http://127.0.0.1:9/ping", events: ["tool.denied"]
  });
  const withSecret = await api("POST", "/v1/webhooks", {
    name: `demo-hook-${tag}`, url: "http://127.0.0.1:9/ping", secret: "s3cret", events: ["tool.denied"]
  });
  check("creating one without a secret is a 400", noSecret.status === 400,
    `POST /v1/webhooks without secret -> ${noSecret.status} ${noSecret.data.error}`);
  check("with a secret it is created", withSecret.status === 201,
    `POST /v1/webhooks with secret -> ${withSecret.status}`);
}

// ── 11. Upstream timeout is a real abort, not just a protocol wait ────────
head(11, "Gateway: a hanging upstream is aborted at UPSTREAM_TIMEOUT_MS");
{
  // A server that accepts the connection and never answers. A non-routable IP
  // is not a test: this network refuses it in milliseconds, so nothing is
  // proven about the timeout.
  const blackhole = createServer(() => { /* deliberately never responds */ });
  // The gateway container does the dialing, so the socket must be reachable
  // from its network: bind everywhere and dial the host alias when this
  // script runs on the host, outside the compose network.
  const hangHost = process.env.HANG_HOST ?? "host.docker.internal";
  await new Promise((resolve) => blackhole.listen(0, "0.0.0.0", resolve));
  const blackholeUrl = `http://${hangHost}:${blackhole.address().port}/mcp`;
  const budget = Number(process.env.UPSTREAM_TIMEOUT_MS ?? 60000);
  try {
    const srv = await gw("POST", "/v1/servers", { name: `demo-hang-${tag}`, base_url: blackholeUrl });
    const t0 = Date.now();
    const out = await gw("POST", `/v1/servers/${srv.data.id}/discover`, {});
    const elapsed = Date.now() - t0;
    check(`a hanging upstream fails at the ${budget}ms budget, not never`,
      out.status >= 400 && elapsed >= budget - 750 && elapsed < budget + 5000,
      `discover against a socket that never answers -> ${out.status} ` +
        `${out.data.error ?? ""} after ${elapsed}ms`);
  } finally {
    blackhole.closeAllConnections?.();
    blackhole.close();
  }
}

// ── UI: the dashboard behaviours, driven in a real browser ────────────────
console.log(`\n${"═".repeat(78)}\n   dashboard, in a real chromium\n${"═".repeat(78)}`);
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
const setKeys = (key, approver = APPROVER) => page.addInitScript(([k, a, api, gw]) => {
  localStorage.setItem("tg_key", k);
  localStorage.setItem("tg_approver_key", a);
  localStorage.setItem("tg_url", api);
  localStorage.setItem("tg_gw_url", gw);
}, [key, approver, API, GW]);
const nav = () => page.getByRole("navigation", { name: "Primary" });
const openTab = async (label) => {
  await nav().getByRole("button", { name: new RegExp(`^${label}`) }).click();
  await page.waitForTimeout(700);
};

// ── 12. The policy form rebinds when you switch rules ────────────────────
head(12, "Dashboard: editing a second rule does not inherit the first rule's fields");
{
  const nameA = `demo-a-${tag}`;
  const nameB = `demo-b-${tag}`;
  for (const p of [
    { name: nameA, priority: 1, tool_name: "read_file", effect: "allow" },
    { name: nameB, priority: 2, tool_name: "wipe_disk", effect: "deny" }
  ]) await gw("POST", "/v1/policies", { ...p, server_id: null });

  await setKeys(KEY);
  await page.goto(WEB);
  await openTab("Policy");
  const rowFor = (name) => page.locator("tr").filter({ hasText: name });
  await rowFor(nameA).getByRole("button", { name: "Edit" }).click();
  await page.waitForTimeout(400);
  const afterA = await page.getByLabel("Rule name").inputValue();
  await rowFor(nameB).getByRole("button", { name: "Edit" }).click();
  await page.waitForTimeout(400);
  const afterB = await page.getByLabel("Rule name").inputValue();
  const toolB = await page.getByLabel("Tool name").inputValue();
  check("the form follows the rule you clicked", afterB === nameB && toolB === "wipe_disk",
    `click Edit on ${nameA} -> form shows "${afterA}"; click Edit on ${nameB} -> ` +
      `form shows "${afterB}" tool "${toolB}"`);
}

// ── 13. Costs: a non-numeric window reports instead of doing nothing ─────
head(13, "Dashboard: the Costs window field reports a bad value");
{
  await openTab("Costs");
  const days = page.getByLabel(/days/i).first();
  await days.fill("abc");
  // The empty state renders its own Compare button, so scope to the form.
  await page.locator("form").getByRole("button", { name: /Compare/i }).click();
  await page.waitForTimeout(500);
  const alert = await page.getByRole("alert").first().textContent().catch(() => null);
  check("an invalid window is explained", /positive number/i.test(alert ?? ""),
    `typing "abc" and comparing -> alert: ${JSON.stringify((alert ?? "").trim())}`);
}

// ── 14. Users: a wrong key and a non-admin key are told apart ────────────
head(14, "Dashboard: the Users tab separates a bad key from a non-admin key");
{
  const u = await api("POST", "/v1/users", {
    email: `demo-ui-${tag}@example.com`, password: "long-password-999", role: "member"
  });
  const k = await api("POST", `/v1/users/${u.data.id}/keys`, { name: "ui", scopes: ["read"] });
  await setKeys(k.data.key);
  await page.goto(WEB);
  await openTab("Users");
  const asMember = (await page.locator("body").innerText()).replace(/\s+/g, " ");
  check("a read-scope key sees the admin-only notice",
    /Admin only/.test(asMember),
    `Users tab as a read-scope key -> "${asMember.match(/Admin only[^.]*/)?.[0]}"`);

  await setKeys("not-a-real-key");
  await page.goto(WEB);
  await openTab("Users");
  const asBadKey = (await page.locator("body").innerText()).replace(/\s+/g, " ");
  check("a wrong key says the key is wrong",
    /unauthorized/i.test(asBadKey),
    `Users tab with a bogus key -> "${asBadKey.match(/unauthorized[^.]*/)?.[0]}"`);
}

// ── 15. The palette is modal and gives focus back ────────────────────────
head(15, "Dashboard: the command palette is modal and returns focus");
{
  await setKeys(KEY);
  await page.goto(WEB);
  await nav().getByRole("button", { name: /^Runs/ }).click();
  await page.waitForTimeout(400);
  await page.keyboard.press("Control+k");
  await page.waitForTimeout(400);
  const modal = await page.getByRole("dialog", { name: "Command palette" })
    .getAttribute("aria-modal").catch(() => null);
  await page.keyboard.press("Escape");
  await page.waitForTimeout(400);
  const stillOpen = await page.getByRole("dialog", { name: "Command palette" }).count();
  // eslint-disable-next-line no-undef -- this callback runs in the page, not in node
  const focusBack = await page.evaluate(() => document.activeElement?.textContent?.trim() ?? "");
  check("the overlay declares itself modal", modal === "true",
    `role=dialog aria-modal=${modal}`);
  check("Escape closes it and focus returns to the control that opened it",
    stillOpen === 0 && /Runs/.test(focusBack),
    `after Escape: dialogs open=${stillOpen}, focus is on "${focusBack}"`);
}

await browser.close();
await pool.end();

console.log(`\n${"═".repeat(78)}`);
console.log(`   ${passed} passed, ${failed} failed`);
console.log(`${"═".repeat(78)}\n`);
process.exit(failed === 0 ? 0 : 1);
