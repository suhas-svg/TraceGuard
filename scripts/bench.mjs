#!/usr/bin/env node
// Percentile benchmark for the paths the spec names as targets (§14):
// ingestion-to-API visibility, dashboard queries, and gateway policy overhead.
// Prints a table you can paste into docs/PERFORMANCE.md, and it records the
// hardware and the row counts so two runs are comparable.
//
//   node scripts/bench.mjs                     # defaults to the compose ports
//   BASE=http://localhost:8090 GW=http://localhost:8091 KEY=... node scripts/bench.mjs
//
// Warm the database first (the numbers below the table's first row are cold
// starts, which are not what the targets are about).

const BASE = process.env.BASE ?? "http://localhost:8090";
const GW = process.env.GW ?? "http://localhost:8091";
const KEY = process.env.KEY ?? process.env.API_KEY ?? "dev_key_change_me";
const N = Number(process.env.N ?? 50);

const auth = { Authorization: `Bearer ${KEY}` };

async function timed(label, run, n = N) {
  const samples = [];
  for (let i = 0; i < n; i++) {
    const t0 = performance.now();
    try {
      await run(i);
    } catch (err) {
      console.error(`  ${label}: request ${i} failed: ${err.message}`);
    }
    samples.push(performance.now() - t0);
  }
  samples.sort((a, b) => a - b);
  const at = (p) => samples[Math.min(samples.length - 1, Math.floor(p * samples.length))];
  const mean = samples.reduce((a, b) => a + b, 0) / samples.length;
  return { label, n: samples.length, p50: at(0.5), p95: at(0.95), max: samples.at(-1), mean };
}

const event = (i) => ({
  schema_version: "1",
  event_id: `bench-${Date.now()}-${i}-${Math.random().toString(36).slice(2)}`,
  agent_name: "bench-agent",
  run_id: crypto.randomUUID(),
  span_id: crypto.randomUUID(),
  event_type: "run.started",
  timestamp: new Date().toISOString(),
  attributes: {}
});

async function counts() {
  try {
    const res = await fetch(`${BASE}/v1/overview`, { headers: auth });
    if (!res.ok) return "unavailable";
    const o = await res.json();
    return `runs=${o.runs.total} spans_with_usage=${o.tokens.spans_with_usage}`;
  } catch {
    return "unavailable";
  }
}

// The spec's gateway target is the policy DECISION on a warmed call, so measure
// a real call through the gateway against the mock upstream: register it,
// discover it, allow the tool, then time the proxied call. Returns null when the
// mock upstream is not running, and the row is reported as skipped rather than
// silently measuring something easier.
const MOCK = process.env.MOCK ?? "http://127.0.0.1:8092/mcp";

async function prepareGatewayCall() {
  const post = (path, body) => fetch(`${GW}${path}`, {
    method: "POST",
    headers: { ...auth, "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  try {
    const reg = await post("/v1/servers", { name: `bench-${Date.now()}`, base_url: MOCK });
    if (!reg.ok) return null;
    const serverId = (await reg.json()).id;
    const disc = await post(`/v1/servers/${serverId}/discover`, {});
    if (!disc.ok) return null;
    const tool = (await disc.json()).tools?.[0]?.tool_name;
    if (!tool) return null;
    const pol = await post("/v1/policies", {
      name: `bench-allow-${Date.now()}`, priority: 1, server_id: serverId,
      tool_name: tool, effect: "allow"
    });
    if (!pol.ok) return null;
    return { serverId, tool };
  } catch {
    return null;
  }
}

const gwCall = await prepareGatewayCall();

// Section 14's target is the policy decision, and the gateway records how long
// each one took. Read it back, so the figure below is measured rather than an
// upper bound inferred from the whole call.
async function gatewayOverhead() {
  if (!process.env.DATABASE_URL) return null;
  try {
    const { default: pg } = await import("pg");
    const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
    await client.connect();
    const res = await client.query(
      `SELECT count(*) AS n,
              percentile_cont(0.5) WITHIN GROUP (ORDER BY overhead_ms) AS p50,
              percentile_cont(0.95) WITHIN GROUP (ORDER BY overhead_ms) AS p95
         FROM policy_decisions
        WHERE overhead_ms IS NOT NULL AND timestamp > now() - interval '10 minutes'`);
    await client.end();
    const r = res.rows[0];
    if (!Number(r.n)) return null;
    return { n: Number(r.n), p50: Number(r.p50), p95: Number(r.p95) };
  } catch {
    return null;
  }
}

const rows = [];
rows.push(await timed("GET /healthz", () => fetch(`${BASE}/healthz`)));
rows.push(await timed("GET /v1/overview", () => fetch(`${BASE}/v1/overview`, { headers: auth })));
rows.push(await timed("GET /v1/runs?limit=50", () => fetch(`${BASE}/v1/runs?limit=50`, { headers: auth })));
rows.push(await timed("POST /v1/ingest/events (1 event)", (i) =>
  fetch(`${BASE}/v1/ingest/events`, {
    method: "POST", headers: { ...auth, "Content-Type": "application/json" },
    body: JSON.stringify({ events: [event(i)] })
  })));
if (gwCall) {
  // The whole call, upstream round trip included. This is NOT the §14 target
  // (which excludes upstream execution); the overhead line below is.
  rows.push(await timed("POST /v1/gateway/tools/call (incl. upstream)", (i) =>
    fetch(`${GW}/v1/gateway/tools/call`, {
      method: "POST", headers: { ...auth, "Content-Type": "application/json" },
      body: JSON.stringify({
        server_id: gwCall.serverId, tool: gwCall.tool,
        arguments: { text: `bench-${i}` }, caller: "bench-agent"
      })
    })));
} else {
  rows.push({ label: "POST /v1/gateway/tools/call", skipped: true });
}

const pad = (s, w) => String(s).padEnd(w);
const num = (v) => `${v.toFixed(0)}ms`;
console.log(`\nhost=${process.platform}/${process.arch} node=${process.version} n=${N}`);
console.log(`db=${await counts()}\n`);
console.log(pad("path", 34) + pad("n", 6) + pad("p50", 9) + pad("p95", 9) + pad("max", 9) + "mean");
console.log("-".repeat(76));
for (const r of rows) {
  if (r.skipped) {
    console.log(pad(r.label, 34) + "skipped (start examples/mock-tools on 8092)");
    continue;
  }
  console.log(pad(r.label, 34) + pad(r.n, 6) + pad(num(r.p50), 9) + pad(num(r.p95), 9) +
    pad(num(r.max), 9) + num(r.mean));
}
console.log(`\nSpec §14 targets: dashboard queries p95 < 500ms, ingest-to-visible p95 < 3s,`);
console.log(`gateway policy overhead p95 < 100ms (excluding upstream execution and human`);
console.log(`approval).`);
const ovh = await gatewayOverhead();
if (ovh) {
  console.log(`\n§14 gateway policy overhead, measured from policy_decisions.overhead_ms`);
  console.log(`(decisions in the last 10 minutes): n=${ovh.n} p50=${num(ovh.p50)} p95=${num(ovh.p95)}`);
} else {
  console.log(`\nGateway policy overhead: not measured (set DATABASE_URL to read`);
  console.log(`policy_decisions.overhead_ms, or run the gateway first).`);
}
console.log(`\nCold starts miss all three; warm the database and rerun before quoting`);
console.log(`any of these numbers.\n`);
