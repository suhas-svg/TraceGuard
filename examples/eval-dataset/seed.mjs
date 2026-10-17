#!/usr/bin/env node
// Loads suite.json into TraceGuard, replays it once per configured run, and
// prints the comparison. This is the §19 deliverable "an evaluation dataset and
// replay scenario": a dataset you can read, and a command that reproduces the
// comparison rather than describing it.
//
//   node examples/eval-dataset/seed.mjs
//   BASE=http://localhost:8090 KEY=... node examples/eval-dataset/seed.mjs
//
// Idempotent in the sense that matters: suites version on creation, so running
// it twice makes a second version of the same suite rather than editing the
// first one. Comparisons always name explicit run ids.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const BASE = (process.env.BASE ?? "http://localhost:8090").replace(/\/$/, "");
const KEY = process.env.KEY ?? process.env.API_KEY ?? "dev_key_change_me";
const here = dirname(fileURLToPath(import.meta.url));
const dataset = JSON.parse(readFileSync(join(here, "suite.json"), "utf8"));

async function call(method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { Authorization: `Bearer ${KEY}`, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) {
    throw new Error(`${method} ${path} -> ${res.status} ${JSON.stringify(data)}`);
  }
  return data;
}

const suite = await call("POST", "/v1/evaluations/suites", dataset.suite);
console.log(`suite ${suite.name} v${suite.version} (${suite.id})`);

for (const kase of dataset.cases) {
  await call("POST", `/v1/evaluations/suites/${suite.id}/cases`, kase);
}
console.log(`  ${dataset.cases.length} cases added; the suite locks on first run`);

const started = [];
for (const run of dataset.runs) {
  const { label, ...config } = run;
  const out = await call("POST", `/v1/evaluations/suites/${suite.id}/runs`, config);
  const passed = out.results.filter((r) => r.passed).length;
  started.push({ label, id: out.eval_run.id, passed, total: out.results.length, stopped: out.stopped });
  console.log(`  run "${label}" -> ${out.eval_run.id}  ${passed}/${out.results.length} passed` +
    (out.stopped ? `  (stopped: ${out.stopped})` : ""));
}

if (started.length < 2) {
  console.log("\nonly one run configured; nothing to compare");
  process.exit(0);
}

const ids = started.map((s) => s.id).join(",");
const cmp = await call("GET", `/v1/evaluations/runs/compare?ids=${ids}`);

const pad = (s, w) => String(s).padEnd(w);
console.log(`\n${pad("config", 12)}${pad("pass", 8)}${pad("latency p50/mean", 20)}${pad("cost (micro)", 14)}violations`);
console.log("-".repeat(70));
for (const r of cmp.runs) {
  const label = started.find((s) => s.id === r.eval_run_id)?.label ?? r.config_fingerprint;
  const rate = r.pass_rate === null ? "n/a" : `${Math.round(r.pass_rate * 100)}%`;
  const lat = r.latency_ms ? `${r.latency_ms.min}/${r.latency_ms.mean}ms` : "n/a";
  const cost = r.cost_micro === null ? "unknown"
    : `${r.cost_micro}${r.cost_partial ? " (partial)" : ""}`;
  // null violations means the spans are gone, which is not the same as zero.
  const viol = r.violations === null ? "unknown" : String(r.violations);
  console.log(pad(label, 12) + pad(rate, 8) + pad(lat, 20) + pad(cost, 14) + viol);
}
console.log(`\nOpen the Evaluations tab to see the same comparison, or read one case's`);
console.log(`trace by its agent run id: GET /v1/evaluations/runs/${started[0].id}\n`);
