#!/usr/bin/env node
// Captures the dashboard screenshots the README links to, from the current
// build, against a running stack. Requires Playwright's browsers:
//
//   pnpm exec playwright install chromium
//   node apps/api/dist/index.js & node apps/api/dist/gateway.js &
//   pnpm --filter @traceguard/web preview --port 5173 &
//   node scripts/screenshots.mjs
//
// Writes docs/images/*.png. The point of committing this is that the README's
// screenshots can be regenerated instead of aging into a claim about a build
// nobody can identify.

import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";

const WEB = process.env.WEB ?? "http://localhost:5173";
const API = process.env.API ?? "http://localhost:8090";
const GW = process.env.GW ?? "http://localhost:8091";
const KEY = process.env.KEY ?? process.env.API_KEY ?? "dev_key_change_me";
const APPROVER = process.env.APPROVER_KEY ?? "dev_approver_change_me";

const out = join(dirname(fileURLToPath(import.meta.url)), "..", "docs", "images");
mkdirSync(out, { recursive: true });

// A run with usage and a failed span, so the screenshots are not of an empty
// install.
async function seed() {
  const headers = { Authorization: `Bearer ${KEY}`, "Content-Type": "application/json" };
  const runId = crypto.randomUUID();
  const span = (over) => ({
    schema_version: "1", event_id: `shot-${crypto.randomUUID()}`,
    agent_name: "docs-agent", run_id: runId, span_id: crypto.randomUUID(),
    parent_span_id: null, timestamp: new Date().toISOString(), attributes: {}, ...over
  });
  const events = [
    span({ event_type: "run.started" }),
    span({ event_type: "model.request", provider: "demo", model: "demo-1",
      input_tokens: 1200, output_tokens: 240, usage_source: "provider_reported",
      duration_ms: 842, attributes: { note: "no prompt text stored by default" } }),
    span({ event_type: "tool.invocation", status: "failed", error_type: "TimeoutError",
      duration_ms: 1500, attributes: { tool: "read_file" } }),
    span({ event_type: "run.completed", status: "failed", error_type: "TimeoutError" })
  ];
  const res = await fetch(`${API}/v1/ingest/events`, {
    method: "POST", headers, body: JSON.stringify({ events })
  });
  if (!res.ok) throw new Error(`seed failed: ${res.status} ${await res.text()}`);
  return runId;
}

const runId = await seed();

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
await page.addInitScript(([key, approver, api, gw]) => {
  localStorage.setItem("tg_key", key);
  localStorage.setItem("tg_approver_key", approver);
  localStorage.setItem("tg_url", api);
  localStorage.setItem("tg_gw_url", gw);
}, [KEY, APPROVER, API, GW]);

const nav = page.getByRole("navigation", { name: "Primary" });
const shot = async (name) => {
  await page.screenshot({ path: join(out, name), fullPage: false });
  console.log(`docs/images/${name}`);
};

await page.goto(WEB);
await page.getByText("Total runs").first().waitFor({ timeout: 20_000 });

// The router's default tab is Runs, so name the tabs explicitly rather than
// screenshotting whatever is already on screen.
const openTab = async (label, file) => {
  await nav.getByRole("button", { name: new RegExp(`^${label}`) }).click();
  await page.waitForTimeout(900);
  await shot(file);
};

await openTab("Overview", "overview.png");
await openTab("Runs", "runs.png");

// The trace of the seeded run, opened by its id.
await page.goto(`${WEB}/#/runs/${runId}`);
await page.waitForTimeout(1200);
await shot("trace.png");

await openTab("Costs", "costs.png");
await openTab("Policy", "policy.png");
await openTab("Evaluations", "evaluations.png");

await browser.close();
console.log(`\n${out}`);
