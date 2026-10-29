#!/usr/bin/env node
// Periodic maintenance sweeps (spec §11.3, §11.4, §12.3).
//
// The API exposes these as cron endpoints rather than in-process schedulers
// (docs/operations.md). This script is the scheduler for the Compose
// reference: it calls each endpoint once per interval and keeps going when one
// of them fails, because a stuck budget sweep must not stop the orphan sweep.
//
//   node scripts/maintenance.mjs            # loop forever
//   node scripts/maintenance.mjs --once     # one pass, non-zero exit on failure
//
// Environment:
//   TRACEGUARD_URL                    API base URL (default http://localhost:8090)
//   MAINTENANCE_TOKEN | API_KEY       bearer credential for the admin routes
//   MAINTENANCE_INTERVAL_SECONDS      pause between passes (default 300, min 30)
//   MAINTENANCE_STALE_SECONDS         orphan threshold (default 900 = 15 min)

const base = (process.env.TRACEGUARD_URL ?? "http://localhost:8090").replace(/\/+$/, "");
const token = process.env.MAINTENANCE_TOKEN || process.env.API_KEY;
const interval = Math.max(Number(process.env.MAINTENANCE_INTERVAL_SECONDS ?? 300), 30);
const stale = Math.max(Number(process.env.MAINTENANCE_STALE_SECONDS ?? 900), 60);
const once = process.argv.includes("--once");

if (!token) {
  console.error("maintenance: set MAINTENANCE_TOKEN or API_KEY");
  process.exit(2);
}

const sweeps = [
  ["finalize-stale-runs", `/v1/admin/finalize-stale-runs?older_than_seconds=${stale}`],
  ["finalize-orphan-spans", `/v1/admin/finalize-orphan-spans?older_than_seconds=${stale}`],
  ["sweep-budget-holds", "/v1/admin/sweep-budget-holds"],
  ["retention-run", "/v1/retention/run"],
];

async function pass() {
  let failed = 0;
  for (const [name, path] of sweeps) {
    try {
      const res = await fetch(base + path, {
        method: "POST",
        headers: { authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(60_000),
      });
      const text = await res.text();
      // No retention rules configured is a state, not a fault.
      if (res.ok || (name === "retention-run" && text.includes("no_retention_rules"))) {
        console.log(`maintenance: ${name} ok`);
      } else {
        failed++;
        console.error(`maintenance: ${name} -> ${res.status} ${text.slice(0, 200)}`);
      }
    } catch (err) {
      failed++;
      console.error(`maintenance: ${name} failed: ${err instanceof Error ? err.message : err}`);
    }
  }
  return failed;
}

if (once) {
  process.exit((await pass()) === 0 ? 0 : 1);
}
for (;;) {
  await pass();
  await new Promise((r) => setTimeout(r, interval * 1000));
}
