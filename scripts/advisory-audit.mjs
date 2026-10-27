#!/usr/bin/env node
// A20: production advisory gate with an explicit, reviewable accept list.
// `pnpm audit` alone fails on any high advisory and offers no way to record a
// reviewed exception on pnpm 9 (GHSA-based ignores need pnpm >= 10.11). This
// wrapper keeps the fail-closed behaviour and puts the accepted advisories,
// with their reasons and revisit conditions, in a file a reviewer can see.
// An entry is a time-box, not a pardon: it is removed when the dependency
// moves to a patched version.
import { spawnSync } from "node:child_process";

const ACCEPTED = [
  // Empty: the zod 3 time-box (GHSA-mrhx-c7xc-m3w5) was retired by the zod
  // 4.6.7 migration. New entries need a reason and a revisit condition.
];

const pnpm = "pnpm";
// shell: true is required on Windows (spawnSync refuses .cmd shims without
// it) and harmless on the CI bash runner. The arguments carry no characters a
// shell would reinterpret.
const audit = spawnSync(
  `${pnpm} audit --prod --audit-level high --json`,
  { encoding: "utf8", shell: true }
);

if (audit.error) {
  console.error(`FAIL could not run pnpm audit: ${audit.error.message}`);
  process.exit(1);
}

let report;
try {
  report = JSON.parse(audit.stdout);
} catch {
  console.error("FAIL pnpm audit did not return JSON:");
  console.error(audit.stderr || audit.stdout || "(no output)");
  process.exit(1);
}

const advisories = Object.values(report.advisories ?? {});
const accepted = [];
const blocking = [];
for (const a of advisories) {
  const entry = ACCEPTED.find((x) => (a.url ?? "").endsWith(x.ghsa));
  if (entry) accepted.push({ advisory: a, entry });
  else blocking.push(a);
}

if (accepted.length > 0) {
  console.log("accepted advisories (reviewed, time-boxed):");
  for (const { advisory, entry } of accepted) {
    console.log(`  ${entry.ghsa} ${advisory.module_name}@${advisory.findings?.[0]?.version ?? "?"} [${advisory.severity}]`);
    console.log(`    reason:  ${entry.reason}`);
    console.log(`    revisit: ${entry.revisit}`);
  }
}

if (blocking.length > 0) {
  console.error("blocking advisories:");
  for (const a of blocking) {
    console.error(`  ${(a.url ?? "").split("/").pop()} ${a.module_name}@${a.findings?.[0]?.version ?? "?"} [${a.severity}] ${a.title ?? ""}`);
    console.error(`    ${(a.url ?? "")}`);
  }
  console.error(`FAIL ${blocking.length} unaccepted high+ advisory(ies) in production dependencies`);
  process.exit(1);
}

console.log(`PASS ${advisories.length - blocking.length} accepted, ${blocking.length} blocking`);
