#!/usr/bin/env node
// Dependency and license review for the pinned pnpm workspace (§20).
//
// Reads the installed tree that `pnpm install --frozen-lockfile` produced,
// classifies every package as production or development, and checks its
// declared SPDX license against the allowlist in docs/dependencies.md.
// Production violations fail the run; development-only violations are reported
// as warnings because they never ship in an image or a release artifact.
//
//   node scripts/dependency-audit.mjs
//   node scripts/dependency-audit.mjs --json
//   node scripts/dependency-audit.mjs --sbom sbom.cdx.json
//
// The CycloneDX output is a build artifact; sbom.cdx.json is gitignored.

import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";

// Permissive licenses accepted for shipped dependencies. MPL-2.0 is allowed
// for unmodified dependencies (file-level copyleft); do not vendor or modify
// an MPL-covered package without recording it in docs/dependencies.md.
const ALLOWED = new Set([
  "0BSD",
  "Apache-2.0",
  "Artistic-2.0",
  "BSD",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "BlueOak-1.0.0",
  "CC0-1.0",
  "ISC",
  "MIT",
  "MIT-0",
  "MPL-2.0",
  "Python-2.0",
  "Unlicense",
  "WTFPL",
  "Zlib",
]);

// Strong copyleft, source-available, or no-license markers. Any package whose
// expression cannot be satisfied by the allowlist is a violation; these markers
// only improve the explanation.
const DENIED_MARKERS = [
  { pattern: /AGPL/i, label: "AGPL" },
  { pattern: /\bGPL/i, label: "GPL" },
  { pattern: /SSPL/i, label: "SSPL" },
  { pattern: /BUSL|Business Source/i, label: "BUSL" },
  { pattern: /CC-BY-NC/i, label: "CC-BY-NC" },
  { pattern: /Commons Clause/i, label: "Commons Clause" },
  { pattern: /UNLICENSED/i, label: "UNLICENSED" },
  { pattern: /proprietary/i, label: "proprietary" },
];

function allowedTerm(term) {
  let value = term.trim().replace(/^\(+|\)+$/g, "");
  const withIndex = value.search(/\s+WITH\s+/i);
  if (withIndex >= 0) value = value.slice(0, withIndex);
  value = value.replace(/\*$/, "").trim();
  return ALLOWED.has(value);
}

// SPDX expressions are evaluated conservatively: an OR branch passes when at
// least one side is allowed (the distributor may choose that side); an AND
// branch passes only when every side is allowed.
export function licenseAllowed(expression) {
  if (!expression) return false;
  const value = expression.trim().replace(/^\(+|\)+$/g, "");
  return value.split(/\s+OR\s+/i).some((branch) =>
    branch.split(/\s+AND\s+/i).every(allowedTerm),
  );
}

function classify(expression) {
  if (!expression) return "missing";
  if (licenseAllowed(expression)) return "allowed";
  const denied = DENIED_MARKERS.find((m) => m.pattern.test(expression));
  return denied ? `denied (${denied.label})` : "not-in-allowlist";
}

function readInstalledLicenses(prodOnly) {
  const command = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
  const args = ["licenses", "list", "--json", ...(prodOnly ? ["--prod"] : [])];
  return JSON.parse(
    execFileSync(command, args, {
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
      shell: process.platform === "win32",
    }),
  );
}

export function collect() {
  const all = readInstalledLicenses(false);
  const production = readInstalledLicenses(true);
  const productionRefs = new Set();
  for (const entries of Object.values(production)) {
    for (const entry of entries) {
      for (const version of entry.versions) productionRefs.add(`${entry.name}@${version}`);
    }
  }

  const found = [];
  for (const [licenseGroup, entries] of Object.entries(all)) {
    for (const entry of entries) {
      for (const version of entry.versions) {
        found.push({
          name: entry.name,
          version,
          license: entry.license ?? (licenseGroup === "Unknown" ? null : licenseGroup),
          dev: !productionRefs.has(`${entry.name}@${version}`),
          path: entry.paths?.[0] ?? "",
        });
      }
    }
  }
  return found;
}

function purl(name, version) {
  const encoded = name.startsWith("@") ? `%40${name.slice(1)}` : name;
  return `pkg:npm/${encoded}@${version}`;
}

export function buildSbom(components) {
  const merged = new Map();
  for (const c of components) {
    const ref = purl(c.name, c.version);
    const existing = merged.get(ref);
    if (existing) {
      if (!c.dev) existing.scope = "required";
      continue;
    }
    const entry = {
      type: "library",
      "bom-ref": ref,
      name: c.name,
      version: c.version,
      scope: c.dev ? "excluded" : "required",
    };
    if (c.license) {
      const isSimple = /^[A-Za-z0-9.+-]+$/.test(c.license) && !/\s/.test(c.license);
      entry.licenses = [isSimple ? { license: { id: c.license } } : { expression: c.license }];
    }
    merged.set(ref, entry);
  }
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: "TraceGuard", name: "dependency-audit", version: "0.1.0" }],
      component: { type: "application", name: "traceguard", version: "0.1.0" },
    },
    components: [...merged.values()].sort((a, b) => a["bom-ref"].localeCompare(b["bom-ref"])),
  };
}

function main(argv) {
  const components = collect();
  const prod = components.filter((c) => !c.dev);
  const dev = components.filter((c) => c.dev);
  const violations = [];
  const warnings = [];

  for (const c of components) {
    const verdict = classify(c.license);
    if (verdict === "allowed") continue;
    const row = { ...c, verdict };
    if (c.dev) warnings.push(row);
    else violations.push(row);
  }

  if (argv.includes("--sbom")) {
    const out = argv[argv.indexOf("--sbom") + 1];
    if (!out || out.startsWith("--")) {
      console.error("usage: dependency-audit.mjs --sbom <path>");
      process.exit(2);
    }
    writeFileSync(out, `${JSON.stringify(buildSbom(components), null, 2)}\n`);
    console.log(`wrote CycloneDX SBOM: ${out} (${components.length} packages)`);
  }

  if (argv.includes("--json")) {
    console.log(JSON.stringify({ totals: { all: components.length, production: prod.length, development: dev.length }, violations, warnings }, null, 2));
    process.exit(violations.length > 0 ? 1 : 0);
  }

  const licenseCounts = (rows) => {
    const counts = new Map();
    for (const row of rows) counts.set(row.license ?? "(missing)", (counts.get(row.license ?? "(missing)") ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  };

  console.log(`Scanned ${components.length} packages from the installed pnpm workspace`);
  console.log(`  production: ${prod.length}`);
  console.log(`  development: ${dev.length}`);
  console.log("Production licenses:");
  for (const [license, count] of licenseCounts(prod)) console.log(`  ${String(count).padStart(4)}  ${license}`);

  if (warnings.length > 0) {
    console.log(`\nDevelopment warnings (not shipped): ${warnings.length}`);
    for (const w of warnings) console.log(`  ${w.name}@${w.version} — ${w.license ?? "(no license field)"} — ${w.verdict}`);
  }

  if (violations.length > 0) {
    console.error(`\nFAIL: ${violations.length} production package(s) outside the allowlist:`);
    for (const v of violations) console.error(`  ${v.name}@${v.version} — ${v.license ?? "(no license field)"} — ${v.verdict}`);
    console.error("\nReview docs/dependencies.md before adding a license to the allowlist.");
    process.exit(1);
  }

  console.log(`\nPASS: every production dependency is within the license allowlist (${warnings.length} development warning(s)).`);
}

if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, "/")}` || process.argv[1]?.endsWith("dependency-audit.mjs")) {
  main(process.argv.slice(2));
}
