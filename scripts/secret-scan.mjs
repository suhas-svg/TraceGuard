#!/usr/bin/env node
// NFR-006: fail the build if a tracked file looks like it carries a live
// credential. The patterns mirror the ones the ingest redactor knows about
// (apps/api/src/redact.ts) plus the common provider formats we would never
// want in a commit. This is a floor, not a replacement for an operator's
// scanning: it runs on every PR without network access or an extra action.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

const PATTERNS = [
  { name: "private key block", re: /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/ },
  { name: "AWS access key id", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "GitHub token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { name: "Slack token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: "Stripe secret key", re: /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/ },
  { name: "provider API key", re: /\bsk-[A-Za-z0-9]{32,}\b/ },
  { name: "JWT", re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/ }
];

// Lockfiles carry hashes, not credentials. Binary formats are skipped because
// a byte match there would be meaningless (and slow to stringify).
const SKIP = /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$/;
const BINARY = /\.(png|jpe?g|gif|ico|webp|pdf|woff2?|ttf|otf|zip|gz|tgz|mp4|mp3|wasm)$/i;

const listed = spawnSync("git", ["ls-files", "-z"], { encoding: "buffer" });
if (listed.status !== 0) {
  console.error("secret scan: git ls-files failed (run inside the repository)");
  process.exit(2);
}
const files = listed.stdout.toString("utf8").split("\0").filter(Boolean);

let findings = 0;
let scanned = 0;
for (const file of files) {
  if (SKIP.test(file) || BINARY.test(file)) continue;
  let text;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    continue;
  }
  if (text.includes("\u0000")) continue;
  scanned += 1;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    for (const pattern of PATTERNS) {
      const match = pattern.re.exec(lines[i]);
      if (match) {
        findings += 1;
        console.error(`${file}:${i + 1}: ${pattern.name}: ${match[0].slice(0, 12)}...`);
      }
    }
  }
}

console.log(`secret scan: ${scanned} tracked files, ${findings} finding(s)`);
process.exit(findings === 0 ? 0 : 1);
