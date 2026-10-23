#!/usr/bin/env node
// §21.5: the example that drives the gateway through the certified client
// shim. The shim owns the hard parts of the approval contract — one stable
// logical_request_id per logical call, a fresh JSON-RPC id per attempt,
// bounded backoff while a human decides, and a hard stop the moment an
// outcome is ambiguous. This script is deliberately thin so the contract,
// not the demo, is what you read.
//
// Prerequisites (see README.md in this directory):
//   1. the compose stack is up and the gateway has a pinned server whose
//      tool is covered by a require_approval policy;
//   2. the shim package is built (npm run build -w @traceguard/mcp-client-shim).
//
// Usage:
//   TRACEGUARD_TOOL=<alias>__<tool> node examples/certified-agent/run.mjs
//   TRACEGUARD_TOOL=<alias>__wipe_disk TRACEGUARD_ARGS='{"target":"/tmp/x"}' ...

import {
  ApprovalClientRequiredError,
  ApprovalPendingError,
  ApprovalTerminalError,
  CertifiedClient,
  OutcomeUnknownError
} from "../../packages/mcp-client-shim/dist/index.js";

const url = process.env.TRACEGUARD_URL ?? "http://localhost:8091/mcp";
const token = process.env.TRACEGUARD_API_KEY ?? "dev_key_change_me";
const tool = process.env.TRACEGUARD_TOOL;
const args = JSON.parse(process.env.TRACEGUARD_ARGS ?? "{}");

if (!tool) {
  console.error("Set TRACEGUARD_TOOL to the namespaced tool name, e.g.");
  console.error("  TRACEGUARD_TOOL=mock-tools-1__read_file TRACEGUARD_ARGS='{\"path\":\"/approval-needed.txt\"}' \\");
  console.error("    node examples/certified-agent/run.mjs");
  process.exit(2);
}

const client = new CertifiedClient({ url, authProfile: "development", token });

console.log(`calling ${tool} through ${url}`);
try {
  const result = await client.callTool(tool, args);
  console.log("executed once; upstream answered:");
  console.log(JSON.stringify(result, null, 2));
} catch (err) {
  if (err instanceof ApprovalPendingError) {
    // The approval is still pending past the caller's deadline. The action
    // has NOT executed; retrying the same logical call later is safe.
    console.error("still pending after the deadline; retry the same logical call once a human decides");
  } else if (err instanceof ApprovalClientRequiredError) {
    // The policy wants approval but no logical id was carried (set LOOSE).
    console.error("this tool needs the approval-aware client (the shim sets the logical id)");
  } else if (err instanceof ApprovalTerminalError) {
    console.error("the approval ended in a terminal state without execution (rejected/expired/invalidated)");
  } else if (err instanceof OutcomeUnknownError) {
    // Never resubmit after this: the upstream action may have executed.
    console.error("ambiguous outcome — the upstream action may have executed; reconcile, do not retry");
  } else {
    throw err;
  }
  process.exitCode = 1;
}
