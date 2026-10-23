# Certified agent (approval-retry shim) — §21.5 demo

`run.mjs` drives the gateway through the certified client shim
(`@traceguard/mcp-client-shim`, profile `approval-client-profile: 1`). It is the
demo that shows the tool-call contract end to end: the agent asks once, the
gateway may hold the call for a human, and the agent retries the **same
logical call** until it executes exactly once — or stops for good when the
outcome is unknown.

The other examples (`examples/demo-agent`, `examples/demo-agent-ts`) show the
telemetry side; this one shows enforcement-side client behaviour only.

## Prerequisites

1. Compose stack up, shim built:

   ```bash
   docker compose up -d
   pnpm --filter @traceguard/mcp-client-shim build
   ```

2. A registered, pinned server and a `require_approval` policy for the tool
   you want to exercise. The quickest path is the reference flow in
   `examples/reference-policy/README.md`; the e2e suite
   (`tests/e2e/scenarios.spec.ts`) automates exactly this setup.

3. A human at the control listener (`:8093`, approver key) to decide the
   request when it goes on hold.

## Run

```bash
TRACEGUARD_TOOL=mock-tools-1__read_file \
TRACEGUARD_ARGS='{"path":"/approval-needed.txt"}' \
node examples/certified-agent/run.mjs
```

Environment: `TRACEGUARD_URL` (default `http://localhost:8091/mcp`),
`TRACEGUARD_API_KEY` (default the compose dev key), `TRACEGUARD_TOOL`
(required, namespaced `alias__tool`), `TRACEGUARD_ARGS` (JSON, default `{}`).

## What you should observe

- If the policy allows the tool, the script prints the upstream result
  immediately — one call, one execution.
- If the policy requires approval, the shim backs off and retries with the
  **same `logical_request_id`** and a fresh JSON-RPC id each attempt. The
  dashboard (Approvals tab) shows the pending request; approving it there (or
  via `POST :8093/_control/v1/approvals/:id/decision`) lets the next retry
  execute — exactly once.
- If the deadline passes while still pending, the script exits non-zero with
  "retry the same logical call" — safe, nothing executed.
- If the upstream outcome is ambiguous (timeout after dispatch), the shim
  raises `OutcomeUnknownError` and the script tells you to reconcile rather
  than retry. The gateway records `OUTCOME_UNKNOWN`; the action may have
  executed.

The retry/terminal semantics are unit-tested in
`packages/mcp-client-shim/tests/shim.test.ts`; this example is the runnable
form of the same contract.
