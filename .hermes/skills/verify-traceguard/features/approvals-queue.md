# Approvals queue

Held tool calls wait in the approvals queue; nothing executes upstream until a human
decides. The queue shows pending requests with their bound arguments and lets an
approver approve, deny, or run an approved call.

## Sub-features

- `approvals-filter` switches between pending/all/approved/denied/expired/consumed.
- `approvals-decide` approves or denies a pending request with an optional reason.
- `approvals-run` executes an approved-but-unconsumed call (`Run now`).
- `approvals-poll` refreshes the queue in place every ~10 s.

## How to get to it (user POV)

- Click `Approvals` in the sidebar (`#/approvals`).
- Use the segmented filter in the page header.

## Driving it with browser_exec

Preconditions:

- Baseline met; gateway up (:8091) and the dashboard's approver key matches the gateway
  (`dev_approver_change_me` by default).
- A fresh pending approval exists. The reliable recipe (proven 2026-10-16): bring up the
  compose mock upstream (`docker compose up -d mock-tools` — it is on the internal `tools`
  network, so the gateway reaches it as `http://mock-tools:8092/mcp`; `localhost:8092` is the
  host's view and is unreachable from the gateway container), register it
  (`POST /v1/servers` with that url), `POST /v1/servers/:id/discover`, add a server-scoped
  `require_approval` rule (`POST /v1/policies` with `server_id`, `tool_name: "wipe_disk"`,
  `priority: 100`), then call `POST /v1/gateway/tools/call` with that server id and tool.
  The response carries `approval_id` + `expires_at`. Do this immediately before driving —
  the TTL is 300 s by default. If none exists, the queue's empty state is the only
  verifiable path — report the rest as skipped with this precondition unmet.
- **Load + filter.** Open `#/approvals`; the `Pending` segment is pressed
  (`aria-pressed`). Switch to `All`; rows from every status can appear.
- **Inspect binding.** Each card shows tool name, caller, expiry, and the args JSON —
  record these; a decision must match this exact request.
- **Decide.** On a pending card, fill the reason input (`aria-label="Decision reason"`)
  via `fill_input('input[aria-label="Decision reason"]', "verified by harness")`, then
  click `Approve`. Target the card as the smallest div that contains the tool name AND an
  `Approve` button — the smallest div matching the tool name alone is the collapsed header
  and has no buttons. The card's badge flips to `approved` and `Run now` appears.
- **Second view.** Refetch the queue (`Refresh` button) — the decision persists with the
  reason text shown on the card.
- **Run now (optional).** Click `Run now` on the approved card; the card shows
  `executed: ...` or `status: ...`, and the approval becomes `consumed` after refresh.
- **Proof.** Screenshots before/after; `checks.txt` records approval id, status
  transition, and reason.

## Gotchas

- A decision moves the card out of the current filter: after `Approve` it leaves `Pending`,
  after `Run now` it leaves `Approved`. Switch filters to assert each state — "not found"
  in the current filter is the expected result of success, not a failure.
- Approvals carry a 5-minute TTL (`APPROVAL_TTL_SECONDS: 300` in compose). Create the
  approval right before driving; an expired card cannot be decided (the gateway answers 410
  and flips it to `expired`).
- The reason is per-card: set it on the same card div that owns the `Approve` button.
- Decisions use the approver key, not the API key — a 401 here is a key mismatch, not a bug.
- An approval is single-use: `Run now` consumes it; replaying gets `410`. Never decide
  the same approval twice in one run.
- Expiry: past `expires_at` the gateway refuses execution regardless of approval.
- Mutating the queue is a real policy action — prefer the user's own disposable stack,
  and note in evidence that a decision was recorded.
