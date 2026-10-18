# Reference policy set

A drop-in starting point for the gateway policy engine: one allow, one hard
deny, and one approval requirement. Together they demonstrate the evaluation
order from the spec (§11.3): deny beats allow no matter the priority, approval
requirements hold a call until a human decides, and anything unmatched is
denied by default.

## Apply it

```bash
# 1. Start the stack (mock tools included) and export your admin key.
export API_KEY=dev_key_change_me        # PowerShell: $env:API_KEY="dev_key_change_me"

# 2. Register the mock upstream and discover its tools.
curl -s -X POST http://localhost:8091/v1/servers \
  -H "authorization: Bearer $API_KEY" -H "content-type: application/json" \
  -d '{"name":"local-tools","base_url":"http://localhost:8092/mcp"}'
# -> take the returned id, then:
curl -s -X POST http://localhost:8091/v1/servers/<server-id>/discover \
  -H "authorization: Bearer $API_KEY"

# 3. Replace REPLACE_WITH_SERVER_ID in policies.json with that id, then create
#    each rule (the API takes one policy per request).
for p in $(jq -c '.[]' policies.json); do
  curl -s -X POST http://localhost:8091/v1/policies \
    -H "authorization: Bearer $API_KEY" -H "content-type: application/json" \
    -d "$p"
done

# 4. Sign and publish the rules + server manifest + reviewed pins as the
#    active policy version. Until this runs, every gateway call fails closed
#    (503 policy_unavailable): these rules are drafts.
npm run policy:keygen                                  # once, writes ./policy-keys/
npm run policy:trust -- --workspace default            # once, audited
npm run policy:publish -- --workspace default
```

## What each rule does

| Rule | Effect | Why |
| --- | --- | --- |
| `allow-read-file` | allow | Baseline access for the read tool. |
| `deny-destructive-wipe` | deny | Unconditional block; priority only orders rules of the same effect, so deny always wins over allow. |
| `approval-for-sensitive-paths` | require_approval | Calls touching the listed path return `202` with an approval id and the upstream is never contacted until a human decides. |

## Try the flows

```bash
CALL="http://localhost:8091/v1/gateway/tools/call"
AUTH="authorization: Bearer $API_KEY"
JSON="content-type: application/json"

# Allowed straight through:
curl -s -X POST $CALL -H "$AUTH" -H "$JSON" \
  -d '{"server_id":"<server-id>","tool":"read_file","arguments":{"path":"/notes.txt"},"caller":"demo"}'

# Denied before any upstream contact (403, reason names the rule):
curl -s -X POST $CALL -H "$AUTH" -H "$JSON" \
  -d '{"server_id":"<server-id>","tool":"wipe_disk","arguments":{"target":"/dev/sda"},"caller":"demo"}'

# Held for approval (202, no upstream contact):
curl -s -X POST $CALL -H "$AUTH" -H "$JSON" \
  -d '{"server_id":"<server-id>","tool":"read_file","arguments":{"path":"/approval-needed.txt"},"caller":"demo","request_id":"demo-1"}'
# A second operator decides with the separate approver key:
curl -s -X POST http://localhost:8091/v1/approvals/<approval-id>/decision \
  -H "authorization: Bearer $APPROVER_KEY" -H "content-type: application/json" \
  -d '{"approved":true}'
# Then the caller retries with approval_id; the approval is single-use and
# bound to caller, server, tool, canonical arguments, and request id.
```

## Condition operators

`conditions.arguments` maps a tool argument to a constraint:

- `required: ["path"]` (a conditions-level list) — the argument must be present.
- `path_within: "/srv/data"` — canonicalized path must stay inside the prefix.
- `regex: "^/tmp/"` — anchor carefully; invalid patterns fail closed.
- `enum: ["a", "b"]` — exact allowed values.
- `max_length: 256` — string length cap.

Unmatched tool calls are denied by default (FR-014). Every decision is written
to `policy_decisions` citing the exact signed policy version id, matched rules,
and the tool-definition pin the call was gated on; outcomes land in the
hash-chained `audit_events` table. Rules only take effect after
`policy-publisher publish` signs them into the active bundle — before the
first publish, calls fail closed with `503 policy_unavailable`.
