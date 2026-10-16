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
to `policy_decisions` citing the exact policy version, and outcomes land in the
hash-chained `audit_events` table.
