# Architecture

Three processes plus Postgres. The API owns ingestion, runs, pricing,
budgets, and evaluations. The gateway owns upstream credentials and every
tool permission decision. The web dashboard only reads. A fourth, operator-run
process — `tools/policy-publisher` — is the only thing that signs policy, and
it never runs as a service.

```
agent/SDK ---> API :8090 ---> postgres
agent ------> gateway :8091 ---> upstream MCP (tools network only)
human ------> web :5173 ---> API / gateway
operator ---> policy-publisher ---> postgres   (signs; holds the private key)
```

The gateway holds upstream bearer tokens and injects them at call time.
Agent tokens never travel upstream, and upstream secrets never come back
down: list endpoints select every column except the secret.

Policy enforcement is a verification problem before it is an evaluation
problem. The gateway loads the active `policy_versions` row, checks its
content hash and Ed25519 signature against the pinned public key, and only
then reads the rule set, the server manifest, and the tool-pin manifest out
of the bundle. It also keeps its own record of the highest version it has
accepted, so a pointer rolled back to an older (genuinely signed) bundle is
detected as a rollback rather than accepted as policy. Anything that fails
this sequence — no active version, bad signature, mismatched hash, retired
key, history gap — fails closed before an upstream is contacted.

Drafts are the untrusted half: rules in `policies`, server registrations,
and discovered tool definitions. Discovery pins the complete definition
(title, both schemas, annotations, icons, execution hints, allowlisted
_meta) and quarantines drift. Reviewing and publishing is what makes a draft
executable: `policy-publisher` assembles the bundle from the current drafts,
signs it, inserts an immutable `policy_versions` row, and moves the
`active_config` pointer in one transaction.

An allowed call forwards with the upstream credential; a deny or an unknown
tool returns without opening a connection. Calls needing a human return 202
with an approval id; the agent retries with that id after the decision.
Approvals are single-use and bound to the exact call by an RFC 8785 request
hash that includes the tool-definition pin. The consume path re-loads and
re-verifies the current bundle inside the claim transaction, so a deny or a
dropped pin added after the approval invalidates it.

Money is integer micro-dollars. Budgets reserve the worst case before a
managed call under a row lock (SELECT ... FOR UPDATE), so concurrent calls
serialize and settle to the measured cost after.

The audit log is append-only with a hash chain, implemented once in
`packages/audit-chain` and shared by the API, the gateway, and the policy
publisher so the hash formula cannot drift between writers. Migration 022
rejects UPDATE/DELETE on the table at the database layer, and
`POST /v1/audit/verify` recomputes every event and link. Tamper-evident, not
tamper-proof: only an externally stored checkpoint anchors history against a
host owner.

Pending approval arguments are sealed with AES-256-GCM bound to the
request id, and open only inside the gateway. Rows written before sealing
stay readable as plaintext; everything new seals.

Rotate by generating a fresh key, deploying it as the primary with the old
key as the previous, waiting past the approval TTL so sealed rows drain,
then removing the previous key. New rows always use the primary.

Known limits: one API key per deploy, one approver key, and the SDK trusts the clock
for Zulu timestamps.
