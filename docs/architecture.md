# Architecture

Three processes plus Postgres. The API owns ingestion, runs, pricing,
budgets, and evaluations. The gateway owns upstream credentials and every
tool permission decision. The web dashboard only reads.

```
agent/SDK ---> API :8090 ---> postgres
agent ------> gateway :8091 ---> upstream MCP (tools network only)
human ------> web :5173 ---> API
```

The gateway holds upstream bearer tokens and injects them at call time.
Agent tokens never travel upstream, and upstream secrets never come back
down: list endpoints select every column except the secret.

Policy decisions run inside the gateway before any upstream contact. A deny
or an unknown tool returns without opening a connection. Calls needing a
human return 202 with an approval id; the agent retries with that id after
the decision. Approvals are single-use and bound to the exact call by hash.

Money is integer micro-dollars. Budgets reserve the worst case before a
managed call in one atomic UPDATE, then settle to the measured cost.

The audit log is append-only with a hash chain: tamper-evident, not
tamper-proof. Reads never return secrets, and no UPDATE or DELETE against
the audit table exists in the codebase.

Pending approval arguments are sealed with AES-256-GCM bound to the
request id, and open only inside the gateway. Rows written before sealing
stay readable as plaintext; everything new seals.

Known limits: one API key per deploy, one approver key, and the SDK trusts the clock
for Zulu timestamps.
