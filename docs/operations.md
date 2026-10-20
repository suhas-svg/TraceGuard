# Operations

Running TraceGuard day to day: backups, restores, migrations, and the cron
endpoints. Everything here is a command you can rerun, not a description.

## Backups

TraceGuard's durable state is Postgres, and nothing else. The API and gateway
are stateless processes, so a backup is one database dump.

```bash
# Custom format: compressed, and restorable selectively with pg_restore.
docker exec traceguard-postgres-1 pg_dump -U traceguard -Fc traceguard \
  > "traceguard-$(date -u +%Y%m%dT%H%M%SZ).dump"
```

What is in there and what it is worth:

| Data | Backup needed | Why |
|---|---|---|
| `runs`, `spans`, `eval_*` | yes | the trace history itself |
| `pricing`, `budgets`, `budget_ledger` | yes | money; the ledger explains every counter |
| `policies`, `policy_decisions`, `approvals` | yes | the audit trail and the decision record |
| `audit_events` | yes | hash-chained; a gap cannot be reconstructed |
| `api_keys`, `users`, `memberships` | yes | key *hashes* only, so a restore does not resurrect plaintext |
| `actuals` | yes | provider invoices already imported |

Two things are **not** in the dump and must be handled separately:

- **`APPROVAL_ARGS_KEY`.** Pending approvals are sealed with it. Restore the
  database without that key and those rows are unreadable — the gateway shows
  them redacted with `decrypt_error` rather than dropping them. Keep the key in
  your secret store next to the backup, and keep the previous key configured
  until the holds sealed under it have expired.
- **`.env` / `infra/k8s/secrets.yaml`.** Never in the database, never in git.

## Restores

```bash
# Into a fresh database, on a throwaway container first.
docker exec -i traceguard-postgres-1 createdb -U traceguard traceguard_restore
docker exec -i traceguard-postgres-1 pg_restore -U traceguard -d traceguard_restore --no-owner \
  < traceguard-20260101T000000Z.dump

# Confirm before you cut over: row counts on the tables that matter.
docker exec traceguard-postgres-1 psql -U traceguard -d traceguard_restore -c \
  "SELECT 'runs' t, count(*) FROM runs UNION ALL
   SELECT 'spans', count(*) FROM spans UNION ALL
   SELECT 'audit_events', count(*) FROM audit_events UNION ALL
   SELECT 'pricing', count(*) FROM pricing;"
```

Restore the whole cluster, not one table. `budgets.spent_micro` is a cached sum
of `budget_ledger`, and `approvals.status` is a state machine whose transitions
are referenced by `policy_decisions`; restoring one without the other produces a
database that answers inconsistently.

Then point `DATABASE_URL` at the restored database and restart the API and
gateway. Verify with `GET /readyz` and by opening a run you know the id of.

## Migrations

Migrations are plain SQL in `apps/api/migrations`, applied in filename order and
idempotent (`CREATE ... IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`), so a retried
migration job is safe.

```bash
# Local, against DATABASE_URL.
npm run db:migrate

# In Kubernetes, the migrate Job does it (waits for postgres, then applies).
kubectl -n traceguard logs job/migrate
```

Two migrations do more than add a column, and both say so in their header:
`014_budget_periods.sql` adds the reporting-period column, and
`015_actuals_idempotency.sql` deletes pre-existing duplicate invoice lines before
it can add the unique index. Read the header of any migration numbered 014 or
above before running it on a database you care about.

## Cron endpoints

These are endpoints rather than in-process schedulers, so one operator decision
drives all of them.

```bash
# Close runs orphaned by a crashed SDK (§11.3: a run silent for 15 minutes is
# ORPHANED, not failed). Idempotent, and audited.
curl -fsS -X POST "$API/v1/admin/finalize-stale-runs?older_than_seconds=900" \
  -H "Authorization: Bearer $API_KEY"

# Flag child spans whose parent never arrived (children may arrive first).
curl -fsS -X POST "$API/v1/admin/finalize-orphan-spans?older_than_seconds=900" \
  -H "Authorization: Bearer $API_KEY"

# Recover budget holds abandoned past their TTL (§12.3).
curl -fsS -X POST "$API/v1/admin/sweep-budget-holds" \
  -H "Authorization: Bearer $API_KEY"

# Apply every enabled retention rule and report per-rule deletion counts.
curl -fsS -X POST "$API/v1/retention/run" -H "Authorization: Bearer $API_KEY"

# Before any audit pruning: create a signed checkpoint over the chain head,
# export it, and keep the export outside the database and containers
# (§10.2/FR-019). The signed payload records the last sequence and hash of
# every workspace covered by the segment. Checkpoints and pruning live on the
# gateway listener; pruning stays deliberate, never scheduled.
curl -fsS -X POST "http://localhost:8091/v1/audit/checkpoints" \
  -H "Authorization: Bearer $API_KEY"
curl -fsS "http://localhost:8091/v1/audit/checkpoints/<checkpoint-id>/export" \
  -H "Authorization: Bearer $API_KEY" > checkpoint-export.json
# Verify the export offline — signature, chain links, per-workspace segments —
# before trusting the copy you are about to prune against:
npm run audit:verify -- --export checkpoint-export.json --public-key checkpoint.pub.pem
# Only then prune. external_ref is required: it names the external copy of the
# signed checkpoint and lands in the audit trail as the receipt for the
# removed segment.
curl -fsS -X POST "http://localhost:8091/v1/audit/prune" \
  -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
  -d '{"checkpoint_id":"<checkpoint-id>","external_ref":"s3://audit-vault/2026-10-20/checkpoint.json"}'
```

Suggested schedule: finalize every 15 minutes, retention nightly. Retention
can age out whole traces by age and by a span-count cap (the seeded
`default-span-retention` keeps 7 days or 100,000 spans, whichever comes
first). Policies, decisions, pending approvals, the audit log, and the
money tables are never deletion targets — the API refuses them.

## Approval operations

The queue and decisions live on the gateway's control listener
(`GATEWAY_CONTROL_PORT`, default 8093), never the agent-facing port. Only the
approver key — or a token carrying the `approve` scope — may list or decide;
agent and read-scope keys get 403 there, and the `admin` scope does not
shortcut the surface either, so plain admin keys are refused too. Consuming an
approval first claims
the row under `APPROVAL_CLAIM_LEASE_SECONDS` (default 30); the queue-list
sweep returns an expired claim to `approved` (audited as
`approval.claim_expired`, which by definition means no execution intent was
written, so nothing was dispatched). The same sweep expires pending rows past
their TTL and flips `executing` rows past
`APPROVAL_EXECUTION_TIMEOUT_SECONDS` (default 300) to `outcome_unknown` —
rows a human should reconcile against the upstream, because the action may
have executed and will never be retried automatically.

```bash
# Watch the queue from the control listener, not the agent port.
curl -fsS "http://localhost:8093/_control/v1/approvals?status=outcome_unknown&limit=200" \
  -H "Authorization: Bearer $APPROVER_KEY"
```

## Policy publication and signing keys

Enforcement reads only the active signed policy bundle; drafts (rules, server
registrations, reviewed pins) become effective solely through a publish
(§13.3). The signing key is operator-host state: it never goes into
PostgreSQL, the API container, or the gateway container.

```bash
# Create the pair once, on the operator's host.
npm run policy:keygen                                   # ./policy-keys/

# Trust the public key for a workspace; audited, and refused if another key
# is already live unless --rotate is passed (rotation retires the old key).
npm run policy:trust -- --workspace default

# Publish the current drafts as the new active version (monotonic).
npm run policy:publish -- --workspace default
npm run policy:publish -- --workspace default --dry-run # inspect without publishing
npm run policy:status -- --workspace default            # active version + draft summary
```

Key rotation order matters: `trust --rotate` retires the old key, and the
gateway refuses versions signed by a retired key, so **publish immediately
after rotating** or tool calls fail closed in between. A previously retired
key that is re-trusted is re-activated in place, never duplicated.

The gateway remembers the highest version it accepted in
`GATEWAY_STATE_DIR` (compose: the `gateway_state` volume). That anchor is
what turns "someone pointed the database at an older signed bundle" into a
detected rollback instead of a silent downgrade — it must persist across
restarts, and a forked anchor is treated as tampering.

## Verifying the audit chain

```bash
curl -fsS -X POST "$GATEWAY/v1/audit/verify" -H "Authorization: Bearer $API_KEY"
# -> { ok, checked, truncated, problems: [{ id, problem }], anchored, empty, complete }
```

The verifier recomputes every event hash and checks every link. Since
migration 022 the table is append-only at the database layer (UPDATE and
DELETE are rejected), so a detected mutation means something with schema
rights disabled the trigger — the party only an externally stored checkpoint
anchors against. A bounded read reports `truncated: true`, and `complete` is
true only when the whole chain is read, intact, and unpruned — an `anchored`
prefix or a truncated read is reported as partial, never as fully verified.
Since FR-019 pruning itself refuses without a valid externally stored
checkpoint and an `external_ref` receipt. `npm run audit:verify -- --export
<file> --public-key <pem>` runs the same checks offline against an exported
checkpoint, without the live database or gateway. The dashboard's Policy tab
has the same check behind the `Verify chain` button.

Upgrade note: as of the signed-policy change, approval binding hashes
(`request_hash`, `args_hash`) are computed over RFC 8785 canonical JSON and
include the tool-definition pin. Pending approvals created before the upgrade
will not match a retry; they expire within the TTL (≤60 minutes). Deploy
with an empty queue, or let old holds expire and recreate them.

## OAuth deployments

With `OAUTH_ISSUER`, `OAUTH_AUDIENCE` and a JWKS source set, tokens are
validated against the issuer on every request; nothing is cached beyond the
issuer's public keys. Operationally:

- **Issuer key rotation** needs no gateway restart: an unknown `kid`
  triggers a JWKS refetch, rate-limited to one fetch per 10 s per source.
  Nothing to do on the TraceGuard side.
- **Audience changes** (a new public hostname) are a config change on both
  services: the old tokens stop validating the moment the audience changes,
  so cut over with a short overlap by accepting the new audience first.
- **Leaving production mode** (clearing the OAUTH_* keys) is a fail-open
  action: the static keys in the environment start authenticating again.
  Treat those values as live credentials for as long as they are set.
- A 401 on the MCP endpoint carries the `resource_metadata` challenge, so a
  client that speaks RFC 9728 can find the issuer without documentation.

## Least-privilege roles

Migration `023` creates six roles, all `NOLOGIN`. Development runs
everything as the database owner and is unaffected. **Compose does the
switch for you**: the `db-roles` service applies the migrations and then
enables the logins with the passwords in `.env` (`API_DB_PASSWORD`,
`GATEWAY_DB_PASSWORD`, `RETENTION_DB_PASSWORD`, `PUBLISHER_DB_PASSWORD`),
and the api, gateway and retention sweep connect as their own roles. In a
deployment assembled by hand, enable only the logins you need, each with its
own password from the secret store:

```sql
-- once, as the database owner
ALTER ROLE api_runtime       LOGIN PASSWORD '<from secret>';
ALTER ROLE gateway_runtime   LOGIN PASSWORD '<from secret>';
ALTER ROLE policy_publisher  LOGIN PASSWORD '<from secret>';   -- operator host
ALTER ROLE retention_job     LOGIN PASSWORD '<from secret>';
```

Then point each connection at its role: `DATABASE_URL` for the API and the
gateway (one each), `DATABASE_URL_RETENTION` for the sweep, and the
publisher's `--database-url`/`DATABASE_URL` on the operator host. Verify with
`npm run test --workspace apps/api -- tests/db-roles.test.ts`, which asserts
the whole allowance/denial matrix.

Gotchas worth knowing before you switch:

- `audit_events` is owned by `audit_owner`, so any database that ran
  migrations before `023` must be migrated with a role that can
  `ALTER TABLE ... OWNER`; a plain runtime role cannot.
- The compose `db-roles` service keeps a `schema_migrations` ledger and skips
  what it has already applied, because older migrations are not
  re-runnable. A database migrated before the ledger existed is adopted once:

  ```sql
  CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now());
  INSERT INTO schema_migrations (name)
    SELECT f FROM unnest(ARRAY['001_init.sql', '002_gateway.sql', /* ... every file already applied ... */]) AS f
    ON CONFLICT DO NOTHING;
  ```
- A runtime role cannot `INSERT` audit rows directly — that is the point —
  so anything you add that writes audit must call `append_audit_event`
  (the shared `@traceguard/audit-chain` already does).
- Retention of *terminal approvals* is `retention_job`'s alone. Without
  `DATABASE_URL_RETENTION`, a sweep run as `api_runtime` fails closed on an
  approvals rule rather than silently skipping it.

## Restore drill

A backup nobody has restored is a guess. Once a quarter: restore the latest dump
into `traceguard_restore`, run the row-count query above, point a scratch API at
it, and open one run and one trace. Record the date and the dump name here.
