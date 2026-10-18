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
# Close runs orphaned by a crashed SDK. Idempotent, and audited.
curl -fsS -X POST "$API/v1/admin/finalize-stale-runs?older_than_seconds=3600" \
  -H "Authorization: Bearer $API_KEY"

# Apply every enabled retention rule and report per-rule deletion counts.
curl -fsS -X POST "$API/v1/retention/run" -H "Authorization: Bearer $API_KEY"
```

Suggested schedule: finalize every 15 minutes, retention nightly. Retention
never targets policies, decisions, pending approvals, the audit log, or the
money tables — the API refuses those targets.

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
# -> { ok, checked, truncated, problems: [{ id, problem }] }
```

The verifier recomputes every event hash and checks every link. Since
migration 022 the table is append-only at the database layer (UPDATE and
DELETE are rejected), so a detected mutation means something with schema
rights disabled the trigger — the party only an externally stored checkpoint
anchors against. A bounded read reports `truncated: true` rather than
labelling a prefix as fully verified. The dashboard's Policy tab has the
same check behind the `Verify chain` button.

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

## Restore drill

A backup nobody has restored is a guess. Once a quarter: restore the latest dump
into `traceguard_restore`, run the row-count query above, point a scratch API at
it, and open one run and one trace. Record the date and the dump name here.
