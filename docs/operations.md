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

## Restore drill

A backup nobody has restored is a guess. Once a quarter: restore the latest dump
into `traceguard_restore`, run the row-count query above, point a scratch API at
it, and open one run and one trace. Record the date and the dump name here.
