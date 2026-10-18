#!/bin/sh
# Applies unapplied migrations as the database owner, then enables the §13.4
# least-privilege logins with the passwords this deployment supplies. Runs
# once per `docker compose up` (the db-roles service); the api and gateway
# wait for it, so a clean clone never starts against an unmigrated database
# or a role that cannot log in.
#
# A ledger makes a second `up` safe: a database migrated before this script
# existed is adopted once by recording the filenames it already ran (see
# docs/operations.md), because some older migrations are not re-runnable.
set -e

psql -v ON_ERROR_STOP=1 -q <<'SQL'
CREATE TABLE IF NOT EXISTS schema_migrations (
  name TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
SQL

for f in /migrations/*.sql; do
  name=$(basename "$f")
  applied=$(psql -tAc "SELECT 1 FROM schema_migrations WHERE name = '$name'")
  if [ "$applied" = "1" ]; then
    continue
  fi
  echo "applying ${name}"
  psql -v ON_ERROR_STOP=1 -q -f "$f"
  psql -v ON_ERROR_STOP=1 -q -c "INSERT INTO schema_migrations (name) VALUES ('$name')"
done

: "${API_DB_PASSWORD:?API_DB_PASSWORD is required}"
: "${GATEWAY_DB_PASSWORD:?GATEWAY_DB_PASSWORD is required}"
: "${RETENTION_DB_PASSWORD:?RETENTION_DB_PASSWORD is required}"
: "${PUBLISHER_DB_PASSWORD:?PUBLISHER_DB_PASSWORD is required}"

psql -v ON_ERROR_STOP=1 -q <<SQL
ALTER ROLE api_runtime      LOGIN PASSWORD '${API_DB_PASSWORD}';
ALTER ROLE gateway_runtime  LOGIN PASSWORD '${GATEWAY_DB_PASSWORD}';
ALTER ROLE retention_job    LOGIN PASSWORD '${RETENTION_DB_PASSWORD}';
ALTER ROLE policy_publisher LOGIN PASSWORD '${PUBLISHER_DB_PASSWORD}';
SQL

echo "migrations applied; role logins enabled"
