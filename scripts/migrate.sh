#!/bin/sh
set -eu

export PGPASSWORD
PGPASSWORD=$(tr -d '\r\n' < "${PGPASSWORD_FILE:-/run/secrets/postgres_migrator_password}")

psql --set=ON_ERROR_STOP=1 <<'SQL'
CREATE SCHEMA IF NOT EXISTS system AUTHORIZATION arc_migrator;
REVOKE ALL ON SCHEMA system FROM PUBLIC;
CREATE TABLE IF NOT EXISTS system.schema_migrations (
  version text PRIMARY KEY,
  checksum text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON TABLE system.schema_migrations FROM PUBLIC;
SQL

for migration in "${MIGRATIONS_DIR:-/migrations}"/*.up.sql; do
  [ -f "$migration" ] || continue
  version=$(basename "$migration")
  case "$version" in
    *[!0-9a-z_.-]*|*.up.sql.up.sql) echo "invalid migration filename" >&2; exit 1 ;;
  esac
  checksum=$(sha256sum "$migration" | cut -d ' ' -f 1)
  applied=$(psql --set=ON_ERROR_STOP=1 --tuples-only --no-align \
    -c "SELECT checksum FROM system.schema_migrations WHERE version = '$version'")

  if [ -n "$applied" ]; then
    if [ "$applied" != "$checksum" ]; then
      echo "migration checksum mismatch: $version" >&2
      exit 1
    fi
    echo "migration already applied: $version"
    continue
  fi

  {
    echo 'BEGIN;'
    cat "$migration"
    printf "INSERT INTO system.schema_migrations (version, checksum) VALUES ('%s', '%s');\n" "$version" "$checksum"
    echo 'COMMIT;'
  } | psql --set=ON_ERROR_STOP=1
  echo "migration applied: $version"
done
