#!/bin/sh
set -eu

psql --set=ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" <<'SQL'
SELECT format(
  'CREATE ROLE arc_migrator LOGIN PASSWORD %L',
  btrim(pg_read_file('/run/secrets/postgres_migrator_password'))
)
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'arc_migrator') \gexec
SELECT format(
  'ALTER ROLE arc_migrator PASSWORD %L',
  btrim(pg_read_file('/run/secrets/postgres_migrator_password'))
) \gexec

SELECT format(
  'CREATE ROLE arc_core LOGIN PASSWORD %L',
  btrim(pg_read_file('/run/secrets/postgres_core_password'))
)
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'arc_core') \gexec
SELECT format(
  'ALTER ROLE arc_core PASSWORD %L',
  btrim(pg_read_file('/run/secrets/postgres_core_password'))
) \gexec

GRANT CONNECT, CREATE ON DATABASE arc TO arc_migrator;
GRANT CONNECT ON DATABASE arc TO arc_core;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL
