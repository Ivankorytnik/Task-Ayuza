#!/bin/bash
# Proves the newest backup can be restored: decrypts it, restores it into a throwaway
# PostgreSQL started inside this container the way a real recovery would (roles and empty
# schema from bootstrap-test.sql, objects owned by the migrator role, grants from
# grant-test.sql), then checks the schema version and the table set. When the live
# database is reachable it also compares them with it. Nothing is written to the live DB.
set -euo pipefail
dir="${BACKUP_DIR:-/backups}"
identity="${AGE_IDENTITY_FILE:-/keys/backup-identity.txt}"
scripts="${SQL_DIR:-/sql}"
file="${1:-$(ls -1t "$dir"/task-ayuza-*.dump.age 2>/dev/null | head -n 1 || true)}"
[[ -n "$file" && -f "$file" ]] || { echo 'restore-check: no backup file found' >&2; exit 2; }
[[ -r "$identity" ]] || { echo "restore-check: private key $identity is not readable" >&2; exit 2; }

work="$(mktemp -d)"
as_pg() { if [[ "$(id -u)" == 0 ]]; then gosu postgres "$@"; else "$@"; fi; }
[[ "$(id -u)" == 0 ]] && chown postgres "$work"
cleanup() { as_pg pg_ctl -D "$work/data" -m immediate -w stop >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT

umask 077
age --decrypt --identity "$identity" --output "$work/db.dump" "$file" 2>/dev/null \
  || { echo "restore-check: FAIL cannot decrypt $(basename "$file") (wrong key or damaged file)" >&2; exit 1; }
[[ "$(id -u)" == 0 ]] && chown postgres "$work/db.dump"
as_pg initdb -D "$work/data" --auth=trust --username=postgres --no-locale --encoding=UTF8 >/dev/null
as_pg pg_ctl -D "$work/data" -l "$work/server.log" -w \
  -o "-c listen_addresses='' -c unix_socket_directories=$work" start >/dev/null
q() { as_pg psql -X -q -v ON_ERROR_STOP=1 -h "$work" -U postgres "$@"; }
q -d postgres -c 'CREATE DATABASE task_ayuza_test'
q -d task_ayuza_test -f "$scripts/bootstrap-test.sql" >/dev/null
# bootstrap-test.sql already created the empty schema; restore everything except it.
as_pg pg_restore --list "$work/db.dump" | grep -v -E ' SCHEMA - task_ayuza ' > "$work/list"
[[ "$(id -u)" == 0 ]] && chown postgres "$work/list"   # written by root with umask 077
as_pg pg_restore --exit-on-error --no-owner --role=task_ayuza_migrator --use-list="$work/list" \
  -h "$work" -U postgres -d task_ayuza_test "$work/db.dump"
q -d task_ayuza_test -f "$scripts/grant-test.sql" >/dev/null

restored_version="$(q -d task_ayuza_test -At -c 'SELECT version_num FROM task_ayuza.alembic_version')"
restored_tables="$(q -d task_ayuza_test -At -c "SELECT count(*) FROM pg_tables WHERE schemaname='task_ayuza'")"
counts="$(q -d task_ayuza_test -At -F' ' -c "SELECT (SELECT count(*) FROM task_ayuza.users), (SELECT count(*) FROM task_ayuza.tasks), (SELECT count(*) FROM task_ayuza.audit_events)")"
[[ -n "$restored_version" && "$restored_tables" -gt 0 ]] || { echo 'restore-check: restored schema is empty' >&2; exit 1; }

if [[ -n "${PGPASSWORD:-}" ]]; then
  live() { psql -X -q -At -h "${PGHOST:-db}" -U "${PGUSER:-task_ayuza_backup}" -d "${PGDATABASE:-task_ayuza_test}" -c "$1"; }
  live_version="$(live 'SELECT version_num FROM task_ayuza.alembic_version')"
  live_tables="$(live "SELECT count(*) FROM pg_tables WHERE schemaname='task_ayuza'")"
  if [[ "$live_version" != "$restored_version" || "$live_tables" != "$restored_tables" ]]; then
    echo "restore-check: FAIL backup $restored_version/$restored_tables tables vs live $live_version/$live_tables" >&2
    exit 1
  fi
fi
read -r users tasks audit <<<"$counts"
echo "restore-check: OK $(basename "$file") schema $restored_version, $restored_tables tables, users=$users tasks=$tasks audit_events=$audit"
