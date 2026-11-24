#!/bin/bash
# Encrypted logical backup of the task_ayuza schema, made with the read-only backup role.
# The file is encrypted to an age public key before it touches the disk; only the holder of
# the private key (password manager, work computer) can read it. Old copies are pruned.
set -euo pipefail
: "${PGPASSWORD:?backup role password is required}"
: "${AGE_RECIPIENT:?age public key is required}"
export PGHOST="${PGHOST:-db}" PGUSER="${PGUSER:-task_ayuza_backup}" PGDATABASE="${PGDATABASE:-task_ayuza_test}"
dir="${BACKUP_DIR:-/backups}"
keep="${BACKUP_KEEP_DAYS:-30}"
[[ "$AGE_RECIPIENT" =~ ^age1[02-9ac-hj-np-z]{58}$ ]] || { echo 'AGE_RECIPIENT is not an age public key' >&2; exit 2; }
[[ "$keep" =~ ^[0-9]+$ ]] || { echo 'BACKUP_KEEP_DAYS must be a number' >&2; exit 2; }
umask 077
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="$dir/task-ayuza-$stamp.dump.age"
tmp="$out.partial"
trap 'rm -f "$tmp"' EXIT
pg_dump --format=custom --schema=task_ayuza --no-owner --no-privileges \
  | age --encrypt --recipient "$AGE_RECIPIENT" --output "$tmp"
mv "$tmp" "$out"
find "$dir" -maxdepth 1 -type f -name 'task-ayuza-*.dump.age' -mtime +"$keep" -delete
echo "backup: $(basename "$out") $(stat -c %s "$out") bytes"
