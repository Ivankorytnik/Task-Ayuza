"""Initialise a LOCAL Task-Ayuza PostgreSQL (roles, schema, grants). Idempotent.

Reuses the reviewed scripts/bootstrap-test.sql, Alembic head and scripts/grant-test.sql.
Credentials come only from environment variables; nothing is stored in Git.
Local/test use only: not a production procedure.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import psycopg
from psycopg import sql

ROOT = Path(__file__).resolve().parents[1]
DB = 'task_ayuza_test'
ROLES = {'migrator': 'TA_MIGRATOR_PW', 'runtime': 'TA_RUNTIME_PW', 'backup': 'TA_BACKUP_PW'}


def need(name: str) -> str:
    value = os.environ.get(name, '')
    if not value:
        sys.exit(f'Missing environment variable {name}')
    return value


def main() -> None:
    host = os.environ.get('TA_DB_HOST', '127.0.0.1')
    port = int(os.environ.get('TA_DB_PORT', '5432'))
    admin_user, admin_pw = need('TA_ADMIN_USER'), need('TA_ADMIN_PASSWORD')
    passwords = {role: need(var) for role, var in ROLES.items()}

    def admin(dbname: str):
        return psycopg.connect(host=host, port=port, user=admin_user, password=admin_pw,
                               dbname=dbname, autocommit=True)

    with admin('postgres') as conn:
        if not conn.execute('SELECT 1 FROM pg_database WHERE datname=%s', (DB,)).fetchone():
            conn.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(DB)))
            print('database created')
    with admin(DB) as conn:
        if not conn.execute("SELECT 1 FROM pg_roles WHERE rolname='task_ayuza_migrator'").fetchone():
            conn.execute((ROOT / 'scripts/bootstrap-test.sql').read_text())
            print('roles and schema bootstrapped')
        for role, pw in passwords.items():
            conn.execute(sql.SQL('ALTER ROLE {} PASSWORD {}').format(
                sql.Identifier('task_ayuza_' + role), sql.Literal(pw)))
        url = f'postgresql+psycopg://task_ayuza_migrator:{passwords["migrator"]}@{host}:{port}/{DB}'
        subprocess.run([sys.executable, '-m', 'alembic', 'upgrade', 'head'], cwd=ROOT,
                       env=dict(os.environ, TASK_AYUZA_DATABASE_URL=url), check=True)
        conn.execute((ROOT / 'scripts/grant-test.sql').read_text())
    print('local database ready')


if __name__ == '__main__':
    main()
