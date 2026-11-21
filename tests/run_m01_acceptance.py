"""Explicit disposable-cluster acceptance; never connects to an existing database.

Usage: python tests/run_m01_acceptance.py --pg-bin /path/to/postgresql/bin
Requires installed requirements-m01.txt. No production credentials are read.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import io
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import traceback

import psycopg
from psycopg import sql
from sqlalchemy import create_engine, inspect, text
from alembic.migration import MigrationContext
from alembic.autogenerate import compare_metadata

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.main import app, lifespan
from backend.db import SchemaVersionError
from backend.models import Base


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pg-bin', type=Path, required=True)
    parser.add_argument('--port', type=int, default=55439)
    args = parser.parse_args()
    # This acceptance runner must never launch PostgreSQL as root or on a
    # platform where we cannot enforce the unprivileged-user requirement.
    if os.name != 'posix' or os.geteuid() == 0:
        parser.error('Use an unprivileged POSIX user; refusing root or non-POSIX execution')
    for executable in ('initdb', 'postgres', 'pg_ctl'):
        path = args.pg_bin / executable
        if not path.is_file() or not os.access(path, os.X_OK):
            parser.error(f'Missing PostgreSQL executable: {path}')
    os.chdir(Path(__file__).resolve().parents[1])
    # Ignore inherited connection/service settings. All credentials are synthetic.
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(('PG', 'TASK_AYUZA_'))}
    with tempfile.TemporaryDirectory(prefix='task-ayuza-m01-') as tmp:
        root = Path(tmp)
        password = secrets.token_hex(24)
        pwfile = root / 'password'
        pwfile.write_text(password)
        pwfile.chmod(0o600)
        data = root / 'data'
        def pg(command, *params):
            return subprocess.run([str(args.pg_bin / command), *map(str, params)],
                                  env=env, check=True, capture_output=True, text=True)
        pg('initdb', '-D', data, '--no-locale', '--encoding=UTF8',
           '--auth-local=peer', '--auth-host=scram-sha-256', '--username=ayuza_test_admin',
           f'--pwfile={pwfile}')
        pg('pg_ctl', '-D', data, '-l', root / 'server.log', '-o',
           f"-h 127.0.0.1 -p {args.port} -c unix_socket_directories='' -c timezone=UTC", '-w', 'start')
        try:
            def admin(db='postgres'):
                return psycopg.connect(host='127.0.0.1', port=args.port,
                    user='ayuza_test_admin', password=password, dbname=db, autocommit=True)
            with admin() as conn:
                assert set(r[0] for r in conn.execute('SELECT datname FROM pg_database')) == {
                    'postgres', 'template0', 'template1'}
                assert conn.execute('SHOW data_directory').fetchone()[0] == str(data)
                assert conn.execute('SHOW listen_addresses').fetchone()[0] == '127.0.0.1'
                print('PostgreSQL', conn.execute('SHOW server_version').fetchone()[0], flush=True)
                conn.execute('CREATE DATABASE task_ayuza_test')
            with admin('task_ayuza_test') as conn:
                assert conn.execute("SELECT count(*) FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')").fetchone()[0] == 0
                conn.execute(Path('scripts/bootstrap-test.sql').read_text())
                urls = {}
                for role in ('migrator', 'runtime', 'backup'):
                    pw = secrets.token_hex(24)
                    user = 'task_ayuza_' + role
                    conn.execute(sql.SQL('ALTER ROLE {} PASSWORD {}').format(sql.Identifier(user), sql.Literal(pw)))
                    urls[role] = f'postgresql+psycopg://{user}:{pw}@127.0.0.1:{args.port}/task_ayuza_test'
                assert conn.execute("SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member WHERE r.rolname LIKE 'task_ayuza_%'").fetchone()[0] == 0
                migration_env = dict(env, TASK_AYUZA_DATABASE_URL=urls['migrator'])
                def alembic(*params):
                    return subprocess.run([sys.executable, '-m', 'alembic', *params],
                        env=migration_env, check=True, capture_output=True, text=True)
                heads = alembic('heads').stdout.strip()
                assert heads == '0004_m01_mfa_grants (head)'
                alembic('upgrade', 'head')
                engine = create_engine(urls['migrator'], hide_parameters=True)
                def snapshot():
                    inspector = inspect(engine)
                    tables = sorted(inspector.get_table_names(schema='task_ayuza'))
                    with engine.connect() as c:
                        counts = [c.execute(text(f'SELECT count(*) FROM task_ayuza.{t}')).scalar_one() for t in tables]
                    return tables, counts, [(t, inspector.get_columns(t, schema='task_ayuza'),
                         inspector.get_indexes(t, schema='task_ayuza'),
                         inspector.get_check_constraints(t, schema='task_ayuza'),
                         inspector.get_unique_constraints(t, schema='task_ayuza')) for t in tables]
                before = repr(snapshot())
                alembic('upgrade', 'head')
                assert before == repr(snapshot())
                tables_now, counts_now = snapshot()[:2]
                assert tables_now == ['administrative_grants', 'alembic_version', 'audit_events', 'auth_limit_events', 'login_attempts', 'mfa_backup_codes', 'organization', 'prelogin_limits', 'sessions', 'setup_state', 'system_role_assignments', 'team_members', 'teams', 'user_mfa', 'users', 'workspace_members', 'workspace_team_access', 'workspace_teams', 'workspaces']
                assert counts_now == [1 if t == 'alembic_version' else 0 for t in tables_now]
                with engine.connect() as c:
                    assert c.execute(text('SELECT version_num FROM task_ayuza.alembic_version')).scalar_one() == '0004_m01_mfa_grants'
                    assert compare_metadata(MigrationContext.configure(c, opts={'include_schemas': True, 'version_table_schema': 'task_ayuza'}), Base.metadata) == []
                conn.execute(Path('scripts/grant-test.sql').read_text())
                print('A01 PASS: one head (0004); empty tables; repeated upgrade unchanged; metadata matches', flush=True)

                async def startup(url):
                    os.environ['TASK_AYUZA_DATABASE_URL'] = url
                    os.environ['TASK_AYUZA_ORIGIN'] = 'https://test.local'
                    os.environ['TASK_AYUZA_AUTH_HMAC_KEY'] = secrets.token_hex(32)
                    os.environ['TASK_AYUZA_MFA_KEY'] = secrets.token_hex(32)
                    async with lifespan(app):
                        pass
                before = repr(snapshot())
                asyncio.run(startup(urls['runtime']))
                assert before == repr(snapshot())
                print('A02 PASS: actual ASGI lifespan under runtime; schema/counts unchanged', flush=True)
                # Each invalid revision uses a separately created disposable database.
                for case in ('missing', 'empty', 'stale', 'unknown'):
                    db = 'task_ayuza_test_' + case
                    with admin() as control:
                        control.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(db)))
                    with admin(db) as invalid:
                        invalid.execute(sql.SQL('REVOKE ALL ON DATABASE {} FROM PUBLIC').format(sql.Identifier(db)))
                        invalid.execute(sql.SQL('GRANT CONNECT ON DATABASE {} TO task_ayuza_runtime').format(sql.Identifier(db)))
                        invalid.execute('CREATE SCHEMA task_ayuza')
                        invalid.execute('GRANT USAGE ON SCHEMA task_ayuza TO task_ayuza_runtime')
                        if case != 'missing':
                            invalid.execute('CREATE TABLE task_ayuza.alembic_version (version_num varchar(32) NOT NULL)')
                            invalid.execute('GRANT SELECT ON task_ayuza.alembic_version TO task_ayuza_runtime')
                            if case != 'empty':
                                invalid.execute('INSERT INTO task_ayuza.alembic_version VALUES (%s)', ('0000_previous' if case == 'stale' else 'unknown_revision',))
                        expected = [] if case in ('missing', 'empty') else [('0000_previous' if case == 'stale' else 'unknown_revision',)]
                        try:
                            asyncio.run(startup(urls['runtime'].rsplit('/', 1)[0] + '/' + db))
                        except SchemaVersionError:
                            pass
                        else:
                            raise AssertionError('Startup accepted incompatible schema')
                        if case == 'missing':
                            assert invalid.execute("SELECT to_regclass('task_ayuza.alembic_version')").fetchone()[0] is None
                        else:
                            assert invalid.execute('SELECT version_num FROM task_ayuza.alembic_version').fetchall() == expected
                # Wrong password: verify rendered traceback, stdout/stderr contain no DSN/password.
                marker = 'synthetic-credential-must-not-leak'
                bad_url = f'postgresql+psycopg://task_ayuza_runtime:{marker}@127.0.0.1:{args.port}/task_ayuza_test'
                captured = io.StringIO()
                with contextlib.redirect_stderr(captured), contextlib.redirect_stdout(captured):
                    try:
                        asyncio.run(startup(bad_url))
                    except SchemaVersionError:
                        rendered = traceback.format_exc()
                    else:
                        raise AssertionError('Invalid password accepted')
                assert marker not in rendered + captured.getvalue()
                assert bad_url not in rendered + captured.getvalue()
                print('A03/A08 PASS: missing/empty/stale/unknown schemas; authentication failure safe', flush=True)
                # Effective roles/PUBLIC/ownership; no DDL on any usable schema or role switching.
                runtime = create_engine(urls['runtime'], hide_parameters=True)
                with runtime.connect() as c:
                    assert not c.execute(text("SELECT bool_or(has_schema_privilege(oid,'USAGE') AND has_schema_privilege(oid,'CREATE')) FROM pg_namespace")).scalar_one()
                    assert not c.execute(text("SELECT has_database_privilege(current_database(),'CREATE') OR has_database_privilege(current_database(),'TEMP')")).scalar_one()
                    role = c.execute(text('SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user')).one()
                    assert not any(role)
                    assert not c.execute(text("SELECT pg_has_role(current_user,'task_ayuza_migrator','MEMBER') OR pg_has_role(current_user,'task_ayuza_backup','MEMBER')")).scalar_one()
                runtime.dispose()
                test_env = dict(env, TASK_AYUZA_DATABASE_URL=urls['runtime'],
                    TASK_AYUZA_TEST_RUNTIME_URL=urls['runtime'], TASK_AYUZA_TEST_BACKUP_URL=urls['backup'], TASK_AYUZA_TEST_MIGRATOR_URL=urls['migrator'], TASK_AYUZA_ORIGIN='https://test.local', TASK_AYUZA_AUTH_HMAC_KEY=secrets.token_hex(32), TASK_AYUZA_MFA_KEY=secrets.token_hex(32))
                subprocess.run([sys.executable, '-m', 'pytest', '-q', '-s', 'tests/test_m01_foundation.py', 'tests/test_m01_auth.py', 'tests/test_m01_acl.py', 'tests/test_m01_mfa_grants.py', '--tb=short'], env=test_env, check=True)
                engine.dispose()
                print('A04-A09 PASS: effective ACL and integration suite; no skipped tests', flush=True)
        finally:
            os.environ.pop('TASK_AYUZA_DATABASE_URL', None)
            pg('pg_ctl', '-D', data, '-m', 'fast', '-w', 'stop')
            print('Disposable cluster stopped; temporary directory cleanup follows.', flush=True)
    print('Disposable cluster stopped and removed. A10 requires source/diff review.', flush=True)


if __name__ == '__main__':
    main()
