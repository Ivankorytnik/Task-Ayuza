# M01.1 | Test-only PostgreSQL runbook

**Status:** M01.1 verified on PostgreSQL 17.11 / Python 3.13.5 on 12.11.2026; see [actual results](M01-1-RESULTS.md). Ready for independent review, not merged or deployed.

## Reproducible disposable-cluster acceptance

After installing requirements-m01.txt and PostgreSQL binaries, explicitly run:

```bash
python tests/run_m01_acceptance.py --pg-bin /path/to/postgresql/17/bin
```

The runner creates a new temporary cluster, binds only 127.0.0.1 (default port 55439), generates test-only credentials, manually runs migrations, tests actual ASGI startup and invalid revisions, checks effective privileges and runs the integration suite. It stops and removes the cluster afterwards. It does not reuse inherited database connection variables. A10 additionally requires source/diff review. An occupied port causes failure, not connection to an existing server.

The manual alternative below remains available.

## Environment
- Python 3.13; pinned free/open-source Python dependencies in `requirements-m01.txt`. Check actual PostgreSQL/driver compatibility and package licenses in an environment with network access.
- PostgreSQL administrator creates a **new empty** `task_ayuza_test` database in an isolated local test cluster. Do not use any existing database.
- Run `psql -v ON_ERROR_STOP=1 -d task_ayuza_test -f scripts/bootstrap-test.sql` as the test database administrator.
- Assign strong local test-only passwords out of band to the three roles (do not commit these credentials). Verify test roles are not members of one another and have no inherited elevated rights.
- Set `TASK_AYUZA_DATABASE_URL` to a private `postgresql+psycopg://task_ayuza_migrator:...@127.0.0.1:5432/task_ayuza_test` DSN. The migrator is **never** the application runtime role.
- Run `python -m alembic upgrade head` manually as migrator. Record `python -m alembic heads`, `SELECT version_num FROM task_ayuza.alembic_version`, table list and counts; repeat upgrade and compare (A01).
- Run `psql -v ON_ERROR_STOP=1 -d task_ayuza_test -f scripts/grant-test.sql` as administrator. Grant script assumes only this M01.1 schema and must not be used on a populated DB.
- Replace `TASK_AYUZA_DATABASE_URL` with the runtime role DSN. Set `TASK_AYUZA_TEST_RUNTIME_URL` to the same DSN and `TASK_AYUZA_TEST_BACKUP_URL` to the backup role DSN, both bound to local `task_ayuza_test`.
- Run `python -m pytest -q tests/test_m01_foundation.py` on an **unused** disposable database. It intentionally inserts synthetic rows and tests concurrent creation. Do not rerun A06/A07 after A07 has populated the singleton; create a fresh isolated database if a second full integration run is needed.
- Run the ASGI lifespan startup under runtime with an up-to-date schema; separately test nonexistent/stale/unknown revision on other **disposable test** databases (A03). Never stamp/reset an unknown database.
- Inspect effective grants, PUBLIC, schema ownership, and `has_schema_privilege`/ `has_table_privilege`, and verify `runtime` cannot CREATE in any schema it can use.
- A08 also requires checking captured exception/log text for secrets. A10 compares metadata with migration, source diff, no DDL on startup, absent production data and changed requirements.

## Important limits
- This runbook is **not evidence** that tests were executed.
- The audit allowlist is intentionally narrow (only organization name and organization action); it must be expanded by reviewed migrations before later modules.
- No users/sessions/workspaces/FKs yet, no web-admin mutation routes.
- DB owners, superusers and privileged OS administrators are outside runtime append-only protection.
- Audit can be bypassed by untrusted direct DB writes to organization; only trusted internal service operations are in scope in M01.1. In M01.2+ require all mutations to pass service/transaction audit, and consider database enforcement if direct DML can occur.
- The test-only role scripts assume default PostgreSQL behavior for PUBLIC and fresh dedicated DB. Verify effective privileges against actual cluster.

