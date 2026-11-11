"""M01.1 integration tests: require disposable, manually migrated PostgreSQL.

Set TASK_AYUZA_TEST_RUNTIME_URL and TASK_AYUZA_TEST_BACKUP_URL out-of-band.
No automatic DB provisioning, migrations, seed or cleanup of actual data.
"""
from __future__ import annotations

import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError, IntegrityError

from backend.audit import create_organization, record_organization_event
from backend.config import ConfigurationError, database_url
from backend.db import SchemaVersionError, verify_schema
from backend.models import Base


def _test_url(key: str) -> str:
    raw = os.environ.get(key)
    if not raw:
        pytest.skip(f"{key} not configured; PostgreSQL integration not executed")
    parsed = make_url(raw)
    if (parsed.drivername != "postgresql+psycopg" or
        parsed.database != "task_ayuza_test" or
        parsed.host not in {"127.0.0.1", "localhost", "::1"}):
        pytest.fail("Refusing non-local or non-disposable PostgreSQL target")
    return raw


@pytest.fixture(scope="module")
def runtime_engine():
    engine = create_engine(_test_url("TASK_AYUZA_TEST_RUNTIME_URL"), hide_parameters=True)
    yield engine
    engine.dispose()


def test_a03_missing_and_invalid_url():
    with patch.dict(os.environ, {"TASK_AYUZA_DATABASE_URL": ""}):
        with pytest.raises(ConfigurationError, match="not configured"):
            database_url()
    for value in ("sqlite:///local.db", "not a url", "postgresql://user:secret@localhost/db"):
        with patch.dict(os.environ, {"TASK_AYUZA_DATABASE_URL": value}):
            with pytest.raises(ConfigurationError) as error:
                database_url()
            assert "secret" not in str(error.value)


def test_a08_snapshot_filter_unit():
    with pytest.raises(ValueError):
        from backend.audit import _safe_snapshot
        _safe_snapshot({"password_hash": "secret"})
    with pytest.raises(ValueError):
        _safe_snapshot({"name": "Allowed", "token": "secret"})


def test_a02_schema_check_is_read_only(runtime_engine):
    inspector = inspect(runtime_engine)
    assert set(inspector.get_table_names(schema="task_ayuza")) == {
        "organization", "audit_events", "alembic_version"
    }
    with runtime_engine.connect() as connection:
        before = [connection.execute(text(f"SELECT count(*) FROM task_ayuza.{table}")).scalar_one()
                  for table in ("organization", "audit_events")]
    verify_schema(runtime_engine)
    with runtime_engine.connect() as connection:
        after = [connection.execute(text(f"SELECT count(*) FROM task_ayuza.{table}")).scalar_one()
                 for table in ("organization", "audit_events")]
    assert before == after


def test_a04_runtime_cannot_ddl_or_change_revision(runtime_engine):
    statements = (
        "CREATE TABLE task_ayuza.forbidden (id int)",
        "ALTER TABLE task_ayuza.organization ADD COLUMN forbidden int",
        "DROP TABLE task_ayuza.audit_events",
        "UPDATE task_ayuza.alembic_version SET version_num='wrong'",
        "SET ROLE task_ayuza_migrator",
    )
    for stmt in statements:
        with runtime_engine.connect() as conn:
            with pytest.raises(DBAPIError):
                conn.execute(text(stmt))
            conn.rollback()


def test_a05_a08_audit_insert_is_append_only(runtime_engine):
    with runtime_engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO task_ayuza.audit_events
                (id, actor_kind, entity_kind, entity_id, action, request_id, "new")
            VALUES (:id, 'system', 'organization', :entity_id,
                    'organization.created', :request_id, CAST(:snapshot AS jsonb))
        """), {"id": uuid.uuid4(), "entity_id": uuid.uuid4(),
               "request_id": uuid.uuid4(), "snapshot": '{"name":"Synthetic"}'})
    attempts = (
        "UPDATE task_ayuza.audit_events SET action='organization.updated'",
        "DELETE FROM task_ayuza.audit_events",
        "TRUNCATE task_ayuza.audit_events",
    )
    for stmt in attempts:
        with runtime_engine.connect() as conn:
            with pytest.raises(DBAPIError):
                conn.execute(text(stmt))
            conn.rollback()
    with runtime_engine.connect() as conn:
        with pytest.raises(DBAPIError):
            conn.execute(text("""
                INSERT INTO task_ayuza.audit_events
                    (id, actor_kind, entity_kind, entity_id, action, request_id, "new")
                VALUES (:id, 'system', 'organization', :entity_id,
                        'organization.created', :request_id, '{"token":"secret"}'::jsonb)
            """), {"id": uuid.uuid4(), "entity_id": uuid.uuid4(), "request_id": uuid.uuid4()})


def test_a06_atomicity_when_audit_fails(runtime_engine):
    from sqlalchemy.orm import Session
    with pytest.raises(IntegrityError):
        with Session(runtime_engine) as session, session.begin():
            create_organization(session, name="Synthetic rollback", request_id=uuid.uuid4())
            # Wrong kind/name for the audit; the database rejects it during flush.
            record_organization_event(
                session, organization_id=uuid.uuid4(), action="organization.created",
                request_id=uuid.uuid4(), old=None, new={"name": "Synthetic"},
            )
            session.execute(text("""
                INSERT INTO task_ayuza.audit_events
                    (id, actor_kind, entity_kind, entity_id, action, request_id, "new")
                VALUES (:id, 'system', 'organization', :entity_id,
                        'organization.created', :request_id, '{"password":"bad"}'::jsonb)
            """), {"id": uuid.uuid4(), "entity_id": uuid.uuid4(), "request_id": uuid.uuid4()})
    with runtime_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM task_ayuza.organization")).scalar_one() == 0


def test_a07_singleton_concurrent(runtime_engine):
    from sqlalchemy.orm import Session
    def insert_org(_):
        try:
            with Session(runtime_engine) as session, session.begin():
                create_organization(session, name="Synthetic winner", request_id=uuid.uuid4())
            return "committed"
        except IntegrityError:
            return "conflict"
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(insert_org, range(2)))
    assert sorted(results) == ["committed", "conflict"]
    with runtime_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM task_ayuza.organization")).scalar_one() == 1
        assert conn.execute(text("SELECT count(*) FROM task_ayuza.audit_events WHERE action='organization.created'")).scalar_one() >= 1


def test_a09_backup_read_only(runtime_engine):
    backup_engine = create_engine(_test_url("TASK_AYUZA_TEST_BACKUP_URL"), hide_parameters=True)
    try:
        with backup_engine.connect() as conn:
            conn.execute(text("SELECT count(*) FROM task_ayuza.organization")).scalar_one()
            conn.execute(text("SELECT count(*) FROM task_ayuza.audit_events")).scalar_one()
        for stmt in (
            "UPDATE task_ayuza.organization SET name='forbidden'",
            "DELETE FROM task_ayuza.audit_events",
            "CREATE TABLE task_ayuza.forbidden_backup (id int)",
        ):
            with backup_engine.connect() as conn:
                with pytest.raises(DBAPIError):
                    conn.execute(text(stmt))
                conn.rollback()
    finally:
        backup_engine.dispose()


def test_a10_static_metadata():
    assert sorted(table.name for table in Base.metadata.tables.values()) == [
        "audit_events", "organization"
    ]
    assert all(table.schema == "task_ayuza" for table in Base.metadata.tables.values())
