"""Engine/session factory: construction and startup perform no DDL or writes."""
from __future__ import annotations

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from backend.config import database_url


class SchemaVersionError(RuntimeError):
    pass


REQUIRED_REVISION = "0005_m02_projects_tasks"


def make_engine(url: str | None = None) -> Engine:
    return create_engine(url or database_url(), pool_pre_ping=True, hide_parameters=True)


def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


def verify_schema(engine: Engine) -> None:
    """Read-only revision check, never stamp/upgrade/create_all."""
    try:
        with engine.connect() as connection:
            revisions = connection.execute(
                text('SELECT version_num FROM task_ayuza.alembic_version')
            ).scalars().all()
    except Exception:
        raise SchemaVersionError("PostgreSQL schema is unavailable or uninitialized") from None
    if revisions != [REQUIRED_REVISION]:
        raise SchemaVersionError("PostgreSQL schema revision is incompatible")
