"""Manual migrations only: never run from application import or startup."""
from __future__ import annotations

from alembic import context
from sqlalchemy import engine_from_config, pool

from backend.config import database_url
from backend.models import Base, SCHEMA

config = context.config
config.set_main_option("sqlalchemy.url", database_url().replace("%", "%%"))
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=database_url(), target_metadata=target_metadata,
        version_table_schema=SCHEMA, include_schemas=True,
        literal_binds=True, dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.", poolclass=pool.NullPool, hide_parameters=True,
    )
    try:
        with connectable.connect() as connection:
            context.configure(
                connection=connection, target_metadata=target_metadata,
                version_table_schema=SCHEMA, include_schemas=True,
                compare_type=True,
            )
            with context.begin_transaction():
                context.run_migrations()
    finally:
        connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
