"""Fail closed on absent or non-PostgreSQL configuration without leaking credentials."""
from __future__ import annotations

import os
from sqlalchemy.engine import make_url

ENV_NAME = "TASK_AYUZA_DATABASE_URL"


class ConfigurationError(RuntimeError):
    pass


def database_url() -> str:
    raw = os.environ.get(ENV_NAME, "")
    if not raw:
        raise ConfigurationError("PostgreSQL database URL is not configured")
    try:
        url = make_url(raw)
        if url.drivername != "postgresql+psycopg" or not url.host or not url.database or not url.username:
            raise ValueError("unsupported or incomplete URL")
    except (ValueError, TypeError):
        raise ConfigurationError("Invalid PostgreSQL database configuration") from None
    return raw
