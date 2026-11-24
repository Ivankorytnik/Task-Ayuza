"""Fail closed on absent or non-PostgreSQL configuration without leaking credentials."""
from __future__ import annotations

import os
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

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
    except (ValueError, TypeError, ArgumentError):
        raise ConfigurationError("Invalid PostgreSQL database configuration") from None
    return raw


def argon2_max_concurrent() -> int:
    """Simultaneous Argon2id operations per worker process (each 64 MiB); default 4."""
    raw = os.environ.get("TASK_AYUZA_ARGON2_MAX_CONCURRENT", "4").strip()
    if not (raw.isascii() and raw.isdigit()) or not 1 <= int(raw) <= 64:
        raise ConfigurationError("Invalid Argon2 concurrency configuration")
    return int(raw)
