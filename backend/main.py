"""Read-only application startup gate; no UI/admin endpoints in M01.1."""
from __future__ import annotations

from contextlib import asynccontextmanager
from fastapi import FastAPI

from backend.db import make_engine, verify_schema


@asynccontextmanager
async def lifespan(app: FastAPI):
    engine = make_engine()
    try:
        verify_schema(engine)
        yield
    finally:
        engine.dispose()


app = FastAPI(title="Task-Ayuza", lifespan=lifespan)
