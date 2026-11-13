"""Read-only schema gate and M01.2 auth routes; no administrative API."""
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from backend.auth import AuthError, AuthService
from backend.auth_http import configured_origin, router
from backend.config import ConfigurationError
from backend.db import make_engine, verify_schema


@asynccontextmanager
async def lifespan(app: FastAPI):
    engine = make_engine()
    try:
        verify_schema(engine)
        origin = configured_origin()
        try:
            key = bytes.fromhex(os.environ.get('TASK_AYUZA_AUTH_HMAC_KEY',''))
            if len(key)<32:
                raise ValueError()
        except ValueError:
            raise ConfigurationError('Authentication key is not configured correctly') from None
        app.state.auth = AuthService(engine,key)
        app.state.auth_origin = origin
        yield
    finally:
        engine.dispose()


app = FastAPI(title='Task-Ayuza',lifespan=lifespan,debug=False)
app.include_router(router)


@app.middleware('http')
async def no_store(request: Request,call_next):
    try:
        response = await call_next(request)
    except Exception:
        # No raw SQL, input bodies or exception details reach clients/logs here.
        response = JSONResponse({'detail':'Authentication service unavailable'},status_code=503)
    response.headers['Cache-Control']='no-store'
    return response


@app.exception_handler(AuthError)
async def auth_error(request,error):
    return JSONResponse({'detail':error.message},status_code=error.status)


@app.exception_handler(RequestValidationError)
async def validation_error(request,error):
    # FastAPI's default response includes rejected input, potentially passwords.
    return JSONResponse({'detail':'Invalid request'},status_code=422)
