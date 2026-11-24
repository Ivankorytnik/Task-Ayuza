"""Read-only schema gate and M01.2 auth routes; no administrative API."""
import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from backend.acl import AclError, AclService
from backend.api_items import router as items_router
from backend.api_ops import router as ops_router
from backend.api_work import router as work_router
from backend.auth import AuthError, AuthService
from backend.auth_http import configured_origin, router, trusted_proxies
from backend.config import ConfigurationError, argon2_max_concurrent
from backend.db import make_engine, verify_schema
from backend.exports import ExportsService
from backend.passwords import GATE
from backend.scheduler import outbox_interval, outbox_loop


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
        GATE.configure(argon2_max_concurrent())
        app.state.auth = AuthService(engine,key)
        app.state.work = ExportsService(app.state.auth)
        app.state.acl = AclService(app.state.auth)
        app.state.auth_origin = origin
        app.state.trusted_proxies = trusted_proxies()
        interval = outbox_interval()
        app.state.outbox_stats = {}
        task = asyncio.create_task(outbox_loop(app.state.work, interval, app.state.outbox_stats)) if interval else None
        try:
            yield
        finally:
            if task is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
    finally:
        engine.dispose()


# Swagger UI and ReDoc load scripts from an external CDN; only the machine-readable schema stays.
app = FastAPI(title='Task-Ayuza',lifespan=lifespan,debug=False,docs_url=None,redoc_url=None)
app.include_router(router)
app.include_router(work_router)
app.include_router(items_router)
app.include_router(ops_router)
WEB_DIR = Path(__file__).resolve().parent.parent / 'web'
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


@app.get('/', include_in_schema=False)
def index():
    return RedirectResponse('/app/')


@app.middleware('http')
async def no_store(request: Request,call_next):
    try:
        response = await call_next(request)
    except Exception:
        # No raw SQL, input bodies or exception details reach clients/logs here.
        response = JSONResponse({'detail':'Authentication service unavailable'},status_code=503)
    response.headers['Cache-Control']='no-store'
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Referrer-Policy']='same-origin'
    if request.url.path.startswith('/app'):
        response.headers['Content-Security-Policy']=CSP
    return response


@app.exception_handler(AuthError)
async def auth_error(request,error):
    return JSONResponse({'detail':error.message},status_code=error.status)


@app.exception_handler(AclError)
async def acl_error(request,error):
    return JSONResponse({'detail':error.message},status_code=error.status)


@app.exception_handler(RequestValidationError)
async def validation_error(request,error):
    # FastAPI's default response includes rejected input, potentially passwords.
    return JSONResponse({'detail':'Invalid request'},status_code=422)


if WEB_DIR.is_dir():
    # Static client from the same origin (the __Host- session cookie needs one origin). Mounted last.
    app.mount('/app', StaticFiles(directory=WEB_DIR, html=True), name='web')
