"""HTTPS cookie authentication routes; no public user management endpoints."""
import os
from urllib.parse import urlsplit

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field, SecretStr

from backend.auth import AuthError
from backend.config import ConfigurationError

COOKIE = '__Host-ay_session'
router = APIRouter(prefix='/api/v1/auth')


def configured_origin():
    origin = os.environ.get('TASK_AYUZA_ORIGIN','')
    try:
        parts = urlsplit(origin)
        if (parts.scheme != 'https' or not parts.hostname or parts.username or parts.password
            or parts.path or parts.query or parts.fragment or parts.port == 0):
            raise ValueError()
    except ValueError:
        raise ConfigurationError('Invalid authentication origin') from None
    return origin


def verify_origin(request):
    expected = request.app.state.auth_origin
    origin = request.headers.get('origin')
    if origin is not None:
        valid = origin == expected
    else:
        referer = request.headers.get('referer')
        try:
            p = urlsplit(referer or '')
            valid = bool(referer) and not p.username and not p.password and f'{p.scheme}://{p.netloc}' == expected
        except ValueError:
            valid = False
    if not valid:
        raise AuthError(403,'Request verification failed')


def credentials(request):
    verify_origin(request)
    csrf = request.headers.get('x-csrf-token')
    if not csrf:
        raise AuthError(403,'Request verification failed')
    return request.cookies.get(COOKIE,''), csrf


def issued(response, result):
    response.set_cookie(COOKIE,result['token'],secure=True,httponly=True,samesite='lax',path='/')
    return {'csrf_token':result['csrf_token'],'password_change_required':result['kind']=='password'}


class LoginInput(BaseModel):
    login: str = Field(max_length=256)
    password: SecretStr = Field(max_length=128)


class PasswordInput(BaseModel):
    new_password: SecretStr = Field(max_length=128)
    current_password: SecretStr | None = Field(default=None,max_length=128)


@router.get('/prelogin')
def prelogin(request: Request,response: Response):
    # Same-origin check required even for bootstrap. Caller sends Referer/Origin.
    verify_origin(request)
    return issued(response,request.app.state.auth.prelogin())


@router.post('/login')
def login(data: LoginInput,request: Request,response: Response):
    token,csrf=credentials(request)
    # Deliberately ignore all client-supplied forwarding headers. ASGI server must
    # run with --no-proxy-headers unless a separately reviewed trusted proxy exists.
    ip=request.client.host if request.client else ''
    result=request.app.state.auth.login(data.login,data.password.get_secret_value(),ip,token,csrf)
    return issued(response,result)


@router.get('/me')
def me(request: Request):
    return request.app.state.auth.me(request.cookies.get(COOKIE,''))


@router.post('/renew')
def renew(request: Request):
    token,csrf=credentials(request)
    request.app.state.auth.renew(token,csrf)
    return {'ok':True}


@router.post('/logout')
def logout(request: Request,response: Response):
    token,csrf=credentials(request)
    request.app.state.auth.logout(token,csrf)
    response.delete_cookie(COOKIE,secure=True,httponly=True,samesite='lax',path='/')
    return {'ok':True}


@router.post('/password')
def password(data: PasswordInput,request: Request,response: Response):
    token,csrf=credentials(request)
    try:
        request.app.state.auth.change_password(token,csrf,data.new_password.get_secret_value(),
            data.current_password.get_secret_value() if data.current_password else None)
    except ValueError:
        raise AuthError(422,'Password does not satisfy policy') from None
    response.delete_cookie(COOKIE,secure=True,httponly=True,samesite='lax',path='/')
    return {'login_required':True}
