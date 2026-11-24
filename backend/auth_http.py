"""HTTPS cookie authentication routes; no public user management endpoints."""
import ipaddress
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


def trusted_proxies():
    """Exact reverse-proxy addresses/networks from TASK_AYUZA_TRUSTED_PROXIES; empty trusts none."""
    networks = []
    for part in os.environ.get('TASK_AYUZA_TRUSTED_PROXIES', '').split(','):
        if part.strip():
            try:
                networks.append(ipaddress.ip_network(part.strip(), strict=True))
            except ValueError:
                raise ConfigurationError('Invalid trusted proxy configuration') from None
    return tuple(networks)


def client_ip(request):
    """Limiter source address. Forwarding headers count only from a configured trusted proxy.

    X-Forwarded-For is read right to left: the first hop that is not itself a trusted
    proxy is the client. A trusted peer without a usable hop fails closed instead of
    charging every user to the proxy address.
    """
    peer = request.client.host if request.client else ''
    networks = getattr(request.app.state, 'trusted_proxies', ())
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return peer  # AuthService rejects it fail-closed.
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped  # dual-stack listener reporting an IPv4 proxy
    if not any(address in network for network in networks):
        return str(address)
    hops = [hop.strip() for value in request.headers.getlist('x-forwarded-for') for hop in value.split(',')]
    for hop in reversed(hops):
        try:
            address = ipaddress.ip_address(hop)
        except ValueError:
            break
        if address.version == 6 and address.ipv4_mapped:
            address = address.ipv4_mapped
        if not any(address in network for network in networks):
            return str(address)
    raise AuthError(503, 'Authentication service unavailable')


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
    ip = client_ip(request)
    return issued(response,request.app.state.auth.prelogin(ip=ip, token=request.cookies.get(COOKIE)))


@router.post('/login')
def login(data: LoginInput,request: Request,response: Response):
    token,csrf=credentials(request)
    # Forwarding headers are honoured only from TASK_AYUZA_TRUSTED_PROXIES (client_ip).
    # The ASGI server runs with --no-proxy-headers so that this is the only decision point.
    ip=client_ip(request)
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
            data.current_password.get_secret_value() if data.current_password else None,ip=client_ip(request))
    except ValueError:
        raise AuthError(422,'Password does not satisfy policy') from None
    response.delete_cookie(COOKIE,secure=True,httponly=True,samesite='lax',path='/')
    return {'login_required':True}
