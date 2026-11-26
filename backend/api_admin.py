"""WEB-MEMBERS-1: /api/v1/admin routes and MFA code entry. No business logic here.

Adding employees is an administrative mutation: the same Origin/Referer and CSRF checks as the other
mutations, a fresh MFA verification (entered through /auth/mfa/verify) and the service rules of
AclService.add_employees. A request with errors creates nothing and answers 422 with the per-row report.
"""
from typing import Any

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field, SecretStr

from backend.api_work import token
from backend.auth import AuthError
from backend.auth_http import credentials

router = APIRouter(prefix='/api/v1')


class MfaCode(BaseModel):
    code: SecretStr = Field(max_length=32)


class EmployeesInput(BaseModel):
    rows: list[dict[str, Any]] = Field(max_length=200)
    dry_run: bool = False


@router.post('/auth/mfa/verify')
def mfa_verify(data: MfaCode, request: Request):
    tok, csrf = credentials(request)
    mfa = getattr(request.app.state, 'mfa', None)
    if mfa is None:
        raise AuthError(503, 'Authentication service unavailable')
    mfa.verify(tok, csrf, data.code.get_secret_value())
    return {'ok': True}


@router.get('/admin/workspaces')
def admin_workspaces(request: Request):
    return request.app.state.acl.admin_workspaces(token(request))


@router.get('/admin/teams')
def admin_teams(request: Request):
    return request.app.state.acl.admin_teams(token(request))


@router.post('/admin/workspaces/{workspace_id}/employees')
def add_employees(workspace_id: str, data: EmployeesInput, request: Request, response: Response):
    tok, csrf = credentials(request)
    result = request.app.state.acl.add_employees(tok, csrf, workspace_id, data.rows, dry_run=data.dry_run)
    if not result['ok'] and not data.dry_run:
        response.status_code = 422
    return result
