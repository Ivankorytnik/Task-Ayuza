"""M05.3: /api/v1 routes for notifications, the risk center, task export and release metadata over the accepted
services. No business logic here; same cookie, CSRF, Origin and error rules as M05.1. The outbox processor is a
system operation and is deliberately not exposed."""
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from backend.api_items import ArchiveInput, given  # noqa: F401
from backend.api_work import token, work
from backend.auth_http import credentials

router = APIRouter(prefix='/api/v1')


class RiskCreate(BaseModel):
    category: str = Field(max_length=20)
    description: str = Field(max_length=2000)
    probability: int
    impact: int
    owner_user_id: str | None = Field(default=None, max_length=36)
    owner_team_id: str | None = Field(default=None, max_length=36)
    measures: str = Field(default='', max_length=5000)
    due_date: str | None = Field(default=None, max_length=10)


class RiskUpdate(BaseModel):
    expected_version: int
    changes: dict[str, Any]


class CheckInput(BaseModel):
    result: str = Field(max_length=8)
    evidence_reference: str | None = Field(default=None, max_length=500)
    valid_until: str | None = Field(default=None, max_length=40)


class LinkedInput(BaseModel):
    linked: bool


class ExportInput(BaseModel):
    format: str = Field(max_length=4)
    status: str | None = Field(default=None, max_length=12)


# ---- notifications

@router.get('/notifications')
def list_notifications(request: Request, unread_only: bool = False, limit: int = 50):
    return work(request).list_notifications(token(request), unread_only=unread_only, limit=limit)


@router.get('/notifications/unread-count')
def unread_count(request: Request):
    return {'count': work(request).count_unread(token(request))}


@router.post('/notifications/{notification_id}/read')
def mark_read(notification_id: str, request: Request):
    tok, csrf = credentials(request)
    return work(request).mark_read(tok, csrf, notification_id)


# ---- release metadata

@router.get('/release')
def release(request: Request):
    return work(request).release_info(token(request))


# ---- risk center

@router.get('/risks')
def list_risks(request: Request, control_status: str | None = None, include_archived: bool = False,
               limit: int = 50, after: str | None = None):
    return work(request).list_risks(token(request), control_status=control_status,
                                    include_archived=include_archived, limit=limit, after=after)


@router.post('/risks')
def create_risk(data: RiskCreate, request: Request):
    tok, csrf = credentials(request)
    return work(request).create_risk(tok, csrf, **data.model_dump())


@router.get('/risks/{risk_id}')
def get_risk(risk_id: str, request: Request):
    return work(request).get_risk(token(request), risk_id)


@router.patch('/risks/{risk_id}')
def update_risk(risk_id: str, data: RiskUpdate, request: Request):
    tok, csrf = credentials(request)
    return work(request).update_risk(tok, csrf, risk_id, data.expected_version, data.changes)


@router.post('/risks/{risk_id}/archive')
def archive_risk(risk_id: str, data: ArchiveInput, request: Request):
    tok, csrf = credentials(request)
    return work(request).set_risk_archived(tok, csrf, risk_id, data.archived, data.expected_version)


@router.get('/risks/{risk_id}/checks')
def list_checks(risk_id: str, request: Request):
    return work(request).list_checks(token(request), risk_id)


@router.post('/risks/{risk_id}/checks')
def record_check(risk_id: str, data: CheckInput, request: Request):
    tok, csrf = credentials(request)
    return work(request).record_check(tok, csrf, risk_id, data.result, data.evidence_reference, data.valid_until)


@router.get('/risks/{risk_id}/links')
def list_links(risk_id: str, request: Request):
    return work(request).list_risk_links(token(request), risk_id)


@router.put('/risks/{risk_id}/tasks/{task_id}')
def link_task(risk_id: str, task_id: str, data: LinkedInput, request: Request):
    tok, csrf = credentials(request)
    return work(request).set_risk_task_link(tok, csrf, risk_id, task_id, data.linked)


@router.put('/risks/{risk_id}/blockers/{blocker_id}')
def link_blocker(risk_id: str, blocker_id: str, data: LinkedInput, request: Request):
    tok, csrf = credentials(request)
    return work(request).set_risk_blocker_link(tok, csrf, risk_id, blocker_id, data.linked)


# ---- export (the content is returned once and never stored)

@router.post('/workspaces/{workspace_id}/exports')
def export_tasks(workspace_id: str, data: ExportInput, request: Request):
    tok, csrf = credentials(request)
    out = work(request).export_tasks(tok, csrf, workspace_id, data.format, status=data.status)
    media = 'text/csv; charset=utf-8' if out['format'] == 'csv' else 'application/json'
    return Response(content=out['content'].encode('utf-8'), media_type=media,
                    headers={'Content-Disposition': f'attachment; filename="tasks.{out["format"]}"',
                             'X-Export-Event-Id': str(out['event_id']), 'X-Export-Row-Count': str(out['row_count'])})
