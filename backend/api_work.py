"""M05.1: /api/v1 routes for projects and tasks over the accepted services. No business logic here.

Reads need only the session cookie; every mutation needs the same Origin/Referer and CSRF checks as the
authentication routes. Service errors map to 403, 404 (identical for hidden and missing), 409 and 422.
"""
from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from backend.auth_http import COOKIE, credentials

router = APIRouter(prefix='/api/v1')


def token(request: Request) -> str:
    return request.cookies.get(COOKIE, '')


def work(request: Request):
    return request.app.state.work


class ProjectCreate(BaseModel):
    title: str = Field(max_length=200)
    description: str = Field(default='', max_length=10000)
    owner_user_id: str = Field(max_length=36)
    start_date: str | None = Field(default=None, max_length=10)
    due_date: str | None = Field(default=None, max_length=10)


class TaskCreate(BaseModel):
    title: str = Field(max_length=200)
    result_owner_user_id: str = Field(max_length=36)
    executor_team_id: str = Field(max_length=36)
    project_id: str | None = Field(default=None, max_length=36)
    description: str = Field(default='', max_length=10000)
    priority: str = Field(default='normal', max_length=10)
    assignee_user_id: str | None = Field(default=None, max_length=36)
    start_date: str | None = Field(default=None, max_length=10)
    due_date: str | None = Field(default=None, max_length=10)
    parent_task_id: str | None = Field(default=None, max_length=36)
    client_key: str | None = Field(default=None, max_length=64)


class TaskUpdate(BaseModel):
    expected_version: int
    changes: dict[str, Any]


class TaskAssign(BaseModel):
    expected_version: int
    result_owner_user_id: str | None = Field(default=None, max_length=36)
    executor_team_id: str | None = Field(default=None, max_length=36)
    assignee_user_id: str | None = Field(default=None, max_length=36)


class ArchiveInput(BaseModel):
    archived: bool
    expected_version: int


@router.get('/workspaces/{workspace_id}/projects')
def list_projects(workspace_id: str, request: Request, limit: int = 50, after: str | None = None):
    return work(request).list_projects(token(request), workspace_id, limit=limit, after=after)


@router.post('/workspaces/{workspace_id}/projects')
def create_project(workspace_id: str, data: ProjectCreate, request: Request):
    tok, csrf = credentials(request)
    return work(request).create_project(tok, csrf, workspace_id, data.title, data.description, data.owner_user_id,
                                        start_date=data.start_date, due_date=data.due_date)


@router.get('/projects/{project_id}')
def get_project(project_id: str, request: Request):
    return work(request).get_project(token(request), project_id)


@router.get('/workspaces/{workspace_id}/tasks')
def list_tasks(workspace_id: str, request: Request, status: str | None = None, limit: int = 50,
               after: str | None = None):
    return work(request).list_tasks(token(request), workspace_id, status=status, limit=limit, after=after)


@router.post('/workspaces/{workspace_id}/tasks')
def create_task(workspace_id: str, data: TaskCreate, request: Request):
    tok, csrf = credentials(request)
    values = data.model_dump(exclude={'title', 'result_owner_user_id', 'executor_team_id'})
    return work(request).create_task(tok, csrf, workspace_id, data.title, data.result_owner_user_id,
                                     data.executor_team_id, **values)


@router.get('/tasks/{task_id}')
def get_task(task_id: str, request: Request):
    return work(request).get_task(token(request), task_id)


@router.patch('/tasks/{task_id}')
def update_task(task_id: str, data: TaskUpdate, request: Request):
    tok, csrf = credentials(request)
    return work(request).update_task(tok, csrf, task_id, data.expected_version, data.changes)


@router.post('/tasks/{task_id}/assign')
def assign_task(task_id: str, data: TaskAssign, request: Request):
    tok, csrf = credentials(request)
    given = {name: getattr(data, name) for name in data.model_fields_set if name != 'expected_version'}
    return work(request).assign_task(tok, csrf, task_id, data.expected_version, **given)


@router.post('/tasks/{task_id}/archive')
def archive_task(task_id: str, data: ArchiveInput, request: Request):
    tok, csrf = credentials(request)
    return work(request).set_task_archived(tok, csrf, task_id, data.archived, data.expected_version)
