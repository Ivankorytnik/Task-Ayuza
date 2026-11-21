"""M05.2: /api/v1 routes for labels, stages, checklists, comments, dependencies, blockers, task access and
history over the accepted services. No business logic here; same cookie, CSRF, Origin and error rules as M05.1."""
from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from backend.api_work import token, work
from backend.auth_http import credentials

router = APIRouter(prefix='/api/v1')


def given(data, skip=()):
    """Only fields the client actually sent (an explicit null differs from an absent field)."""
    return {name: getattr(data, name) for name in data.model_fields_set if name not in skip}


class Version(BaseModel):
    expected_version: int


class NameInput(BaseModel):
    name: str = Field(max_length=100)


class ActiveInput(BaseModel):
    active: bool = True


class StageCreate(BaseModel):
    title: str = Field(max_length=200)
    start_date: str | None = Field(default=None, max_length=10)
    due_date: str | None = Field(default=None, max_length=10)
    sort_order: int = 0


class StageUpdate(Version):
    changes: dict[str, Any]


class ArchiveInput(Version):
    archived: bool


class StageSet(Version):
    stage_id: str | None = Field(default=None, max_length=36)


class TextInput(BaseModel):
    text: str = Field(max_length=500)


class ChecklistChange(Version):
    text: str | None = Field(default=None, max_length=500)
    checked: bool | None = None
    deleted: bool | None = None


class BodyInput(BaseModel):
    body: str = Field(max_length=10000)


class BodyEdit(Version):
    body: str = Field(max_length=10000)


class HiddenInput(Version):
    hidden: bool


class DependencyCreate(BaseModel):
    blocker_task_id: str = Field(max_length=36)
    dependent_task_id: str = Field(max_length=36)
    reason: str = Field(default='', max_length=500)


class DependencyRemove(Version):
    reason: str = Field(max_length=500)


class BlockerCreate(BaseModel):
    title: str = Field(max_length=200)
    description: str = Field(default='', max_length=5000)
    responsible_team_id: str | None = Field(default=None, max_length=36)
    responsible_user_id: str | None = Field(default=None, max_length=36)
    blocking_task_id: str | None = Field(default=None, max_length=36)
    expected_resolution_date: str | None = Field(default=None, max_length=10)


class BlockerUpdate(Version):
    changes: dict[str, Any]


class ResolvedInput(Version):
    resolved: bool


class AccessInput(BaseModel):
    user_id: str = Field(max_length=36)
    capability: str = Field(max_length=20)
    active: bool
    reason: str = Field(max_length=500)
    expected_version: int | None = None


# ---- labels

@router.get('/workspaces/{workspace_id}/labels')
def list_labels(workspace_id: str, request: Request):
    return work(request).list_labels(token(request), workspace_id)


@router.post('/workspaces/{workspace_id}/labels')
def create_label(workspace_id: str, data: NameInput, request: Request):
    tok, csrf = credentials(request)
    return work(request).create_label(tok, csrf, workspace_id, data.name)


@router.get('/tasks/{task_id}/labels')
def task_labels(task_id: str, request: Request):
    return work(request).list_task_labels(token(request), task_id)


@router.put('/tasks/{task_id}/labels/{label_id}')
def set_task_label(task_id: str, label_id: str, data: ActiveInput, request: Request):
    tok, csrf = credentials(request)
    return work(request).set_task_label(tok, csrf, task_id, label_id, data.active)


@router.put('/projects/{project_id}/labels/{label_id}')
def set_project_label(project_id: str, label_id: str, data: ActiveInput, request: Request):
    tok, csrf = credentials(request)
    return work(request).set_project_label(tok, csrf, project_id, label_id, data.active)


# ---- stages

@router.get('/projects/{project_id}/stages')
def list_stages(project_id: str, request: Request):
    return work(request).list_stages(token(request), project_id)


@router.post('/projects/{project_id}/stages')
def create_stage(project_id: str, data: StageCreate, request: Request):
    tok, csrf = credentials(request)
    return work(request).create_stage(tok, csrf, project_id, data.title, start_date=data.start_date,
                                      due_date=data.due_date, sort_order=data.sort_order)


@router.patch('/stages/{stage_id}')
def update_stage(stage_id: str, data: StageUpdate, request: Request):
    tok, csrf = credentials(request)
    return work(request).update_stage(tok, csrf, stage_id, data.expected_version, data.changes)


@router.post('/stages/{stage_id}/archive')
def archive_stage(stage_id: str, data: ArchiveInput, request: Request):
    tok, csrf = credentials(request)
    return work(request).set_stage_archived(tok, csrf, stage_id, data.archived, data.expected_version)


@router.put('/tasks/{task_id}/stage')
def set_task_stage(task_id: str, data: StageSet, request: Request):
    tok, csrf = credentials(request)
    return work(request).set_task_stage(tok, csrf, task_id, data.stage_id, data.expected_version)


# ---- checklist

@router.get('/tasks/{task_id}/checklist')
def list_checklist(task_id: str, request: Request):
    return work(request).list_checklist(token(request), task_id)


@router.post('/tasks/{task_id}/checklist')
def add_checklist_item(task_id: str, data: TextInput, request: Request):
    tok, csrf = credentials(request)
    return work(request).add_checklist_item(tok, csrf, task_id, data.text)


@router.patch('/checklist/{item_id}')
def change_checklist_item(item_id: str, data: ChecklistChange, request: Request):
    tok, csrf = credentials(request)
    return work(request).change_checklist_item(tok, csrf, item_id, data.expected_version,
                                               **given(data, skip=('expected_version',)))


# ---- comments

@router.get('/tasks/{task_id}/comments')
def list_comments(task_id: str, request: Request):
    return work(request).list_comments(token(request), task_id)


@router.post('/tasks/{task_id}/comments')
def add_comment(task_id: str, data: BodyInput, request: Request):
    tok, csrf = credentials(request)
    return work(request).add_comment(tok, csrf, task_id, data.body)


@router.patch('/comments/{comment_id}')
def edit_comment(comment_id: str, data: BodyEdit, request: Request):
    tok, csrf = credentials(request)
    return work(request).edit_comment(tok, csrf, comment_id, data.expected_version, data.body)


@router.post('/comments/{comment_id}/delete')
def delete_comment(comment_id: str, data: Version, request: Request):
    tok, csrf = credentials(request)
    return work(request).delete_comment(tok, csrf, comment_id, data.expected_version)


@router.post('/comments/{comment_id}/hidden')
def hide_comment(comment_id: str, data: HiddenInput, request: Request):
    tok, csrf = credentials(request)
    return work(request).set_comment_hidden(tok, csrf, comment_id, data.hidden, data.expected_version)


# ---- dependencies

@router.get('/tasks/{task_id}/dependencies')
def list_dependencies(task_id: str, request: Request):
    return work(request).list_dependencies(token(request), task_id)


@router.post('/dependencies')
def add_dependency(data: DependencyCreate, request: Request):
    tok, csrf = credentials(request)
    return work(request).add_dependency(tok, csrf, data.blocker_task_id, data.dependent_task_id, data.reason)


@router.post('/dependencies/{dependency_id}/remove')
def remove_dependency(dependency_id: str, data: DependencyRemove, request: Request):
    tok, csrf = credentials(request)
    return work(request).remove_dependency(tok, csrf, dependency_id, data.reason, data.expected_version)


@router.post('/dependencies/{dependency_id}/restore')
def restore_dependency(dependency_id: str, data: Version, request: Request):
    tok, csrf = credentials(request)
    return work(request).restore_dependency(tok, csrf, dependency_id, data.expected_version)


# ---- blockers

@router.get('/tasks/{task_id}/blockers')
def list_blockers(task_id: str, request: Request, include_resolved: bool = True):
    return work(request).list_blockers(token(request), task_id, include_resolved=include_resolved)


@router.post('/tasks/{task_id}/blockers')
def create_blocker(task_id: str, data: BlockerCreate, request: Request):
    tok, csrf = credentials(request)
    return work(request).create_blocker(tok, csrf, task_id, data.title, data.description, data.responsible_team_id,
                                        data.responsible_user_id, data.blocking_task_id, data.expected_resolution_date)


@router.patch('/blockers/{blocker_id}')
def update_blocker(blocker_id: str, data: BlockerUpdate, request: Request):
    tok, csrf = credentials(request)
    return work(request).update_blocker(tok, csrf, blocker_id, data.expected_version, data.changes)


@router.post('/blockers/{blocker_id}/resolved')
def resolve_blocker(blocker_id: str, data: ResolvedInput, request: Request):
    tok, csrf = credentials(request)
    return work(request).set_blocker_resolved(tok, csrf, blocker_id, data.resolved, data.expected_version)


@router.post('/blockers/{blocker_id}/archive')
def archive_blocker(blocker_id: str, data: ArchiveInput, request: Request):
    tok, csrf = credentials(request)
    return work(request).set_blocker_archived(tok, csrf, blocker_id, data.archived, data.expected_version)


@router.get('/blockers/{blocker_id}/events')
def blocker_events(blocker_id: str, request: Request):
    return work(request).list_blocker_events(token(request), blocker_id)


# ---- task access and history

@router.get('/tasks/{task_id}/access')
def list_access(task_id: str, request: Request):
    return work(request).list_task_access(token(request), task_id)


@router.post('/tasks/{task_id}/access')
def set_access(task_id: str, data: AccessInput, request: Request):
    tok, csrf = credentials(request)
    return work(request).set_task_access(tok, csrf, task_id, data.user_id, data.capability, data.active,
                                         data.reason, expected_version=data.expected_version)


@router.get('/tasks/{task_id}/events')
def task_events(task_id: str, request: Request):
    return work(request).list_task_events(token(request), task_id)
