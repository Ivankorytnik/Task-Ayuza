"""M02.1 internal work service: projects, project members and tasks (D01/D02/D04). No HTTP.

Every call goes through AuthService.protected (session, CSRF for mutations; user and session rows
locked first). Object rights are computed on the server for the concrete object and operation:
no administrator bypass; a workspace administrator or system role gets content only through an
unexpired administrative grant (D03), which also needs a fresh MFA verification. Hidden objects
answer 404, identical to missing ones. Audit events carry identifiers and enums only, never
titles or descriptions, and are written in the same transaction as the change.

Lock order: user, session, workspace_members, then project, project_members, task. Deadlocks and
serialization failures are retried by AuthService.transaction.

Deferred (not part of M02.1): project status list, stages, labels, subtasks, checklists,
comments, task_events history, task_access_grants, dependencies and blockers.
"""
from __future__ import annotations

import uuid
from datetime import date

from backend.acl import (AclError, _forbidden, _not_found, as_uuid, audit, check_version,
                         clean_text, grant_capability, membership)
from backend.auth import AuthService, execute, one
from backend.mfa import mfa_fresh

UNSET = object()
STATUSES = ('new', 'planned', 'in_progress', 'blocked', 'done', 'cancelled')
PRIORITIES = ('low', 'normal', 'high', 'critical')
PROJECT_ROLES = ('observer', 'participant', 'project_manager')
TERMINAL = frozenset({'done', 'cancelled'})
REOPEN = frozenset({'new', 'planned', 'in_progress'})
TASK_FIELDS = frozenset({'title', 'description', 'priority', 'status', 'start_date', 'due_date'})
PROJECT_FIELDS = frozenset({'title', 'description', 'start_date', 'due_date'})


def status_transition_allowed(old: str, new: str) -> bool:
    """D04: done and cancelled are terminal; no direct done<->cancelled, reopen explicitly."""
    if old == new:
        return True
    if old in TERMINAL:
        return new in REOPEN
    return True


def _date(value):
    if value is None or isinstance(value, date) and not hasattr(value, 'hour'):
        return value
    if isinstance(value, str) and len(value) == 10:
        try:
            return date.fromisoformat(value)
        except ValueError:
            pass
    raise AclError(422, 'Invalid date')


def _text(value, limit, *, required):
    if required:
        return clean_text(value, limit)
    if not isinstance(value, str) or len(value) > limit:
        raise AclError(422, 'Invalid value')
    return value


def _check_dates(start, due):
    if start is not None and due is not None and start > due:
        raise AclError(422, 'Start date is after due date')


def _grant_ok(c, s, user_id, workspace_id, capability) -> bool:
    if not grant_capability(c, user_id, workspace_id, capability):
        return False
    if not mfa_fresh(c, s):
        raise AclError(403, 'MFA required')  # an administrative grant needs MFA
    return True


def _project_role(c, user_id, project):
    if project['owner_user_id'] == user_id:
        return 'project_manager'
    row = one(c, '''SELECT role FROM task_ayuza.project_members
        WHERE project_id=:p AND user_id=:u AND active FOR SHARE''', p=project['id'], u=user_id)
    return row['role'] if row else None


def _in_team(c, user_id, team_id) -> bool:
    teams = execute(c, '''SELECT team_id FROM task_ayuza.team_members
        WHERE user_id=:u AND team_id=:t AND active ORDER BY id FOR SHARE''', u=user_id, t=team_id).scalars().all()
    if not teams:
        return False
    return execute(c, 'SELECT id FROM task_ayuza.teams WHERE id=:t AND active FOR SHARE', t=team_id).first() is not None


def _active_member(c, workspace_id, user_id):
    row = one(c, '''SELECT id FROM task_ayuza.workspace_members
        WHERE workspace_id=:w AND user_id=:u AND active FOR SHARE''', w=workspace_id, u=user_id)
    if row is None:
        raise AclError(422, 'User is not an active workspace member')


def _allowed_team(c, workspace_id, team_id):
    row = one(c, '''SELECT wt.id FROM task_ayuza.workspace_teams wt JOIN task_ayuza.teams t ON t.id = wt.team_id
        WHERE wt.workspace_id=:w AND wt.team_id=:t AND wt.active AND t.active''', w=workspace_id, t=team_id)
    if row is None:
        raise AclError(422, 'Team is not allowed in this workspace')


def _check_people(c, workspace_id, owner, team, assignee):
    _active_member(c, workspace_id, owner)
    _allowed_team(c, workspace_id, team)
    if assignee is not None:
        _active_member(c, workspace_id, assignee)
        if not _in_team(c, assignee, team):
            raise AclError(422, 'Assignee is not in the executor team')


class WorkService:
    def __init__(self, auth: AuthService):
        self.auth = auth

    # ------------------------------------------------------------------ authorization

    def _project_access(self, c, u, s, project, op):
        """op: read | manage | edit | archive | access. Returns the caller's project role."""
        wid, uid = project['workspace_id'], u['id']
        member = membership(c, uid, wid)
        role = _project_role(c, uid, project) if member else None
        caps = {'manage': 'content_edit', 'edit': 'content_edit', 'archive': 'archive_restore', 'access': 'manage_access'}
        if op == 'read':
            if role is not None:
                return role
            if _grant_ok(c, s, uid, wid, 'read'):
                return None
            raise _not_found()
        if member is not None and member['role'] != 'observer' and role == 'project_manager':
            return role
        if _grant_ok(c, s, uid, wid, caps[op]):
            return role
        raise _forbidden() if role is not None else _not_found()

    def _task_access(self, c, u, s, task, op):
        """op: read | edit | assign | archive. Returns (project, member_role, project_role)."""
        wid, uid = task['workspace_id'], u['id']
        project = None
        if task['project_id'] is not None:
            project = one(c, 'SELECT id, workspace_id, owner_user_id FROM task_ayuza.projects WHERE id=:p FOR SHARE',
                          p=task['project_id'])
        member = membership(c, uid, wid)
        prole = _project_role(c, uid, project) if (member and project) else None
        personal = uid in (task['created_by_user_id'], task['result_owner_user_id'], task['assignee_user_id'])
        readable = member is not None and (personal or prole is not None or _in_team(c, uid, task['executor_team_id']))
        ok = False
        if op == 'read':
            ok = readable
        elif member is not None and member['role'] != 'observer' and prole != 'observer':
            if op == 'edit':
                ok = personal or prole in ('participant', 'project_manager')
            else:
                ok = uid == task['result_owner_user_id'] or prole == 'project_manager'
        cap = {'read': 'read', 'edit': 'content_edit', 'assign': 'assign', 'archive': 'archive_restore'}[op]
        if not ok and _grant_ok(c, s, uid, wid, cap):
            ok = True
        if ok:
            return project, member['role'] if member else None, prole
        if readable or (op != 'read' and _grant_ok(c, s, uid, wid, 'read')):
            raise _forbidden()
        raise _not_found()

    # ------------------------------------------------------------------ projects

    def create_project(self, token, csrf, workspace_id, title, description, owner_user_id,
                       start_date=None, due_date=None, request_id=None):
        wid, owner = as_uuid(workspace_id), as_uuid(owner_user_id)
        title, description = clean_text(title, 200), _text(description, 10000, required=False)
        start, due = _date(start_date), _date(due_date)
        _check_dates(start, due)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            member = membership(c, u['id'], wid)
            if member is None:
                raise _not_found()
            if member['role'] != 'participant' and not _grant_ok(c, s, u['id'], wid, 'content_edit'):
                raise _forbidden()  # workspace administrators and observers need a grant (no bypass)
            _active_member(c, wid, owner)
            pid = uuid.uuid4()
            execute(c, '''INSERT INTO task_ayuza.projects (id, workspace_id, owner_user_id, title, description, start_date, due_date)
                VALUES (:id, :w, :o, :t, :d, :s, :due)''', id=pid, w=wid, o=owner, t=title, d=description, s=start, due=due)
            execute(c, '''INSERT INTO task_ayuza.project_members (id, project_id, workspace_id, user_id, role)
                VALUES (:id, :p, :w, :o, 'project_manager')''', id=uuid.uuid4(), p=pid, w=wid, o=owner)
            audit(c, u, s, request_id=request_id, entity_kind='project', entity_id=pid, action='project.created',
                  workspace_id=wid, old=None, new={'owner_user_id': str(owner), 'archived': False})
            return {'id': pid, 'version': 1}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def _locked_project(self, c, project_id):
        project = one(c, 'SELECT * FROM task_ayuza.projects WHERE id=:id FOR UPDATE', id=project_id)
        if project is None:
            raise _not_found()
        return project

    def update_project(self, token, csrf, project_id, expected_version, changes, request_id=None):
        pid, expected = as_uuid(project_id), check_version(expected_version)
        if not isinstance(changes, dict) or not changes or set(changes) - PROJECT_FIELDS:
            raise AclError(422, 'Invalid fields')
        values = {}
        for name, value in changes.items():
            if name == 'title':
                values[name] = clean_text(value, 200)
            elif name == 'description':
                values[name] = _text(value, 10000, required=False)
            else:
                values[name] = _date(value)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            project = self._locked_project(c, pid)
            self._project_access(c, u, s, project, 'edit')
            if project['archived_at'] is not None:
                raise AclError(409, 'Project is archived')
            if all(project[k] == v for k, v in values.items()):
                return {'id': pid, 'version': project['version'], 'changed': False}
            if expected is None or expected != project['version']:
                raise AclError(409, 'Version conflict')
            _check_dates(values.get('start_date', project['start_date']), values.get('due_date', project['due_date']))
            sets = ', '.join(f'{k}=:v_{k}' for k in values)
            row = one(c, f'''UPDATE task_ayuza.projects SET {sets}, version=version+1, updated_at=clock_timestamp()
                WHERE id=:id AND version=:version RETURNING version''', id=pid, version=expected,
                      **{f'v_{k}': v for k, v in values.items()})
            if row is None:
                raise AclError(409, 'Version conflict')
            audit(c, u, s, request_id=request_id, entity_kind='project', entity_id=pid, action='project.updated',
                  workspace_id=project['workspace_id'], old=None, new={'fields': sorted(values)})
            return {'id': pid, 'version': row['version'], 'changed': True}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def set_project_archived(self, token, csrf, project_id, archived, expected_version, request_id=None):
        pid, expected = as_uuid(project_id), check_version(expected_version)
        if not isinstance(archived, bool):
            raise AclError(422, 'Invalid value')
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            project = self._locked_project(c, pid)
            self._project_access(c, u, s, project, 'archive')
            if (project['archived_at'] is not None) == archived:
                return {'id': pid, 'version': project['version'], 'changed': False}
            if expected is None or expected != project['version']:
                raise AclError(409, 'Version conflict')
            row = one(c, '''UPDATE task_ayuza.projects SET archived_at = CASE WHEN :a THEN clock_timestamp() ELSE NULL END,
                version=version+1, updated_at=clock_timestamp() WHERE id=:id AND version=:version RETURNING version''',
                      a=archived, id=pid, version=expected)
            if row is None:
                raise AclError(409, 'Version conflict')
            audit(c, u, s, request_id=request_id, entity_kind='project', entity_id=pid,
                  action='project.archived' if archived else 'project.restored', workspace_id=project['workspace_id'],
                  old={'archived': not archived}, new={'archived': archived})
            return {'id': pid, 'version': row['version'], 'changed': True}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def set_project_member(self, token, csrf, project_id, user_id, role, active, expected_version=None, request_id=None):
        pid, target, expected = as_uuid(project_id), as_uuid(user_id), check_version(expected_version)
        if role not in PROJECT_ROLES or not isinstance(active, bool):
            raise AclError(422, 'Invalid value')
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            project = self._locked_project(c, pid)
            self._project_access(c, u, s, project, 'access')
            if project['archived_at'] is not None:
                raise AclError(409, 'Project is archived')
            if target == u['id'] or target == project['owner_user_id']:
                raise _forbidden()  # no self-change, and the owner stays project manager
            _active_member(c, project['workspace_id'], target)
            row = one(c, 'SELECT * FROM task_ayuza.project_members WHERE project_id=:p AND user_id=:u FOR UPDATE',
                      p=pid, u=target)
            if row is None:
                if expected is not None:
                    raise AclError(409, 'Version conflict')
                mid = uuid.uuid4()
                execute(c, '''INSERT INTO task_ayuza.project_members (id, project_id, workspace_id, user_id, role, active)
                    VALUES (:id, :p, :w, :u, :r, :a)''', id=mid, p=pid, w=project['workspace_id'], u=target, r=role, a=active)
                audit(c, u, s, request_id=request_id, entity_kind='project_member', entity_id=mid,
                      action='project.member_added', workspace_id=project['workspace_id'],
                      old=None, new={'role': role, 'active': active})
                return {'id': mid, 'version': 1, 'created': True}
            if row['role'] == role and row['active'] == active:
                return {'id': row['id'], 'version': row['version'], 'created': False}
            if expected is None or expected != row['version']:
                raise AclError(409, 'Version conflict')
            upd = one(c, '''UPDATE task_ayuza.project_members SET role=:r, active=:a, version=version+1,
                updated_at=clock_timestamp() WHERE id=:id AND version=:v RETURNING version''',
                      r=role, a=active, id=row['id'], v=expected)
            if upd is None:
                raise AclError(409, 'Version conflict')
            audit(c, u, s, request_id=request_id, entity_kind='project_member', entity_id=row['id'],
                  action='project.member_changed', workspace_id=project['workspace_id'],
                  old={'role': row['role'], 'active': row['active']}, new={'role': role, 'active': active})
            return {'id': row['id'], 'version': upd['version'], 'created': False}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def get_project(self, token, project_id):
        pid = as_uuid(project_id)

        def run(c, u, s):
            project = one(c, 'SELECT * FROM task_ayuza.projects WHERE id=:id', id=pid)
            if project is None:
                raise _not_found()
            self._project_access(c, u, s, project, 'read')
            return dict(project)
        return self.auth.protected(token, run)

    def list_projects(self, token, workspace_id, limit=50, after=None):
        wid, after = as_uuid(workspace_id), (as_uuid(after) if after else None)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise AclError(422, 'Invalid limit')

        def run(c, u, s):
            if membership(c, u['id'], wid) is None:
                raise _not_found()
            rows = execute(c, '''SELECT p.* FROM task_ayuza.projects p
                WHERE p.workspace_id=:w AND p.archived_at IS NULL AND (CAST(:after AS uuid) IS NULL OR p.id > CAST(:after AS uuid))
                  AND (p.owner_user_id=:u OR EXISTS (SELECT 1 FROM task_ayuza.project_members m
                       WHERE m.project_id=p.id AND m.user_id=:u AND m.active))
                ORDER BY p.id LIMIT :n''', w=wid, u=u['id'], after=after, n=limit).mappings().all()
            return [dict(r) for r in rows]
        return self.auth.protected(token, run)

    # ------------------------------------------------------------------ tasks

    def create_task(self, token, csrf, workspace_id, title, result_owner_user_id, executor_team_id,
                    project_id=None, description='', priority='normal', assignee_user_id=None,
                    start_date=None, due_date=None, request_id=None):
        wid, owner, team = as_uuid(workspace_id), as_uuid(result_owner_user_id), as_uuid(executor_team_id)
        pid = as_uuid(project_id) if project_id is not None else None
        assignee = as_uuid(assignee_user_id) if assignee_user_id is not None else None
        title, description = clean_text(title, 300), _text(description, 20000, required=False)
        if priority not in PRIORITIES:
            raise AclError(422, 'Invalid priority')
        start, due = _date(start_date), _date(due_date)
        _check_dates(start, due)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            uid = u['id']
            member = membership(c, uid, wid)
            if member is None:
                raise _not_found()  # the author must be an active workspace member; a grant alone cannot author
            project, prole = None, None
            if pid is not None:
                project = one(c, 'SELECT * FROM task_ayuza.projects WHERE id=:p AND workspace_id=:w FOR SHARE', p=pid, w=wid)
                if project is None:
                    raise _not_found()
                prole = _project_role(c, uid, project)
            can_create = member['role'] != 'observer' and (
                prole in ('participant', 'project_manager') if project else member['role'] == 'participant')
            if not can_create and not _grant_ok(c, s, uid, wid, 'content_edit'):
                raise _forbidden() if (project is None or prole is not None) else _not_found()
            if project is not None and project['archived_at'] is not None:
                raise AclError(409, 'Project is archived')
            # naming someone else as result owner is assignment (D02); the owner may pick team and assignee
            if owner != uid and prole != 'project_manager' and not _grant_ok(c, s, uid, wid, 'assign'):
                raise _forbidden()
            _check_people(c, wid, owner, team, assignee)
            tid = uuid.uuid4()
            author = uid
            execute(c, '''INSERT INTO task_ayuza.tasks (id, workspace_id, project_id, title, description, priority,
                    created_by_user_id, result_owner_user_id, executor_team_id, assignee_user_id, start_date, due_date)
                VALUES (:id, :w, :p, :t, :d, :pr, :a, :o, :team, :asg, :s, :due)''',
                    id=tid, w=wid, p=pid, t=title, d=description, pr=priority, a=author, o=owner, team=team,
                    asg=assignee, s=start, due=due)
            audit(c, u, s, request_id=request_id, entity_kind='task', entity_id=tid, action='task.created',
                  workspace_id=wid, old=None,
                  new={'status': 'new', 'priority': priority, 'project_id': str(pid) if pid else None,
                       'result_owner_user_id': str(owner), 'executor_team_id': str(team),
                       'assignee_user_id': str(assignee) if assignee else None})
            return {'id': tid, 'version': 1}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def _locked_task(self, c, task_id):
        task = one(c, 'SELECT * FROM task_ayuza.tasks WHERE id=:id FOR UPDATE', id=task_id)
        if task is None:
            raise _not_found()
        return task

    def update_task(self, token, csrf, task_id, expected_version, changes, request_id=None):
        tid, expected = as_uuid(task_id), check_version(expected_version)
        if not isinstance(changes, dict) or not changes or set(changes) - TASK_FIELDS:
            raise AclError(422, 'Invalid fields')
        values = {}
        for name, value in changes.items():
            if name == 'title':
                values[name] = clean_text(value, 300)
            elif name == 'description':
                values[name] = _text(value, 20000, required=False)
            elif name == 'priority':
                if value not in PRIORITIES:
                    raise AclError(422, 'Invalid priority')
                values[name] = value
            elif name == 'status':
                if value not in STATUSES:
                    raise AclError(422, 'Invalid status')
                values[name] = value
            else:
                values[name] = _date(value)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            task = self._locked_task(c, tid)
            self._task_access(c, u, s, task, 'edit')
            if task['archived_at'] is not None:
                raise AclError(409, 'Task is archived')
            if all(task[k] == v for k, v in values.items()):
                return {'id': tid, 'version': task['version'], 'changed': False}
            if expected is None or expected != task['version']:
                raise AclError(409, 'Version conflict')
            new_status = values.get('status', task['status'])
            if not status_transition_allowed(task['status'], new_status):
                raise AclError(422, 'Status transition is not allowed')
            _check_dates(values.get('start_date', task['start_date']), values.get('due_date', task['due_date']))
            sets = [f'{k}=:v_{k}' for k in values]
            if 'status' in values and new_status != task['status']:
                sets.append("closed_at = CASE WHEN CAST(:v_status AS text) = 'done' THEN clock_timestamp() ELSE NULL END")
            row = one(c, f'''UPDATE task_ayuza.tasks SET {', '.join(sets)}, version=version+1, updated_at=clock_timestamp()
                WHERE id=:id AND version=:version RETURNING version''', id=tid, version=expected,
                      **{f'v_{k}': v for k, v in values.items()})
            if row is None:
                raise AclError(409, 'Version conflict')
            if new_status != task['status']:
                audit(c, u, s, request_id=request_id, entity_kind='task', entity_id=tid, action='task.status_changed',
                      workspace_id=task['workspace_id'], old={'status': task['status']}, new={'status': new_status})
            others = sorted(k for k in values if k != 'status' and task[k] != values[k])
            if others:
                audit(c, u, s, request_id=request_id, entity_kind='task', entity_id=tid, action='task.updated',
                      workspace_id=task['workspace_id'], old=None, new={'fields': others})
            return {'id': tid, 'version': row['version'], 'changed': True}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def assign_task(self, token, csrf, task_id, expected_version, result_owner_user_id=UNSET,
                    executor_team_id=UNSET, assignee_user_id=UNSET, request_id=None):
        tid, expected = as_uuid(task_id), check_version(expected_version)
        owner = as_uuid(result_owner_user_id) if result_owner_user_id is not UNSET else UNSET
        team = as_uuid(executor_team_id) if executor_team_id is not UNSET else UNSET
        assignee = UNSET if assignee_user_id is UNSET else (None if assignee_user_id is None else as_uuid(assignee_user_id))
        if owner is UNSET and team is UNSET and assignee is UNSET:
            raise AclError(422, 'Nothing to change')
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            task = self._locked_task(c, tid)
            self._task_access(c, u, s, task, 'assign')
            if task['archived_at'] is not None:
                raise AclError(409, 'Task is archived')
            new_owner = task['result_owner_user_id'] if owner is UNSET else owner
            new_team = task['executor_team_id'] if team is UNSET else team
            new_assignee = task['assignee_user_id'] if assignee is UNSET else assignee
            if (new_owner, new_team, new_assignee) == (task['result_owner_user_id'], task['executor_team_id'],
                                                       task['assignee_user_id']):
                return {'id': tid, 'version': task['version'], 'changed': False}
            if expected is None or expected != task['version']:
                raise AclError(409, 'Version conflict')
            _check_people(c, task['workspace_id'], new_owner, new_team, new_assignee)
            row = one(c, '''UPDATE task_ayuza.tasks SET result_owner_user_id=:o, executor_team_id=:t, assignee_user_id=:a,
                version=version+1, updated_at=clock_timestamp() WHERE id=:id AND version=:v RETURNING version''',
                      o=new_owner, t=new_team, a=new_assignee, id=tid, v=expected)
            if row is None:
                raise AclError(409, 'Version conflict')
            def snap(o, t, a):
                return {'result_owner_user_id': str(o), 'executor_team_id': str(t),
                        'assignee_user_id': str(a) if a else None}
            audit(c, u, s, request_id=request_id, entity_kind='task', entity_id=tid, action='task.assigned',
                  workspace_id=task['workspace_id'],
                  old=snap(task['result_owner_user_id'], task['executor_team_id'], task['assignee_user_id']),
                  new=snap(new_owner, new_team, new_assignee))
            return {'id': tid, 'version': row['version'], 'changed': True}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def set_task_archived(self, token, csrf, task_id, archived, expected_version, request_id=None):
        tid, expected = as_uuid(task_id), check_version(expected_version)
        if not isinstance(archived, bool):
            raise AclError(422, 'Invalid value')
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            task = self._locked_task(c, tid)
            self._task_access(c, u, s, task, 'archive')
            if (task['archived_at'] is not None) == archived:
                return {'id': tid, 'version': task['version'], 'changed': False}
            if expected is None or expected != task['version']:
                raise AclError(409, 'Version conflict')
            row = one(c, '''UPDATE task_ayuza.tasks SET archived_at = CASE WHEN :a THEN clock_timestamp() ELSE NULL END,
                version=version+1, updated_at=clock_timestamp() WHERE id=:id AND version=:v RETURNING version''',
                      a=archived, id=tid, v=expected)
            if row is None:
                raise AclError(409, 'Version conflict')
            audit(c, u, s, request_id=request_id, entity_kind='task', entity_id=tid,
                  action='task.archived' if archived else 'task.restored', workspace_id=task['workspace_id'],
                  old={'archived': not archived}, new={'archived': archived})
            return {'id': tid, 'version': row['version'], 'changed': True}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def get_task(self, token, task_id):
        tid = as_uuid(task_id)

        def run(c, u, s):
            task = one(c, 'SELECT * FROM task_ayuza.tasks WHERE id=:id', id=tid)
            if task is None:
                raise _not_found()
            self._task_access(c, u, s, task, 'read')
            return dict(task)
        return self.auth.protected(token, run)

    def list_tasks(self, token, workspace_id, status=None, limit=50, after=None):
        """Stable pagination by id. Only tasks the caller can read; a read grant opens the workspace."""
        wid, after = as_uuid(workspace_id), (as_uuid(after) if after else None)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise AclError(422, 'Invalid limit')
        if status is not None and status not in STATUSES:
            raise AclError(422, 'Invalid status')

        def run(c, u, s):
            member = membership(c, u['id'], wid)
            everything = _grant_ok(c, s, u['id'], wid, 'read')
            if member is None and not everything:
                raise _not_found()
            rows = execute(c, '''SELECT t.* FROM task_ayuza.tasks t
                WHERE t.workspace_id=:w AND t.archived_at IS NULL AND (CAST(:status AS text) IS NULL OR t.status=CAST(:status AS text))
                  AND (CAST(:after AS uuid) IS NULL OR t.id > CAST(:after AS uuid))
                  AND (CAST(:everything AS boolean) OR (CAST(:member AS boolean) AND (
                       CAST(:u AS uuid) IN (t.created_by_user_id, t.result_owner_user_id, t.assignee_user_id)
                       OR EXISTS (SELECT 1 FROM task_ayuza.team_members tm JOIN task_ayuza.teams tt ON tt.id = tm.team_id
                                  WHERE tm.user_id=:u AND tm.team_id=t.executor_team_id AND tm.active AND tt.active)
                       OR (t.project_id IS NOT NULL AND (
                           EXISTS (SELECT 1 FROM task_ayuza.project_members pm
                                   WHERE pm.project_id=t.project_id AND pm.user_id=:u AND pm.active)
                           OR EXISTS (SELECT 1 FROM task_ayuza.projects pr
                                      WHERE pr.id=t.project_id AND pr.owner_user_id=:u))))))
                ORDER BY t.id LIMIT :n''', w=wid, u=u['id'], status=status, after=after, n=limit,
                           everything=everything, member=member is not None).mappings().all()
            return [dict(r) for r in rows]
        return self.auth.protected(token, run)
