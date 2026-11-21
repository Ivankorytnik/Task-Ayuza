"""M03.1 internal service: task dependencies and blockers (D04/D05). No HTTP.

Dependency "A blocks B" is a directed edge. Creating, removing or restoring an edge needs the link
capability on both tasks; cycles are rejected under one advisory lock for the whole graph, so two
concurrent opposite edges cannot both commit. A reader of one task sees the other side only if it
can read that task too; otherwise only a counter of hidden external dependencies is returned, with
no id, title, status, dates or people. A dependency never changes any task status.

A blocker is a fact obstructing a task. Creating, changing, resolving, reopening or archiving it
needs edit on the blocked task; it needs a responsible person and/or team (D05). Naming a
responsible person never opens the task to them, and the optional blocking task is shown only to a
reader who can read it. History (blocker_events) is append-only.
"""
from __future__ import annotations

import uuid

from backend.acl import AclError, _not_found, as_uuid, audit, check_version, clean_text
from backend.auth import execute, one
from backend.outbox import enqueue, people
from backend.work import _date
from backend.work_items import ItemsService

GRAPH_LOCK = 7001
BLOCKER_FIELDS = frozenset({'title', 'description', 'responsible_team_id', 'responsible_user_id',
                            'expected_resolution_date', 'blocking_task_id'})


class LinksService(ItemsService):
    def _task(self, c, task_id):
        task = one(c, 'SELECT * FROM task_ayuza.tasks WHERE id=:id', id=task_id)
        if task is None:
            raise _not_found()
        return task

    def _can(self, c, u, s, task, op) -> bool:
        try:
            self._task_access(c, u, s, task, op)
            return True
        except AclError:
            return False

    def _audit_edge(self, c, u, s, request_id, edge_id, action, tasks):
        seen = set()
        for task in tasks:  # one row per involved workspace; no foreign task id inside
            if task['workspace_id'] in seen:
                continue
            seen.add(task['workspace_id'])
            audit(c, u, s, request_id=request_id, entity_kind='task_dependency', entity_id=edge_id, action=action,
                  workspace_id=task['workspace_id'], old=None, new={'active': action != 'dependency.removed'})

    def _notify_edge(self, c, u, edge_id, version, tasks):
        for task in tasks:  # each side is told about its own task only; no foreign id or title is stored
            enqueue(c, actor_id=u['id'], task=task, event_type='dependency_changed', source_id=edge_id,
                    source_key=f'{edge_id}:v{version}', recipients=people(task))

    def _would_cycle(self, c, blocker_id, dependent_id) -> bool:
        return execute(c, '''WITH RECURSIVE walk(id) AS (
                SELECT CAST(:start AS uuid)
                UNION
                SELECT d.dependent_task_id FROM task_ayuza.task_dependencies d JOIN walk w ON d.blocker_task_id = w.id
                WHERE d.deleted_at IS NULL)
            SELECT 1 FROM walk WHERE id = CAST(:target AS uuid) LIMIT 1''',
                       start=dependent_id, target=blocker_id).first() is not None

    # ------------------------------------------------------------------ dependencies

    def add_dependency(self, token, csrf, blocker_task_id, dependent_task_id, reason='', request_id=None):
        bid, did = as_uuid(blocker_task_id), as_uuid(dependent_task_id)
        if bid == did:
            raise AclError(422, 'A task cannot depend on itself')
        if not isinstance(reason, str) or len(reason) > 500:
            raise AclError(422, 'Invalid value')
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            execute(c, 'SELECT pg_advisory_xact_lock(:k)', k=GRAPH_LOCK)
            dependent, blocker = self._task(c, did), self._task(c, bid)
            self._task_access(c, u, s, dependent, 'link')
            self._task_access(c, u, s, blocker, 'link')
            if dependent['archived_at'] is not None or blocker['archived_at'] is not None:
                raise AclError(409, 'Archived task')
            existing = one(c, '''SELECT id, version FROM task_ayuza.task_dependencies
                WHERE blocker_task_id=:b AND dependent_task_id=:d AND deleted_at IS NULL''', b=bid, d=did)
            if existing is not None:
                return {'id': existing['id'], 'version': existing['version'], 'created': False}
            if self._would_cycle(c, bid, did):
                raise AclError(422, 'Dependency would create a cycle')
            eid = uuid.uuid4()
            execute(c, '''INSERT INTO task_ayuza.task_dependencies (id, blocker_task_id, dependent_task_id, reason, created_by)
                VALUES (:id, :b, :d, :r, :u)''', id=eid, b=bid, d=did, r=reason, u=u['id'])
            self._audit_edge(c, u, s, request_id, eid, 'dependency.created', [dependent, blocker])
            self._notify_edge(c, u, eid, 1, [dependent, blocker])
            return {'id': eid, 'version': 1, 'created': True}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def _edge_with_tasks(self, c, u, s, edge_id):
        edge = one(c, 'SELECT * FROM task_ayuza.task_dependencies WHERE id=:id FOR UPDATE', id=edge_id)
        if edge is None:
            raise _not_found()
        dependent, blocker = self._task(c, edge['dependent_task_id']), self._task(c, edge['blocker_task_id'])
        self._task_access(c, u, s, dependent, 'link')
        self._task_access(c, u, s, blocker, 'link')
        return edge, dependent, blocker

    def remove_dependency(self, token, csrf, dependency_id, reason, expected_version=None, request_id=None):
        eid, expected, reason = as_uuid(dependency_id), check_version(expected_version), clean_text(reason, 500)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            execute(c, 'SELECT pg_advisory_xact_lock(:k)', k=GRAPH_LOCK)
            edge, dependent, blocker = self._edge_with_tasks(c, u, s, eid)
            if edge['deleted_at'] is not None:
                return {'id': eid, 'version': edge['version'], 'changed': False}
            if expected is None or expected != edge['version']:
                raise AclError(409, 'Version conflict')
            row = one(c, '''UPDATE task_ayuza.task_dependencies SET deleted_at=clock_timestamp(), deleted_by=:u,
                deletion_reason=:r, version=version+1 WHERE id=:id AND version=:v RETURNING version''',
                      u=u['id'], r=reason, id=eid, v=expected)
            if row is None:
                raise AclError(409, 'Version conflict')
            self._audit_edge(c, u, s, request_id, eid, 'dependency.removed', [dependent, blocker])
            self._notify_edge(c, u, eid, row['version'], [dependent, blocker])
            return {'id': eid, 'version': row['version'], 'changed': True}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def restore_dependency(self, token, csrf, dependency_id, expected_version=None, request_id=None):
        eid, expected = as_uuid(dependency_id), check_version(expected_version)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            execute(c, 'SELECT pg_advisory_xact_lock(:k)', k=GRAPH_LOCK)
            edge, dependent, blocker = self._edge_with_tasks(c, u, s, eid)
            if edge['deleted_at'] is None:
                return {'id': eid, 'version': edge['version'], 'changed': False}
            if expected is None or expected != edge['version']:
                raise AclError(409, 'Version conflict')
            if dependent['archived_at'] is not None or blocker['archived_at'] is not None:
                raise AclError(409, 'Archived task')
            if one(c, '''SELECT 1 AS x FROM task_ayuza.task_dependencies WHERE blocker_task_id=:b
                AND dependent_task_id=:d AND deleted_at IS NULL''', b=blocker['id'], d=dependent['id']):
                raise AclError(409, 'An active dependency already exists')
            if self._would_cycle(c, blocker['id'], dependent['id']):
                raise AclError(422, 'Dependency would create a cycle')
            row = one(c, '''UPDATE task_ayuza.task_dependencies SET deleted_at=NULL, deleted_by=NULL, deletion_reason=NULL,
                version=version+1 WHERE id=:id AND version=:v RETURNING version''', id=eid, v=expected)
            if row is None:
                raise AclError(409, 'Version conflict')
            self._audit_edge(c, u, s, request_id, eid, 'dependency.restored', [dependent, blocker])
            self._notify_edge(c, u, eid, row['version'], [dependent, blocker])
            return {'id': eid, 'version': row['version'], 'changed': True}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def list_dependencies(self, token, task_id):
        """Visible edges with the other task's basics; hidden ones only as a counter (no ids, titles, statuses)."""
        tid = as_uuid(task_id)

        def run(c, u, s):
            task = self._task(c, tid)
            self._task_access(c, u, s, task, 'read')
            visible, hidden = [], 0
            for edge in execute(c, '''SELECT * FROM task_ayuza.task_dependencies
                WHERE deleted_at IS NULL AND (blocker_task_id=:t OR dependent_task_id=:t) ORDER BY id''',
                                t=tid).mappings().all():
                blocked_by = edge['dependent_task_id'] == tid
                other = self._task(c, edge['blocker_task_id'] if blocked_by else edge['dependent_task_id'])
                if self._can(c, u, s, other, 'read'):
                    visible.append({'id': edge['id'], 'direction': 'blocked_by' if blocked_by else 'blocks',
                                    'task_id': other['id'], 'title': other['title'], 'status': other['status'],
                                    'reason': edge['reason'], 'version': edge['version']})
                else:
                    hidden += 1
            return {'edges': visible, 'hidden_external': hidden,
                    'has_active_dependencies': any(e['direction'] == 'blocked_by' and e['status'] != 'done'
                                                   for e in visible)}
        return self.auth.protected(token, run)

    # ------------------------------------------------------------------ blockers

    def _check_responsible(self, c, u, team_id, user_id):
        if team_id is None and user_id is None:
            raise AclError(422, 'A responsible person or team is required')
        if user_id is not None and one(c, '''SELECT 1 AS x FROM task_ayuza.users
                WHERE id=:id AND organization_id=:o AND active''', id=user_id, o=u['organization_id']) is None:
            raise AclError(422, 'Responsible user is not available')
        if team_id is not None and one(c, '''SELECT 1 AS x FROM task_ayuza.teams
                WHERE id=:id AND organization_id=:o AND active''', id=team_id, o=u['organization_id']) is None:
            raise AclError(422, 'Responsible team is not available')

    def _blocker_event(self, c, u, blocker_id, event_type):
        row = one(c, 'SELECT * FROM task_ayuza.blockers WHERE id=:id', id=blocker_id)
        execute(c, '''INSERT INTO task_ayuza.blocker_events
            (id, blocker_id, actor_user_id, event_type, resulting_version, blocking_task_id_snapshot,
             responsible_team_id_snapshot, responsible_user_id_snapshot, expected_resolution_date_snapshot)
            VALUES (:id, :b, :a, :t, :v, :bt, :team, :user, :due)''',
                id=uuid.uuid4(), b=blocker_id, a=u['id'], t=event_type, v=row['version'], bt=row['blocking_task_id'],
                team=row['responsible_team_id'], user=row['responsible_user_id'], due=row['expected_resolution_date'])

    def _blocker_audit(self, c, u, s, request_id, blocker, action, new):
        audit(c, u, s, request_id=request_id, entity_kind='blocker', entity_id=blocker['id'], action=action,
              workspace_id=blocker['workspace_id'], old=None, new=new)

    def create_blocker(self, token, csrf, blocked_task_id, title, description='', responsible_team_id=None,
                       responsible_user_id=None, blocking_task_id=None, expected_resolution_date=None, request_id=None):
        tid = as_uuid(blocked_task_id)
        title = clean_text(title, 200)
        if not isinstance(description, str) or len(description) > 5000:
            raise AclError(422, 'Invalid value')
        team = as_uuid(responsible_team_id) if responsible_team_id is not None else None
        user = as_uuid(responsible_user_id) if responsible_user_id is not None else None
        blocking = as_uuid(blocking_task_id) if blocking_task_id is not None else None
        due = _date(expected_resolution_date)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            task = self._task(c, tid)
            self._task_access(c, u, s, task, 'edit')
            if task['archived_at'] is not None:
                raise AclError(409, 'Task is archived')
            self._check_responsible(c, u, team, user)
            if blocking is not None:
                if blocking == tid:
                    raise AclError(422, 'A task cannot block itself')
                self._task_access(c, u, s, self._task(c, blocking), 'read')
            bid = uuid.uuid4()
            execute(c, '''INSERT INTO task_ayuza.blockers (id, workspace_id, blocked_task_id, blocking_task_id, title,
                    description, responsible_team_id, responsible_user_id, expected_resolution_date, created_by)
                VALUES (:id, :w, :t, :bt, :title, :d, :team, :user, :due, :u)''',
                    id=bid, w=task['workspace_id'], t=tid, bt=blocking, title=title, d=description, team=team,
                    user=user, due=due, u=u['id'])
            self._blocker_event(c, u, bid, 'created')
            self._blocker_audit(c, u, s, request_id, {'id': bid, 'workspace_id': task['workspace_id']},
                                'blocker.created', {'active': True})
            return {'id': bid, 'version': 1}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def _locked_blocker(self, c, u, s, blocker_id, op='edit'):
        blocker = one(c, 'SELECT * FROM task_ayuza.blockers WHERE id=:id FOR UPDATE', id=blocker_id)
        if blocker is None:
            raise _not_found()
        task = self._task(c, blocker['blocked_task_id'])
        self._task_access(c, u, s, task, op)
        return blocker, task

    def update_blocker(self, token, csrf, blocker_id, expected_version, changes, request_id=None):
        bid, expected = as_uuid(blocker_id), check_version(expected_version)
        if not isinstance(changes, dict) or not changes or set(changes) - BLOCKER_FIELDS:
            raise AclError(422, 'Invalid fields')
        values = {}
        for name, value in changes.items():
            if name == 'title':
                values[name] = clean_text(value, 200)
            elif name == 'description':
                if not isinstance(value, str) or len(value) > 5000:
                    raise AclError(422, 'Invalid value')
                values[name] = value
            elif name == 'expected_resolution_date':
                values[name] = _date(value)
            else:
                values[name] = as_uuid(value) if value is not None else None
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            blocker, task = self._locked_blocker(c, u, s, bid)
            if blocker['archived_at'] is not None or task['archived_at'] is not None:
                raise AclError(409, 'Archived')
            if all(blocker[k] == v for k, v in values.items()):
                return {'id': bid, 'version': blocker['version'], 'changed': False}
            if expected is None or expected != blocker['version']:
                raise AclError(409, 'Version conflict')
            self._check_responsible(c, u, values.get('responsible_team_id', blocker['responsible_team_id']),
                                    values.get('responsible_user_id', blocker['responsible_user_id']))
            new_blocking = values.get('blocking_task_id')
            if new_blocking is not None and new_blocking != blocker['blocking_task_id']:
                if new_blocking == blocker['blocked_task_id']:
                    raise AclError(422, 'A task cannot block itself')
                self._task_access(c, u, s, self._task(c, new_blocking), 'read')
            sets = ', '.join(f'{k}=:v_{k}' for k in values)
            row = one(c, f'''UPDATE task_ayuza.blockers SET {sets}, version=version+1, updated_at=clock_timestamp()
                WHERE id=:id AND version=:version RETURNING version''', id=bid, version=expected,
                      **{f'v_{k}': v for k, v in values.items()})
            if row is None:
                raise AclError(409, 'Version conflict')
            self._blocker_event(c, u, bid, 'updated')
            self._blocker_audit(c, u, s, request_id, blocker, 'blocker.updated', {'fields': sorted(values)})
            return {'id': bid, 'version': row['version'], 'changed': True}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def set_blocker_resolved(self, token, csrf, blocker_id, resolved, expected_version, request_id=None):
        bid, expected = as_uuid(blocker_id), check_version(expected_version)
        if not isinstance(resolved, bool):
            raise AclError(422, 'Invalid value')
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            blocker, task = self._locked_blocker(c, u, s, bid)
            if blocker['archived_at'] is not None or task['archived_at'] is not None:
                raise AclError(409, 'Archived')
            if (blocker['status'] == 'resolved') == resolved:
                return {'id': bid, 'version': blocker['version'], 'changed': False}
            if expected is None or expected != blocker['version']:
                raise AclError(409, 'Version conflict')
            row = one(c, '''UPDATE task_ayuza.blockers SET status = CASE WHEN :r THEN 'resolved' ELSE 'active' END,
                resolved_at = CASE WHEN :r THEN clock_timestamp() ELSE NULL END,
                version=version+1, updated_at=clock_timestamp() WHERE id=:id AND version=:v RETURNING version''',
                      r=resolved, id=bid, v=expected)
            if row is None:
                raise AclError(409, 'Version conflict')
            self._blocker_event(c, u, bid, 'resolved' if resolved else 'reopened')
            if resolved:
                enqueue(c, actor_id=u['id'], task=task, event_type='blocker_resolved', source_id=bid,
                        source_key=f'{bid}:v{row["version"]}', recipients=people(task) + [blocker['responsible_user_id']])
            self._blocker_audit(c, u, s, request_id, blocker, 'blocker.resolved' if resolved else 'blocker.reopened',
                                {'active': not resolved})
            return {'id': bid, 'version': row['version'], 'changed': True}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def set_blocker_archived(self, token, csrf, blocker_id, archived, expected_version, request_id=None):
        bid, expected = as_uuid(blocker_id), check_version(expected_version)
        if not isinstance(archived, bool):
            raise AclError(422, 'Invalid value')
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            blocker, _task = self._locked_blocker(c, u, s, bid)
            if (blocker['archived_at'] is not None) == archived:
                return {'id': bid, 'version': blocker['version'], 'changed': False}
            if expected is None or expected != blocker['version']:
                raise AclError(409, 'Version conflict')
            row = one(c, '''UPDATE task_ayuza.blockers SET archived_at = CASE WHEN :a THEN clock_timestamp() ELSE NULL END,
                version=version+1, updated_at=clock_timestamp() WHERE id=:id AND version=:v RETURNING version''',
                      a=archived, id=bid, v=expected)
            if row is None:
                raise AclError(409, 'Version conflict')
            self._blocker_event(c, u, bid, 'archived' if archived else 'restored')
            self._blocker_audit(c, u, s, request_id, blocker, 'blocker.archived' if archived else 'blocker.restored',
                                {'archived': archived})
            return {'id': bid, 'version': row['version'], 'changed': True}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def _blocker_view(self, c, u, s, row):
        view = dict(row)
        if view['blocking_task_id'] is not None and not self._can(c, u, s, self._task(c, view['blocking_task_id']), 'read'):
            view['blocking_task_id'] = None  # the other side is hidden from this reader
        return view

    def list_blockers(self, token, task_id, include_resolved=True):
        tid = as_uuid(task_id)

        def run(c, u, s):
            task = self._task(c, tid)
            self._task_access(c, u, s, task, 'read')
            rows = execute(c, '''SELECT * FROM task_ayuza.blockers WHERE blocked_task_id=:t AND archived_at IS NULL
                AND (CAST(:incl AS boolean) OR status='active') ORDER BY occurred_at, id''', t=tid, incl=bool(include_resolved)).mappings().all()
            return [self._blocker_view(c, u, s, r) for r in rows]
        return self.auth.protected(token, run)

    def list_blocker_events(self, token, blocker_id):
        bid = as_uuid(blocker_id)

        def run(c, u, s):
            blocker = one(c, 'SELECT * FROM task_ayuza.blockers WHERE id=:id', id=bid)
            if blocker is None:
                raise _not_found()
            self._task_access(c, u, s, self._task(c, blocker['blocked_task_id']), 'read')
            out = []
            for r in execute(c, 'SELECT * FROM task_ayuza.blocker_events WHERE blocker_id=:b ORDER BY occurred_at, id',
                             b=bid).mappings().all():
                row = dict(r)
                snap = row['blocking_task_id_snapshot']
                if snap is not None and not self._can(c, u, s, self._task(c, snap), 'read'):
                    row['blocking_task_id_snapshot'] = None
                out.append(row)
            return out
        return self.auth.protected(token, run)
