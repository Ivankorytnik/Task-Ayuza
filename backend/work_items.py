"""M02.2 internal service: labels, project stages, task stage, checklists, comments. No HTTP.

Built on WorkService: every operation authenticates through AuthService.protected, checks the
concrete object and operation (D01/D02) and writes an audit event with identifiers and enums
only (never label names, titles, checklist text or comment bodies) in the same transaction.
Checklist changes never complete a task; comments are reached only through task access.

Comment moderation (hide/restore without rewriting the author's text) is open only to a holder
of an unexpired administrative content_edit grant with fresh MFA; a dedicated moderator role is
deferred until the owner defines it.
"""
from __future__ import annotations

import uuid

from backend.acl import (AclError, _forbidden, _not_found, as_uuid, audit, check_version, clean_text,
                         grant_capability, membership)
from backend.auth import execute, one
from backend.work import UNSET, WorkService, _date, _check_dates, _grant_ok

STAGE_FIELDS = frozenset({'title', 'start_date', 'due_date', 'sort_order'})


def _lock(c, namespace, key):
    digest = uuid.uuid5(uuid.NAMESPACE_URL, f'{namespace}:{key}').int & 0x7FFFFFFFFFFFFFFF
    execute(c, 'SELECT pg_advisory_xact_lock(:k)', k=digest)


class ItemsService(WorkService):
    # ------------------------------------------------------------------ labels

    def create_label(self, token, csrf, workspace_id, name, request_id=None):
        wid, name = as_uuid(workspace_id), clean_text(name, 60)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            member = membership(c, u['id'], wid)
            if member is None:
                raise _not_found()
            if member['role'] != 'participant' and not _grant_ok(c, s, u['id'], wid, 'content_edit'):
                raise _forbidden()
            lid = uuid.uuid4()
            row = one(c, '''INSERT INTO task_ayuza.labels (id, workspace_id, name) VALUES (:id, :w, :n)
                ON CONFLICT (workspace_id, lower(name)) DO NOTHING RETURNING id, version''', id=lid, w=wid, n=name)
            if row is None:
                existing = one(c, 'SELECT id, version FROM task_ayuza.labels WHERE workspace_id=:w AND lower(name)=lower(:n)',
                               w=wid, n=name)
                return {'id': existing['id'], 'version': existing['version'], 'created': False}
            audit(c, u, s, request_id=request_id, entity_kind='label', entity_id=lid, action='label.created',
                  workspace_id=wid, old=None, new={'active': True})
            return {'id': lid, 'version': 1, 'created': True}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def list_labels(self, token, workspace_id):
        wid = as_uuid(workspace_id)

        def run(c, u, s):
            if membership(c, u['id'], wid) is None:
                raise _not_found()
            return [dict(r) for r in execute(c, 'SELECT id, name, version FROM task_ayuza.labels WHERE workspace_id=:w ORDER BY lower(name), id',
                                             w=wid).mappings().all()]
        return self.auth.protected(token, run)

    def _set_label(self, c, u, s, *, table, key, key_value, workspace_id, label_id, active, entity_kind, action, request_id):
        label = one(c, 'SELECT id FROM task_ayuza.labels WHERE id=:l AND workspace_id=:w', l=label_id, w=workspace_id)
        if label is None:
            raise AclError(422, 'Label is not in this workspace')
        row = one(c, f'SELECT active, version FROM task_ayuza.{table} WHERE {key}=:k AND label_id=:l FOR UPDATE',
                  k=key_value, l=label_id)
        if row is None:
            if not active:
                return {'changed': False}
            execute(c, f'INSERT INTO task_ayuza.{table} ({key}, label_id, workspace_id) VALUES (:k, :l, :w)',
                    k=key_value, l=label_id, w=workspace_id)
        elif row['active'] == active:
            return {'changed': False}
        else:
            execute(c, f'''UPDATE task_ayuza.{table} SET active=:a, version=version+1
                WHERE {key}=:k AND label_id=:l''', a=active, k=key_value, l=label_id)
        audit(c, u, s, request_id=request_id, entity_kind=entity_kind, entity_id=key_value, action=action,
              workspace_id=workspace_id, old=None, new={'label_id': str(label_id), 'active': active})
        return {'changed': True}

    def set_project_label(self, token, csrf, project_id, label_id, active=True, request_id=None):
        pid, lid = as_uuid(project_id), as_uuid(label_id)
        if not isinstance(active, bool):
            raise AclError(422, 'Invalid value')
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            project = self._locked_project(c, pid)
            self._project_access(c, u, s, project, 'edit')
            if project['archived_at'] is not None:
                raise AclError(409, 'Project is archived')
            return self._set_label(c, u, s, table='project_labels', key='project_id', key_value=pid,
                                   workspace_id=project['workspace_id'], label_id=lid, active=active,
                                   entity_kind='project', action='label.project_set', request_id=request_id)
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def set_task_label(self, token, csrf, task_id, label_id, active=True, request_id=None):
        tid, lid = as_uuid(task_id), as_uuid(label_id)
        if not isinstance(active, bool):
            raise AclError(422, 'Invalid value')
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            task = self._locked_task(c, tid)
            self._task_access(c, u, s, task, 'edit')
            if task['archived_at'] is not None:
                raise AclError(409, 'Task is archived')
            return self._set_label(c, u, s, table='task_labels', key='task_id', key_value=tid,
                                   workspace_id=task['workspace_id'], label_id=lid, active=active,
                                   entity_kind='task', action='label.task_set', request_id=request_id)
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def list_task_labels(self, token, task_id):
        tid = as_uuid(task_id)

        def run(c, u, s):
            task = one(c, 'SELECT * FROM task_ayuza.tasks WHERE id=:id', id=tid)
            if task is None:
                raise _not_found()
            self._task_access(c, u, s, task, 'read')
            return [dict(r) for r in execute(c, '''SELECT l.id, l.name FROM task_ayuza.task_labels tl
                JOIN task_ayuza.labels l ON l.id = tl.label_id WHERE tl.task_id=:t AND tl.active
                ORDER BY lower(l.name), l.id''', t=tid).mappings().all()]
        return self.auth.protected(token, run)

    # ------------------------------------------------------------------ project stages

    def create_stage(self, token, csrf, project_id, title, start_date=None, due_date=None, sort_order=0, request_id=None):
        pid, title = as_uuid(project_id), clean_text(title, 200)
        start, due = _date(start_date), _date(due_date)
        _check_dates(start, due)
        if isinstance(sort_order, bool) or not isinstance(sort_order, int) or not -10000 <= sort_order <= 10000:
            raise AclError(422, 'Invalid order')
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            project = self._locked_project(c, pid)
            self._project_access(c, u, s, project, 'edit')
            if project['archived_at'] is not None:
                raise AclError(409, 'Project is archived')
            sid = uuid.uuid4()
            execute(c, '''INSERT INTO task_ayuza.project_stages
                (id, workspace_id, project_id, title, start_date, due_date, sort_order)
                VALUES (:id, :w, :p, :t, :s, :d, :o)''', id=sid, w=project['workspace_id'], p=pid, t=title,
                    s=start, d=due, o=sort_order)
            audit(c, u, s, request_id=request_id, entity_kind='project_stage', entity_id=sid, action='stage.created',
                  workspace_id=project['workspace_id'], old=None, new={'project_id': str(pid), 'archived': False})
            return {'id': sid, 'version': 1}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def _locked_stage(self, c, stage_id):
        stage = one(c, 'SELECT * FROM task_ayuza.project_stages WHERE id=:id FOR UPDATE', id=stage_id)
        if stage is None:
            raise _not_found()
        return stage

    def update_stage(self, token, csrf, stage_id, expected_version, changes, request_id=None):
        sid, expected = as_uuid(stage_id), check_version(expected_version)
        if not isinstance(changes, dict) or not changes or set(changes) - STAGE_FIELDS:
            raise AclError(422, 'Invalid fields')
        values = {}
        for name, value in changes.items():
            if name == 'title':
                values[name] = clean_text(value, 200)
            elif name == 'sort_order':
                if isinstance(value, bool) or not isinstance(value, int) or not -10000 <= value <= 10000:
                    raise AclError(422, 'Invalid order')
                values[name] = value
            else:
                values[name] = _date(value)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            stage = self._locked_stage(c, sid)
            project = self._locked_project(c, stage['project_id'])
            self._project_access(c, u, s, project, 'edit')
            if project['archived_at'] is not None or stage['archived_at'] is not None:
                raise AclError(409, 'Archived')
            if all(stage[k] == v for k, v in values.items()):
                return {'id': sid, 'version': stage['version'], 'changed': False}
            if expected is None or expected != stage['version']:
                raise AclError(409, 'Version conflict')
            _check_dates(values.get('start_date', stage['start_date']), values.get('due_date', stage['due_date']))
            sets = ', '.join(f'{k}=:v_{k}' for k in values)
            row = one(c, f'''UPDATE task_ayuza.project_stages SET {sets}, version=version+1, updated_at=clock_timestamp()
                WHERE id=:id AND version=:version RETURNING version''', id=sid, version=expected,
                      **{f'v_{k}': v for k, v in values.items()})
            if row is None:
                raise AclError(409, 'Version conflict')
            audit(c, u, s, request_id=request_id, entity_kind='project_stage', entity_id=sid, action='stage.updated',
                  workspace_id=stage['workspace_id'], old=None, new={'fields': sorted(values)})
            return {'id': sid, 'version': row['version'], 'changed': True}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def set_stage_archived(self, token, csrf, stage_id, archived, expected_version, request_id=None):
        sid, expected = as_uuid(stage_id), check_version(expected_version)
        if not isinstance(archived, bool):
            raise AclError(422, 'Invalid value')
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            stage = self._locked_stage(c, sid)
            project = self._locked_project(c, stage['project_id'])
            self._project_access(c, u, s, project, 'archive')
            if (stage['archived_at'] is not None) == archived:
                return {'id': sid, 'version': stage['version'], 'changed': False}
            if expected is None or expected != stage['version']:
                raise AclError(409, 'Version conflict')
            row = one(c, '''UPDATE task_ayuza.project_stages SET archived_at = CASE WHEN :a THEN clock_timestamp() ELSE NULL END,
                version=version+1, updated_at=clock_timestamp() WHERE id=:id AND version=:v RETURNING version''',
                      a=archived, id=sid, v=expected)
            if row is None:
                raise AclError(409, 'Version conflict')
            audit(c, u, s, request_id=request_id, entity_kind='project_stage', entity_id=sid,
                  action='stage.archived' if archived else 'stage.restored', workspace_id=stage['workspace_id'],
                  old={'archived': not archived}, new={'archived': archived})
            return {'id': sid, 'version': row['version'], 'changed': True}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def list_stages(self, token, project_id):
        pid = as_uuid(project_id)

        def run(c, u, s):
            project = one(c, 'SELECT * FROM task_ayuza.projects WHERE id=:id', id=pid)
            if project is None:
                raise _not_found()
            self._project_access(c, u, s, project, 'read')
            return [dict(r) for r in execute(c, '''SELECT * FROM task_ayuza.project_stages
                WHERE project_id=:p AND archived_at IS NULL ORDER BY sort_order, id''', p=pid).mappings().all()]
        return self.auth.protected(token, run)

    def set_task_stage(self, token, csrf, task_id, stage_id, expected_version, request_id=None):
        tid, expected = as_uuid(task_id), check_version(expected_version)
        sid = as_uuid(stage_id) if stage_id is not None else None
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            task = self._locked_task(c, tid)
            self._task_access(c, u, s, task, 'edit')
            if task['archived_at'] is not None:
                raise AclError(409, 'Task is archived')
            if sid is not None:
                if task['project_id'] is None:
                    raise AclError(422, 'A standalone task has no stage')
                stage = one(c, '''SELECT archived_at FROM task_ayuza.project_stages
                    WHERE id=:s AND project_id=:p AND workspace_id=:w FOR SHARE''', s=sid, p=task['project_id'], w=task['workspace_id'])
                if stage is None:
                    raise AclError(422, 'Stage does not belong to the task project')
                if stage['archived_at'] is not None:
                    raise AclError(409, 'Stage is archived')
            if task['stage_id'] == sid:
                return {'id': tid, 'version': task['version'], 'changed': False}
            if expected is None or expected != task['version']:
                raise AclError(409, 'Version conflict')
            row = one(c, '''UPDATE task_ayuza.tasks SET stage_id=:s, version=version+1, updated_at=clock_timestamp()
                WHERE id=:id AND version=:v RETURNING version''', s=sid, id=tid, v=expected)
            if row is None:
                raise AclError(409, 'Version conflict')
            audit(c, u, s, request_id=request_id, entity_kind='task', entity_id=tid, action='task.stage_set',
                  workspace_id=task['workspace_id'],
                  old={'stage_id': str(task['stage_id']) if task['stage_id'] else None},
                  new={'stage_id': str(sid) if sid else None})
            return {'id': tid, 'version': row['version'], 'changed': True}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    # ------------------------------------------------------------------ checklists

    def _shared_task(self, c, task_id):
        task = one(c, 'SELECT * FROM task_ayuza.tasks WHERE id=:id FOR SHARE', id=task_id)
        if task is None:
            raise _not_found()
        return task

    def add_checklist_item(self, token, csrf, task_id, text, request_id=None):
        tid, text = as_uuid(task_id), clean_text(text, 500)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            task = self._shared_task(c, tid)
            self._task_access(c, u, s, task, 'edit')
            if task['archived_at'] is not None:
                raise AclError(409, 'Task is archived')
            _lock(c, 'checklist', tid)
            position = execute(c, 'SELECT coalesce(max(position), 0) + 1 FROM task_ayuza.checklist_items WHERE task_id=:t',
                               t=tid).scalar_one()
            iid = uuid.uuid4()
            execute(c, '''INSERT INTO task_ayuza.checklist_items (id, workspace_id, task_id, text, position)
                VALUES (:id, :w, :t, :x, :pos)''', id=iid, w=task['workspace_id'], t=tid, x=text, pos=position)
            audit(c, u, s, request_id=request_id, entity_kind='checklist_item', entity_id=iid,
                  action='checklist.item_added', workspace_id=task['workspace_id'], old=None,
                  new={'checked': False, 'position': position})
            return {'id': iid, 'version': 1, 'position': position}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def change_checklist_item(self, token, csrf, item_id, expected_version, text=UNSET, checked=UNSET,
                              deleted=UNSET, request_id=None):
        iid, expected = as_uuid(item_id), check_version(expected_version)
        if text is UNSET and checked is UNSET and deleted is UNSET:
            raise AclError(422, 'Nothing to change')
        if text is not UNSET:
            text = clean_text(text, 500)
        for flag in (checked, deleted):
            if flag is not UNSET and not isinstance(flag, bool):
                raise AclError(422, 'Invalid value')
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            item = one(c, 'SELECT * FROM task_ayuza.checklist_items WHERE id=:id FOR UPDATE', id=iid)
            if item is None:
                raise _not_found()
            task = self._shared_task(c, item['task_id'])
            self._task_access(c, u, s, task, 'edit')
            if task['archived_at'] is not None:
                raise AclError(409, 'Task is archived')
            new_text = item['text'] if text is UNSET else text
            new_checked = item['is_checked'] if checked is UNSET else checked
            new_deleted = (item['deleted_at'] is not None) if deleted is UNSET else deleted
            if (new_text, new_checked, new_deleted) == (item['text'], item['is_checked'], item['deleted_at'] is not None):
                return {'id': iid, 'version': item['version'], 'changed': False}
            if expected is None or expected != item['version']:
                raise AclError(409, 'Version conflict')
            row = one(c, '''UPDATE task_ayuza.checklist_items SET text=:x, is_checked=:ch,
                checked_by = CASE WHEN :ch THEN COALESCE(CASE WHEN :keep THEN checked_by END, :u) ELSE NULL END,
                checked_at = CASE WHEN :ch THEN COALESCE(CASE WHEN :keep THEN checked_at END, clock_timestamp()) ELSE NULL END,
                deleted_at = CASE WHEN :gone THEN COALESCE(deleted_at, clock_timestamp()) ELSE NULL END,
                version=version+1, updated_at=clock_timestamp()
                WHERE id=:id AND version=:v RETURNING version''',
                      x=new_text, ch=new_checked, keep=item['is_checked'], u=u['id'], gone=new_deleted,
                      id=iid, v=expected)
            if row is None:
                raise AclError(409, 'Version conflict')
            audit(c, u, s, request_id=request_id, entity_kind='checklist_item', entity_id=iid,
                  action='checklist.item_changed', workspace_id=task['workspace_id'],
                  old={'checked': item['is_checked'], 'deleted': item['deleted_at'] is not None},
                  new={'checked': new_checked, 'deleted': new_deleted})
            return {'id': iid, 'version': row['version'], 'changed': True}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def list_checklist(self, token, task_id):
        tid = as_uuid(task_id)

        def run(c, u, s):
            task = one(c, 'SELECT * FROM task_ayuza.tasks WHERE id=:id', id=tid)
            if task is None:
                raise _not_found()
            self._task_access(c, u, s, task, 'read')
            return [dict(r) for r in execute(c, '''SELECT id, text, position, is_checked, checked_by, checked_at, version
                FROM task_ayuza.checklist_items WHERE task_id=:t AND deleted_at IS NULL ORDER BY position''',
                                             t=tid).mappings().all()]
        return self.auth.protected(token, run)

    # ------------------------------------------------------------------ comments

    def add_comment(self, token, csrf, task_id, body, request_id=None):
        tid, body = as_uuid(task_id), clean_text(body, 10000)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            task = self._shared_task(c, tid)
            self._task_access(c, u, s, task, 'comment')
            if task['archived_at'] is not None:
                raise AclError(409, 'Task is archived')
            if membership(c, u['id'], task['workspace_id']) is None:
                raise _forbidden()  # a comment author must be an active workspace member
            cid = uuid.uuid4()
            execute(c, '''INSERT INTO task_ayuza.comments (id, workspace_id, task_id, author_user_id, body)
                VALUES (:id, :w, :t, :a, :b)''', id=cid, w=task['workspace_id'], t=tid, a=u['id'], b=body)
            audit(c, u, s, request_id=request_id, entity_kind='comment', entity_id=cid, action='comment.added',
                  workspace_id=task['workspace_id'], old=None, new={'hidden': False, 'deleted': False})
            return {'id': cid, 'version': 1}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def _comment_for_author(self, c, u, s, comment_id):
        comment = one(c, 'SELECT * FROM task_ayuza.comments WHERE id=:id FOR UPDATE', id=comment_id)
        if comment is None:
            raise _not_found()
        task = self._shared_task(c, comment['task_id'])
        self._task_access(c, u, s, task, 'comment')
        if comment['deleted_at'] is not None:
            raise _not_found()
        if comment['author_user_id'] != u['id']:
            raise _forbidden()  # nobody rewrites or deletes another author's comment
        if comment['hidden_at'] is not None:
            raise AclError(409, 'Comment is hidden')
        if task['archived_at'] is not None:
            raise AclError(409, 'Task is archived')
        return comment, task

    def edit_comment(self, token, csrf, comment_id, expected_version, body, request_id=None):
        cid, expected, body = as_uuid(comment_id), check_version(expected_version), clean_text(body, 10000)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            comment, task = self._comment_for_author(c, u, s, cid)
            if comment['body'] == body:
                return {'id': cid, 'version': comment['version'], 'changed': False}
            if expected is None or expected != comment['version']:
                raise AclError(409, 'Version conflict')
            execute(c, '''INSERT INTO task_ayuza.comment_revisions (id, comment_id, body, version)
                VALUES (:id, :c, :b, :v)''', id=uuid.uuid4(), c=cid, b=comment['body'], v=comment['version'])
            row = one(c, '''UPDATE task_ayuza.comments SET body=:b, version=version+1, edited_at=clock_timestamp()
                WHERE id=:id AND version=:v RETURNING version''', b=body, id=cid, v=expected)
            if row is None:
                raise AclError(409, 'Version conflict')
            audit(c, u, s, request_id=request_id, entity_kind='comment', entity_id=cid, action='comment.edited',
                  workspace_id=task['workspace_id'], old=None, new={'fields': ['body']})
            return {'id': cid, 'version': row['version'], 'changed': True}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def delete_comment(self, token, csrf, comment_id, expected_version, request_id=None):
        cid, expected = as_uuid(comment_id), check_version(expected_version)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            comment, task = self._comment_for_author(c, u, s, cid)
            if expected is None or expected != comment['version']:
                raise AclError(409, 'Version conflict')
            row = one(c, '''UPDATE task_ayuza.comments SET deleted_at=clock_timestamp(), version=version+1
                WHERE id=:id AND version=:v RETURNING version''', id=cid, v=expected)
            if row is None:
                raise AclError(409, 'Version conflict')
            audit(c, u, s, request_id=request_id, entity_kind='comment', entity_id=cid, action='comment.deleted',
                  workspace_id=task['workspace_id'], old={'deleted': False}, new={'deleted': True})
            return {'id': cid, 'version': row['version'], 'changed': True}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def set_comment_hidden(self, token, csrf, comment_id, hidden, expected_version, request_id=None):
        cid, expected = as_uuid(comment_id), check_version(expected_version)
        if not isinstance(hidden, bool):
            raise AclError(422, 'Invalid value')
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            comment = one(c, 'SELECT * FROM task_ayuza.comments WHERE id=:id FOR UPDATE', id=cid)
            if comment is None or comment['deleted_at'] is not None:
                raise _not_found()
            task = self._shared_task(c, comment['task_id'])
            member = membership(c, u['id'], task['workspace_id'])
            if not _grant_ok(c, s, u['id'], task['workspace_id'], 'content_edit'):
                self._task_access(c, u, s, task, 'read')  # 404 for hidden objects, 403 for visible ones
                raise _forbidden()
            if (comment['hidden_at'] is not None) == hidden:
                return {'id': cid, 'version': comment['version'], 'changed': False}
            if expected is None or expected != comment['version']:
                raise AclError(409, 'Version conflict')
            row = one(c, '''UPDATE task_ayuza.comments SET hidden_at = CASE WHEN :h THEN clock_timestamp() ELSE NULL END,
                hidden_by = CASE WHEN :h THEN CAST(:u AS uuid) ELSE NULL END, version=version+1
                WHERE id=:id AND version=:v RETURNING version''', h=hidden, u=u['id'], id=cid, v=expected)
            if row is None:
                raise AclError(409, 'Version conflict')
            audit(c, u, s, request_id=request_id, entity_kind='comment', entity_id=cid,
                  action='comment.hidden' if hidden else 'comment.restored', workspace_id=task['workspace_id'],
                  old={'hidden': not hidden}, new={'hidden': hidden})
            return {'id': cid, 'version': row['version'], 'changed': True}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def list_comments(self, token, task_id):
        """Hidden comments keep their place but show no text, except to the author and a moderator."""
        tid = as_uuid(task_id)

        def run(c, u, s):
            task = one(c, 'SELECT * FROM task_ayuza.tasks WHERE id=:id', id=tid)
            if task is None:
                raise _not_found()
            self._task_access(c, u, s, task, 'read')
            moderator = grant_capability(c, u['id'], task['workspace_id'], 'content_edit') and \
                _grant_ok(c, s, u['id'], task['workspace_id'], 'content_edit')
            out = []
            for r in execute(c, '''SELECT id, author_user_id, body, version, created_at, edited_at, hidden_at
                FROM task_ayuza.comments WHERE task_id=:t AND deleted_at IS NULL ORDER BY created_at, id''',
                             t=tid).mappings().all():
                row = dict(r)
                hidden = row['hidden_at'] is not None
                if hidden and not (moderator or row['author_user_id'] == u['id']):
                    row['body'] = None
                row['hidden'] = hidden
                out.append(row)
            return out
        return self.auth.protected(token, run)
