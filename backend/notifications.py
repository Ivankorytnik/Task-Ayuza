"""M04.1 internal service: outbox processing and in-app notifications. No HTTP, no external delivery.

Mutations queue outbox rows in their own transaction (backend/outbox.py). process_outbox turns each row
into at most one notification (dedupe_key), so repeating the run or a mutation never duplicates anything.
A notification stores only the type and a typed reference to the task. When it is read, access to that
task is checked again: a recipient who lost access sees nothing, not even a count.
"""
from __future__ import annotations

import uuid

from backend.acl import AclError, _not_found, as_uuid
from backend.auth import execute, one
from backend.links import LinksService

MAX_ATTEMPTS = 5


class NotificationsService(LinksService):
    def process_outbox(self, limit=100):
        """System operation without a user session. Safe to run concurrently (SKIP LOCKED) and to repeat."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise AclError(422, 'Invalid limit')

        def run(c):
            created = failed = 0
            for row in execute(c, '''SELECT * FROM task_ayuza.outbox_events WHERE state='pending'
                ORDER BY created_at, id LIMIT :n FOR UPDATE SKIP LOCKED''', n=limit).mappings().all():
                active = one(c, 'SELECT 1 AS x FROM task_ayuza.users WHERE id=:u AND active', u=row['recipient_user_id'])
                if active is None:  # a deactivated recipient never gets a notification
                    execute(c, '''UPDATE task_ayuza.outbox_events SET state='failed', attempts=attempts+1,
                        processed_at=clock_timestamp() WHERE id=:id''', id=row['id'])
                    failed += 1
                    continue
                created += execute(c, '''INSERT INTO task_ayuza.notifications
                    (id, workspace_id, task_id, recipient_user_id, event_type, outbox_event_id, dedupe_key)
                    VALUES (:id, :w, :t, :r, :e, :o, :k) ON CONFLICT (dedupe_key) DO NOTHING''',
                                   id=uuid.uuid4(), w=row['workspace_id'], t=row['task_id'], r=row['recipient_user_id'],
                                   e=row['event_type'], o=row['id'], k=row['dedupe_key']).rowcount
                execute(c, '''UPDATE task_ayuza.outbox_events SET state='done', attempts=attempts+1,
                    processed_at=clock_timestamp() WHERE id=:id''', id=row['id'])
            return {'created': created, 'failed': failed}
        return self.auth.transaction(run)

    def _visible_notifications(self, c, u, s, unread_only):
        out = []
        for row in execute(c, '''SELECT * FROM task_ayuza.notifications WHERE recipient_user_id=:u
            AND (NOT CAST(:unread AS boolean) OR read_at IS NULL) ORDER BY created_at DESC, id DESC''',
                           u=u['id'], unread=bool(unread_only)).mappings().all():
            task = one(c, 'SELECT * FROM task_ayuza.tasks WHERE id=:id', id=row['task_id'])
            if task is not None and self._can(c, u, s, task, 'read'):
                out.append(row)
        return out

    def list_notifications(self, token, unread_only=False, limit=50):
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise AclError(422, 'Invalid limit')

        def run(c, u, s):
            rows = self._visible_notifications(c, u, s, unread_only)
            return [{'id': r['id'], 'event_type': r['event_type'], 'task_id': r['task_id'],
                     'created_at': r['created_at'], 'read_at': r['read_at']} for r in rows[:limit]]
        return self.auth.protected(token, run)

    def count_unread(self, token):
        return self.auth.protected(token, lambda c, u, s: len(self._visible_notifications(c, u, s, True)))

    def mark_read(self, token, csrf, notification_id):
        nid = as_uuid(notification_id)

        def run(c, u, s):
            row = one(c, 'SELECT * FROM task_ayuza.notifications WHERE id=:id AND recipient_user_id=:u FOR UPDATE',
                      id=nid, u=u['id'])
            if row is None:
                raise _not_found()
            task = one(c, 'SELECT * FROM task_ayuza.tasks WHERE id=:id', id=row['task_id'])
            if task is None or not self._can(c, u, s, task, 'read'):
                raise _not_found()
            if row['read_at'] is not None:
                return {'id': nid, 'changed': False}
            execute(c, 'UPDATE task_ayuza.notifications SET read_at=clock_timestamp() WHERE id=:id', id=nid)
            return {'id': nid, 'changed': True}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)
