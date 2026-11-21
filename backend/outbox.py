"""M04.1: transactional outbox helper. Called inside the mutation's own transaction; never delivers anything."""
from __future__ import annotations

import uuid

from backend.auth import execute

EVENT_TYPES = ('task_assigned', 'comment_added', 'blocker_resolved', 'dependency_changed')


def enqueue(c, *, actor_id, task, event_type, source_id, source_key, recipients) -> int:
    """One row per recipient. The actor is never notified. Repeating the same source is a no-op (dedupe_key)."""
    assert event_type in EVENT_TYPES
    queued = 0
    for recipient in sorted({r for r in recipients if r is not None and r != actor_id}, key=str):
        queued += execute(c, '''INSERT INTO task_ayuza.outbox_events
            (id, workspace_id, task_id, event_type, recipient_user_id, actor_user_id, source_id, dedupe_key)
            VALUES (:id, :w, :t, :e, :r, :a, :s, :k) ON CONFLICT (dedupe_key) DO NOTHING''',
                          id=uuid.uuid4(), w=task['workspace_id'], t=task['id'], e=event_type, r=recipient,
                          a=actor_id, s=source_id, k=f'{event_type}:{source_key}:{task["id"]}:{recipient}').rowcount
    return queued


def people(task):
    """Result owner and assignee of a task: the people who must learn about changes to it."""
    return [task['result_owner_user_id'], task['assignee_user_id']]
