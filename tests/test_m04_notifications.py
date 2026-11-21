"""M04.1 tests: outbox and in-app notifications. Disposable PostgreSQL, synthetic data only."""
import pytest

from backend.notifications import NotificationsService
from test_m01_acl import acl, admin_sql, migrator, person, rows, status, violates, world  # noqa: F401
from test_m01_auth import service  # noqa: F401
from test_m02_work import join, new_task  # noqa: F401


@pytest.fixture(scope='module')
def notes(service):
    return NotificationsService(service)


@pytest.fixture(scope='module')
def w(service, acl, migrator):
    return world(service, acl, migrator)


def types(notes, who, unread_only=False):
    return sorted(n['event_type'] for n in notes.list_notifications(who.token, unread_only=unread_only))


def test_h01_assignment_queued_in_transaction_and_processed_once(service, acl, notes, w, migrator):
    a, b = join(acl, w, person(service)), join(acl, w, person(service))
    t = new_task(notes, a, w)
    notes.assign_task(a.token, a.csrf, t['id'], 1, assignee_user_id=b.id)
    pending = rows(migrator, "SELECT * FROM task_ayuza.outbox_events WHERE task_id=:t", t=t['id'])
    assert [(r['recipient_user_id'], r['state'], r['event_type']) for r in pending] == [(b.id, 'pending', 'task_assigned')]
    assert notes.list_notifications(b.token) == []                    # nothing is delivered before processing
    assert notes.process_outbox(1000)['created'] >= 1
    assert types(notes, b) == ['task_assigned'] and notes.count_unread(b.token) == 1
    assert notes.list_notifications(a.token) == []                    # the actor is never notified
    assert notes.process_outbox(1000)['created'] == 0                 # repeat run changes nothing
    again = notes.assign_task(a.token, a.csrf, t['id'], 2, assignee_user_id=b.id)
    assert again['changed'] is False
    notes.process_outbox(1000)
    assert types(notes, b) == ['task_assigned']                       # unchanged assignment makes no new notification
    done = rows(migrator, "SELECT state, attempts, processed_at FROM task_ayuza.outbox_events WHERE task_id=:t", t=t['id'])[0]
    assert done['state'] == 'done' and done['attempts'] == 1 and done['processed_at'] is not None


def test_h02_comment_notifies_owner_and_assignee_not_author(service, acl, notes, w, migrator):
    a, b = join(acl, w, person(service)), join(acl, w, person(service))
    t = new_task(notes, a, w, assignee_user_id=b.id)['id']
    notes.add_comment(b.token, b.csrf, t, 'first')
    notes.process_outbox(1000)
    assert types(notes, a) == ['comment_added'] and types(notes, b) == []
    notes.add_comment(a.token, a.csrf, t, 'second')
    notes.process_outbox(1000)
    assert types(notes, a) == ['comment_added'] and types(notes, b) == ['comment_added']
    dump = repr(rows(migrator, 'SELECT * FROM task_ayuza.notifications') + rows(migrator, 'SELECT * FROM task_ayuza.outbox_events'))
    assert 'first' not in dump and 'second' not in dump             # no text is copied


def test_h03_access_is_checked_again_when_reading(service, acl, notes, w, migrator):
    a = join(acl, w, person(service))
    h = join(acl, w, person(service), team=False)
    stranger = join(acl, w, person(service), team=False)
    t = new_task(notes, a, w)['id']
    blocker = notes.create_blocker(a.token, a.csrf, t, 'Waiting', responsible_user_id=h.id)
    notes.set_blocker_resolved(a.token, a.csrf, blocker['id'], True, 1)
    notes.process_outbox(1000)
    assert rows(migrator, "SELECT count(*) AS n FROM task_ayuza.notifications WHERE recipient_user_id=:u", u=h.id)[0]['n'] == 1
    # the responsible person has no access to the task: nothing is listed, counted or markable
    assert notes.list_notifications(h.token) == [] and notes.count_unread(h.token) == 0
    nid = rows(migrator, "SELECT id FROM task_ayuza.notifications WHERE recipient_user_id=:u", u=h.id)[0]['id']
    assert status(lambda: notes.mark_read(h.token, h.csrf, nid)) == 404
    notes.set_task_access(a.token, a.csrf, t, h.id, 'read', True, 'help')
    seen = notes.list_notifications(h.token)
    assert [(n['event_type'], n['task_id']) for n in seen] == [('blocker_resolved', t)]
    assert status(lambda: notes.mark_read(stranger.token, stranger.csrf, nid)) == 404       # not the recipient
    assert notes.mark_read(h.token, h.csrf, nid)['changed'] is True
    assert notes.mark_read(h.token, h.csrf, nid)['changed'] is False
    assert notes.count_unread(h.token) == 0 and types(notes, h, unread_only=True) == []
    notes.set_task_access(a.token, a.csrf, t, h.id, 'read', False, 'done')
    assert notes.list_notifications(h.token) == []                                          # access withdrawn again


def test_h04_dependency_changes_notify_each_own_task_only(service, acl, notes, w, migrator):
    a, b = join(acl, w, person(service)), join(acl, w, person(service))
    A, B = (new_task(notes, a, w, assignee_user_id=b.id)['id'] for _ in range(2))
    edge = notes.add_dependency(a.token, a.csrf, A, B)
    notes.add_dependency(a.token, a.csrf, A, B)                                               # idempotent: no new events
    notes.process_outbox(1000)
    assert sorted(n['task_id'] for n in notes.list_notifications(b.token)) == sorted([A, B])
    assert notes.list_notifications(a.token) == []
    notes.remove_dependency(a.token, a.csrf, edge['id'], 'not needed', 1)
    notes.process_outbox(1000)
    assert types(notes, b) == ['dependency_changed'] * 4
    dump = repr(rows(migrator, 'SELECT * FROM task_ayuza.outbox_events WHERE task_id IN (:a, :b)', a=A, b=B))
    assert 'not needed' not in dump


def test_h05_deactivated_recipient_and_atomic_rollback(service, acl, notes, w, migrator):
    a, b = join(acl, w, person(service)), join(acl, w, person(service))
    t = new_task(notes, a, w)['id']
    notes.assign_task(a.token, a.csrf, t, 1, assignee_user_id=b.id)
    service.deactivate(b.id)
    assert notes.process_outbox(1000)['failed'] >= 1
    assert rows(migrator, "SELECT state FROM task_ayuza.outbox_events WHERE task_id=:t", t=t)[0]['state'] == 'failed'
    assert rows(migrator, "SELECT count(*) AS n FROM task_ayuza.notifications WHERE recipient_user_id=:u", u=b.id)[0]['n'] == 0
    # a failed mutation leaves no outbox row (same transaction)
    before = rows(migrator, 'SELECT count(*) AS n FROM task_ayuza.outbox_events')[0]['n']
    assert status(lambda: notes.assign_task(a.token, a.csrf, t, 1, assignee_user_id=a.id)) == 409
    assert rows(migrator, 'SELECT count(*) AS n FROM task_ayuza.outbox_events')[0]['n'] == before


def test_h06_constraints_and_privileges(service, acl, notes, w, migrator):
    a, b = join(acl, w, person(service)), join(acl, w, person(service))
    t = new_task(notes, a, w)['id']
    notes.assign_task(a.token, a.csrf, t, 1, assignee_user_id=b.id)
    notes.process_outbox(1000)
    ob = rows(migrator, "SELECT * FROM task_ayuza.outbox_events WHERE task_id=:t", t=t)[0]
    nid = rows(migrator, "SELECT id FROM task_ayuza.notifications WHERE task_id=:t", t=t)[0]['id']
    violates(migrator, "UPDATE task_ayuza.outbox_events SET state='pending' WHERE id=:id", '23514', id=ob['id'])
    violates(migrator, "UPDATE task_ayuza.outbox_events SET event_type='other' WHERE id=:id", '23514', id=ob['id'])
    violates(migrator, "UPDATE task_ayuza.outbox_events SET recipient_user_id=actor_user_id WHERE id=:id", '23514', id=ob['id'])
    violates(migrator, "INSERT INTO task_ayuza.outbox_events (id, workspace_id, task_id, event_type, recipient_user_id, actor_user_id, source_id, dedupe_key) SELECT gen_random_uuid(), workspace_id, task_id, event_type, recipient_user_id, actor_user_id, source_id, dedupe_key FROM task_ayuza.outbox_events WHERE id=:id", '23505', id=ob['id'])
    violates(migrator, "UPDATE task_ayuza.notifications SET event_type='other' WHERE id=:id", '23514', id=nid)
    runtime = service.engine
    for table in ('outbox_events', 'notifications'):
        violates(runtime, f'TRUNCATE task_ayuza.{table}', '42501')
        violates(runtime, f'DELETE FROM task_ayuza.{table} WHERE false', '42501')
    violates(runtime, "UPDATE task_ayuza.notifications SET recipient_user_id=recipient_user_id WHERE false", '42501')
    violates(runtime, "UPDATE task_ayuza.notifications SET task_id=task_id WHERE false", '42501')
