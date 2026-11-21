"""M02.3 tests: task_events (D04/D06), idempotent create, explicit task access grants (D02)."""
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

from backend.acl import AclError
from backend.work_items import ItemsService
from test_m01_acl import acl, admin_sql, migrator, person, rows, status, violates, world  # noqa: F401
from test_m01_auth import service  # noqa: F401
from test_m02_work import join, new_project, new_task  # noqa: F401


@pytest.fixture(scope='module')
def items(service):
    return ItemsService(service)


@pytest.fixture(scope='module')
def w(service, acl, migrator):
    return world(service, acl, migrator)


def events(migrator, task_id):
    return rows(migrator, 'SELECT * FROM task_ayuza.task_events WHERE task_id=:t ORDER BY occurred_at, id', t=task_id)


def test_e01_status_events_and_attribution(service, acl, items, w, migrator):
    a = join(acl, w, person(service))
    b = join(acl, w, person(service))
    pid = new_project(items, a, w)['id']
    t = new_task(items, a, w, project_id=pid, assignee_user_id=b.id, due_date='2026-12-31')['id']
    first = events(migrator, t)
    assert [e['event_type'] for e in first] == ['created']
    assert first[0]['owner_id_snapshot'] == a.id and first[0]['assignee_id_snapshot'] == b.id
    assert first[0]['project_id_snapshot'] == pid and first[0]['project_owner_id_snapshot'] == a.id
    assert first[0]['priority_snapshot'] == 'normal' and str(first[0]['due_date_snapshot']) == '2026-12-31'
    v = 1
    for target in ('in_progress', 'done', 'in_progress', 'cancelled', 'new'):
        v = items.update_task(a.token, a.csrf, t, v, {'status': target})['version']
    kinds = [e['event_type'] for e in events(migrator, t)]
    assert kinds == ['created', 'status_changed', 'completed', 'reopened', 'cancelled', 'reopened']
    done = [e for e in events(migrator, t) if e['event_type'] == 'completed'][0]
    assert (done['from_status'], done['to_status']) == ('in_progress', 'done')
    # no-op and same-status patches leave no event
    before = len(events(migrator, t))
    assert items.update_task(a.token, a.csrf, t, v, {'status': 'new'})['changed'] is False
    assert len(events(migrator, t)) == before
    v = items.update_task(a.token, a.csrf, t, v, {'due_date': '2027-01-15', 'priority': 'high'})['version']
    assert [e['event_type'] for e in events(migrator, t)][-2:] == ['due_changed', 'priority_changed']
    # attribution at event time survives later reassignment
    items.assign_task(a.token, a.csrf, t, v, assignee_user_id=None)
    all_events = events(migrator, t)
    assert all_events[0]['assignee_id_snapshot'] == b.id and all_events[-1]['event_type'] == 'assigned'
    assert all_events[-1]['assignee_id_snapshot'] is None
    versions = [e['resulting_version'] for e in all_events]
    assert versions == sorted(versions)
    # archive, restore, stage
    cur = items.get_task(a.token, t)['version']
    arch = items.set_task_archived(a.token, a.csrf, t, True, cur)
    items.set_task_archived(a.token, a.csrf, t, False, arch['version'])
    stage = items.create_stage(a.token, a.csrf, pid, 'Phase')['id']
    items.set_task_stage(a.token, a.csrf, t, stage, items.get_task(a.token, t)['version'])
    assert [e['event_type'] for e in events(migrator, t)][-3:] == ['archived', 'restored', 'stage_changed']


def test_e02_history_redacts_project_for_task_only_readers(service, acl, items, w, migrator):
    pm = join(acl, w, person(service))
    only_task = join(acl, w, person(service), team=False)
    pid = new_project(items, pm, w)['id']
    t = new_task(items, pm, w, project_id=pid)['id']
    items.assign_task(pm.token, pm.csrf, t, 1, assignee_user_id=only_task.id)
    mine = items.list_task_events(pm.token, t)
    assert mine[0]['project_id_snapshot'] == pid and mine[0]['project_owner_id_snapshot'] == pm.id
    seen = items.list_task_events(only_task.token, t)
    assert [e['event_type'] for e in seen] == ['created', 'assigned']
    assert all(e['project_id_snapshot'] is None and e['project_owner_id_snapshot'] is None for e in seen)
    assert status(lambda: items.list_task_events(w.outsider.token, t)) == 404
    assert status(lambda: items.list_task_events(w.admin.token, t)) == 404


def test_e03_events_are_append_only_and_checked(service, acl, items, w, migrator):
    a = join(acl, w, person(service))
    t = new_task(items, a, w)['id']
    violates(service.engine, 'TRUNCATE task_ayuza.task_events', '42501')
    violates(service.engine, 'DELETE FROM task_ayuza.task_events WHERE false', '42501')
    violates(service.engine, "UPDATE task_ayuza.task_events SET event_type='created' WHERE false", '42501')
    insert = '''INSERT INTO task_ayuza.task_events (id, workspace_id, task_id, actor_user_id, event_type, from_status,
        to_status, resulting_version) SELECT gen_random_uuid(), workspace_id, id, :u, :type, :f, :to, 1
        FROM task_ayuza.tasks WHERE id=:t'''
    violates(migrator, insert, '23514', u=a.id, t=t, type='deleted', f=None, to=None)
    violates(migrator, insert, '23514', u=a.id, t=t, type='completed', f='new', to='cancelled')
    violates(migrator, insert, '23514', u=a.id, t=t, type='status_changed', f='new', to='new')
    violates(migrator, insert, '23514', u=a.id, t=t, type='reopened', f='new', to='in_progress')
    violates(migrator, insert, '23514', u=a.id, t=t, type='created', f='new', to=None)


def test_e04_idempotent_create(service, acl, items, w, migrator):
    a = join(acl, w, person(service))
    other = join(acl, w, person(service))
    key = 'client-key-' + uuid.uuid4().hex[:12]
    first = new_task(items, a, w, client_key=key)
    again = new_task(items, a, w, client_key=key)
    assert again['id'] == first['id'] and again['replayed'] is True and 'replayed' not in first
    assert len([e for e in events(migrator, first['id']) if e['event_type'] == 'created']) == 1
    assert status(lambda: new_task(items, a, w, client_key=key, title='Different content')) == 409
    # the key is per actor
    assert new_task(items, other, w, client_key=key)['id'] != first['id']
    assert status(lambda: new_task(items, a, w, client_key='short')) == 422
    # concurrent retries create exactly one task
    ckey = 'concurrent-' + uuid.uuid4().hex[:12]

    def attempt(_):
        try:
            return new_task(items, a, w, client_key=ckey, title='Concurrent')['id']
        except AclError as error:
            return error.status
    with ThreadPoolExecutor(4) as pool:
        results = list(pool.map(attempt, range(4)))
    assert len({r for r in results if isinstance(r, uuid.UUID)}) == 1 and all(isinstance(r, uuid.UUID) for r in results)
    # the replay re-checks access: once the author is removed from the workspace it is hidden
    lost = join(acl, w, person(service))
    lkey = 'lost-access-' + uuid.uuid4().hex[:8]
    new_task(items, lost, w, client_key=lkey)
    acl.set_workspace_member(w.admin.token, w.admin.csrf, w.ws, lost.id, 'participant', False,
                             rows(migrator, 'SELECT version FROM task_ayuza.workspace_members WHERE user_id=:u', u=lost.id)[0]['version'])
    assert status(lambda: new_task(items, lost, w, client_key=lkey)) == 404
    # an expired key is reusable and creates a new task
    admin_sql(migrator, "UPDATE task_ayuza.idempotency_requests SET created_at = created_at - interval '2 days', expires_at = clock_timestamp() - interval '1 day' WHERE client_key=:k", k=key)
    assert new_task(items, a, w, client_key=key)['id'] != first['id']
    violates(service.engine, 'DELETE FROM task_ayuza.idempotency_requests WHERE false', '42501')
    violates(migrator, "INSERT INTO task_ayuza.idempotency_requests (id, actor_user_id, operation, client_key, request_hash, resource_id, expires_at) VALUES (gen_random_uuid(), :u, 'x', 'abcdefgh', '\\x00', gen_random_uuid(), now() + interval '1 day')", '23514', u=a.id)


def test_e05_task_access_grants(service, acl, items, w, migrator):
    owner = join(acl, w, person(service))
    peer = join(acl, w, person(service), team=False)
    watcher = join(acl, w, person(service), 'observer', team=False)
    t = new_task(items, owner, w)['id']
    assert status(lambda: items.get_task(peer.token, t)) == 404
    granted = items.set_task_access(owner.token, owner.csrf, t, peer.id, 'read', True, 'synthetic need')
    assert granted['changed'] is True
    assert items.set_task_access(owner.token, owner.csrf, t, peer.id, 'read', True, 'synthetic need')['changed'] is False
    assert items.get_task(peer.token, t)['id'] == t
    assert any(r['id'] == t for r in items.list_tasks(peer.token, w.ws, limit=200))
    assert status(lambda: items.update_task(peer.token, peer.csrf, t, 1, {'title': 'x'})) == 403
    assert status(lambda: items.add_comment(peer.token, peer.csrf, t, 'No right')) == 403
    # the grant does not open neighbouring tasks
    neighbour = new_task(items, owner, w)['id']
    assert status(lambda: items.get_task(peer.token, neighbour)) == 404
    items.set_task_access(owner.token, owner.csrf, t, peer.id, 'comment', True, 'discuss')
    assert items.add_comment(peer.token, peer.csrf, t, 'Allowed comment')['version'] == 1
    items.set_task_access(owner.token, owner.csrf, t, peer.id, 'content_edit', True, 'edit')
    assert items.update_task(peer.token, peer.csrf, t, 1, {'priority': 'high'})['version'] == 2
    assert status(lambda: items.assign_task(peer.token, peer.csrf, t, 2, assignee_user_id=None)) == 403
    assert status(lambda: items.set_task_access(peer.token, peer.csrf, t, watcher.id, 'read', True, 'escalate')) == 403
    assert status(lambda: items.set_task_access(owner.token, owner.csrf, t, owner.id, 'read', True, 'self')) == 403
    assert status(lambda: items.set_task_access(owner.token, owner.csrf, t, w.outsider.id, 'read', True, 'x')) == 422
    assert status(lambda: items.set_task_access(owner.token, owner.csrf, t, peer.id, 'assign', True, 'x')) == 422
    assert status(lambda: items.set_task_access(owner.token, owner.csrf, t, peer.id, 'read', True, ' ')) == 422
    # an observer may be granted read, never edit
    items.set_task_access(owner.token, owner.csrf, t, watcher.id, 'read', True, 'audit view')
    items.set_task_access(owner.token, owner.csrf, t, watcher.id, 'content_edit', True, 'tries edit')
    assert items.get_task(watcher.token, t)['id'] == t
    assert status(lambda: items.update_task(watcher.token, watcher.csrf, t, 2, {'title': 'x'})) == 403
    assert sorted(r['capability'] for r in items.list_task_access(owner.token, t) if r['user_id'] == peer.id) == ['comment', 'content_edit', 'read']
    assert status(lambda: items.list_task_access(peer.token, t)) == 403
    # revocation applies to the very next request, re-grant needs the current version
    rows_now = {r['capability']: r for r in rows(migrator, 'SELECT capability, version FROM task_ayuza.task_access_grants WHERE user_id=:u', u=peer.id)}
    for cap in ('content_edit', 'comment', 'read'):
        revoked = items.set_task_access(owner.token, owner.csrf, t, peer.id, cap, False, 'done', rows_now[cap]['version'])
        assert revoked['changed'] is True
    assert status(lambda: items.get_task(peer.token, t)) == 404
    assert status(lambda: items.set_task_access(owner.token, owner.csrf, t, peer.id, 'read', True, 'again', 1)) == 409
    assert items.set_task_access(owner.token, owner.csrf, t, peer.id, 'read', True, 'again', 2)['version'] == 3
    dump = repr(rows(migrator, 'SELECT "old","new" FROM task_ayuza.audit_events'))
    assert 'synthetic need' not in dump and 'tries edit' not in dump
    assert {'task.access_granted', 'task.access_revoked'} <= {r['action'] for r in rows(migrator, 'SELECT action FROM task_ayuza.audit_events WHERE entity_id=:t', t=t)}
    violates(migrator, "UPDATE task_ayuza.task_access_grants SET capability='assign' WHERE user_id=:u", '23514', u=peer.id)
    violates(migrator, "UPDATE task_ayuza.task_access_grants SET granted_by=user_id WHERE user_id=:u", '23514', u=peer.id)
    violates(service.engine, 'DELETE FROM task_ayuza.task_access_grants WHERE false', '42501')
