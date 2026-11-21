"""M03.1 tests: dependencies (D04/D05) and blockers. Disposable PostgreSQL, synthetic data only."""
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

from backend.acl import AclError
from backend.links import LinksService
from test_m01_acl import acl, admin_sql, migrator, person, rows, status, violates, world  # noqa: F401
from test_m01_auth import service  # noqa: F401
from test_m02_work import join, new_project, new_task  # noqa: F401


@pytest.fixture(scope='module')
def links(service):
    return LinksService(service)


@pytest.fixture(scope='module')
def w(service, acl, migrator):
    return world(service, acl, migrator)


def three_tasks(links, a, w):
    return [new_task(links, a, w)['id'] for _ in range(3)]


def test_g01_dependency_rules_and_cycles(service, acl, links, w, migrator):
    a = join(acl, w, person(service))
    stranger = join(acl, w, person(service), team=False)
    A, B, C = three_tasks(links, a, w)
    edge = links.add_dependency(a.token, a.csrf, A, B, 'needs A first')
    assert edge['created'] is True
    again = links.add_dependency(a.token, a.csrf, A, B, 'needs A first')
    assert again['created'] is False and again['id'] == edge['id']
    assert status(lambda: links.add_dependency(a.token, a.csrf, A, A)) == 422
    assert status(lambda: links.add_dependency(a.token, a.csrf, B, A)) == 422        # direct cycle
    links.add_dependency(a.token, a.csrf, B, C)
    assert status(lambda: links.add_dependency(a.token, a.csrf, C, A)) == 422        # transitive cycle
    assert status(lambda: links.add_dependency(stranger.token, stranger.csrf, A, C)) == 404
    assert status(lambda: links.add_dependency(a.token, a.csrf, A, uuid.uuid4())) == 404
    # statuses are never changed by a dependency; active means the blocker is not done
    listed = links.list_dependencies(a.token, B)
    assert listed['has_active_dependencies'] is True and listed['hidden_external'] == 0
    assert sorted((e['direction'], str(e['task_id'])) for e in listed['edges']) == sorted([('blocked_by', str(A)), ('blocks', str(C))])
    done = links.update_task(a.token, a.csrf, A, 1, {'status': 'done'})
    assert links.list_dependencies(a.token, B)['has_active_dependencies'] is False
    assert links.get_task(a.token, B)['status'] == 'new'
    # archived tasks cannot be linked
    arch = links.set_task_archived(a.token, a.csrf, C, True, 1)
    D = new_task(links, a, w)['id']
    assert status(lambda: links.add_dependency(a.token, a.csrf, D, C)) == 409
    links.set_task_archived(a.token, a.csrf, C, False, arch['version'])
    assert done['version'] == 2


def test_g02_remove_restore_with_reason(service, acl, links, w, migrator):
    a = join(acl, w, person(service))
    A, B, C = three_tasks(links, a, w)
    edge = links.add_dependency(a.token, a.csrf, A, B)
    assert status(lambda: links.remove_dependency(a.token, a.csrf, edge['id'], ' ', 1)) == 422
    assert status(lambda: links.remove_dependency(a.token, a.csrf, edge['id'], 'no longer needed', 9)) == 409
    removed = links.remove_dependency(a.token, a.csrf, edge['id'], 'no longer needed', 1)
    assert removed['changed'] is True
    assert links.remove_dependency(a.token, a.csrf, edge['id'], 'again', 1)['changed'] is False
    assert links.list_dependencies(a.token, B)['edges'] == []
    links.add_dependency(a.token, a.csrf, B, A)                     # opposite direction is fine once removed
    assert status(lambda: links.restore_dependency(a.token, a.csrf, edge['id'], removed['version'])) == 422  # would cycle
    other = links.add_dependency(a.token, a.csrf, A, C)
    links.remove_dependency(a.token, a.csrf, other['id'], 'temp', 1)
    restored = links.restore_dependency(a.token, a.csrf, other['id'], 2)
    assert restored['changed'] is True
    assert links.add_dependency(a.token, a.csrf, A, C)['id'] == other['id']
    row = rows(migrator, 'SELECT deleted_at, deletion_reason FROM task_ayuza.task_dependencies WHERE id=:id', id=edge['id'])[0]
    assert row['deleted_at'] is not None and row['deletion_reason'] == 'no longer needed'


def test_g03_cross_workspace_and_hidden_external(service, acl, links, w, migrator):
    w2 = world(service, acl, migrator)
    p = person(service)
    join(acl, w, p)
    join(acl, w2, p)
    only1 = join(acl, w, person(service))
    only2 = join(acl, w2, person(service))
    T1 = new_task(links, p, w)['id']
    T2 = links.create_task(p.token, p.csrf, w2.ws, 'Cross title secret', p.id, w2.team)['id']
    edge = links.add_dependency(p.token, p.csrf, T1, T2, 'cross')
    assert edge['created'] is True
    mine = links.list_dependencies(p.token, T1)
    assert mine['edges'][0]['task_id'] == T2 and mine['hidden_external'] == 0
    # a reader of one side sees only a safe indicator of the hidden one
    solo = links.get_task(only1.token, T1)
    assert solo['id'] == T1
    seen = links.list_dependencies(only1.token, T1)
    assert seen['edges'] == [] and seen['hidden_external'] == 1 and seen['has_active_dependencies'] is False
    assert 'Cross title secret' not in repr(seen) and str(T2) not in repr(seen)
    assert links.list_dependencies(only2.token, T2)['hidden_external'] == 1
    # no access to either side: not found; link on one side only: 404 on the other
    assert status(lambda: links.add_dependency(only1.token, only1.csrf, T1, T2)) in (403, 404)
    assert status(lambda: links.remove_dependency(only1.token, only1.csrf, edge['id'], 'x', 1)) in (403, 404)
    audit_ws = {r['workspace_id'] for r in rows(migrator, "SELECT workspace_id FROM task_ayuza.audit_events WHERE entity_id=:e AND action='dependency.created'", e=edge['id'])}
    assert audit_ws == {w.ws, w2.ws}
    dump = repr(rows(migrator, 'SELECT "old","new" FROM task_ayuza.audit_events'))
    assert str(T1) not in dump and str(T2) not in dump


def test_g04_concurrent_opposite_edges(service, acl, links, w, migrator):
    a = join(acl, w, person(service))
    A, B = new_task(links, a, w)['id'], new_task(links, a, w)['id']

    def attempt(pair):
        try:
            return links.add_dependency(a.token, a.csrf, *pair)['created']
        except AclError as error:
            return error.status
    with ThreadPoolExecutor(4) as pool:
        results = list(pool.map(attempt, [(A, B), (B, A), (A, B), (B, A)]))
    active = rows(migrator, 'SELECT blocker_task_id, dependent_task_id FROM task_ayuza.task_dependencies WHERE deleted_at IS NULL AND blocker_task_id IN (:a, :b)', a=A, b=B)
    assert len(active) == 1 and 422 in results


def test_g05_blockers(service, acl, links, w, migrator):
    a = join(acl, w, person(service))
    reader = join(acl, w, person(service), team=False)
    helper = person(service)                                   # active user without any access to the task
    stranger = join(acl, w, person(service), team=False)
    T, other = new_task(links, a, w)['id'], new_task(links, a, w)['id']
    assert status(lambda: links.create_blocker(a.token, a.csrf, T, 'Waiting for parts')) == 422   # no responsible
    assert status(lambda: links.create_blocker(a.token, a.csrf, T, '', responsible_team_id=w.team)) == 422
    assert status(lambda: links.create_blocker(stranger.token, stranger.csrf, T, 'X', responsible_team_id=w.team)) == 404
    assert status(lambda: links.create_blocker(a.token, a.csrf, T, 'X', responsible_user_id=uuid.uuid4())) == 422
    b = links.create_blocker(a.token, a.csrf, T, 'Waiting for parts', 'secret reason', responsible_user_id=helper.id,
                             blocking_task_id=other, expected_resolution_date='2026-12-20')
    # naming a responsible person does not open the task to them
    assert status(lambda: links.get_task(helper.token, T)) == 404
    # explicit read-only access: may see the blocker, may not change it
    links.set_task_access(a.token, a.csrf, T, reader.id, 'read', True, 'view')
    seen = links.list_blockers(reader.token, T)
    assert [x['id'] for x in seen] == [b['id']] and seen[0]['blocking_task_id'] is None   # blocking task is hidden from this reader
    assert links.list_blockers(a.token, T)[0]['blocking_task_id'] == other
    assert status(lambda: links.update_blocker(reader.token, reader.csrf, b['id'], 1, {'title': 'x'})) == 403
    assert status(lambda: links.set_blocker_resolved(stranger.token, stranger.csrf, b['id'], True, 1)) == 404
    assert status(lambda: links.update_blocker(a.token, a.csrf, b['id'], 1, {'responsible_user_id': None})) == 422  # last responsible
    upd = links.update_blocker(a.token, a.csrf, b['id'], 1, {'responsible_team_id': w.team, 'title': 'Parts delayed'})
    assert upd['version'] == 2
    assert links.update_blocker(a.token, a.csrf, b['id'], 2, {'responsible_team_id': w.team})['changed'] is False
    assert status(lambda: links.update_blocker(a.token, a.csrf, b['id'], 1, {'title': 'Stale'})) == 409
    assert status(lambda: links.update_blocker(a.token, a.csrf, b['id'], 2, {'status': 'resolved'})) == 422
    links.update_blocker(a.token, a.csrf, b['id'], 2, {'responsible_user_id': None})   # team remains
    res = links.set_blocker_resolved(a.token, a.csrf, b['id'], True, 3)
    assert links.list_blockers(a.token, T, include_resolved=False) == []
    assert links.get_task(a.token, T)['status'] == 'new'                                # never changes the task
    reopened = links.set_blocker_resolved(a.token, a.csrf, b['id'], False, res['version'])
    archived = links.set_blocker_archived(a.token, a.csrf, b['id'], True, reopened['version'])
    assert links.list_blockers(a.token, T) == []
    links.set_blocker_archived(a.token, a.csrf, b['id'], False, archived['version'])
    events = links.list_blocker_events(a.token, b['id'])
    assert [e['event_type'] for e in events] == ['created', 'updated', 'updated', 'resolved', 'reopened', 'archived', 'restored']
    assert events[0]['responsible_user_id_snapshot'] == helper.id and events[0]['blocking_task_id_snapshot'] == other
    assert all(e['blocking_task_id_snapshot'] is None for e in links.list_blocker_events(reader.token, b['id']))
    assert status(lambda: links.list_blocker_events(stranger.token, b['id'])) == 404
    dump = repr(rows(migrator, 'SELECT "old","new" FROM task_ayuza.audit_events'))
    assert 'secret reason' not in dump and 'Waiting for parts' not in dump and 'Parts delayed' not in dump
    # blocking task the creator cannot read is rejected as not found
    w3 = world(service, acl, migrator)
    outsider = join(acl, w3, person(service))
    hidden = new_task(links, outsider, w3)['id']
    assert status(lambda: links.create_blocker(a.token, a.csrf, T, 'Hidden link', responsible_team_id=w.team, blocking_task_id=hidden)) == 404


def test_g06_constraints(service, acl, links, w, migrator):
    a = join(acl, w, person(service))
    A, B = new_task(links, a, w)['id'], new_task(links, a, w)['id']
    edge = links.add_dependency(a.token, a.csrf, A, B)['id']
    blocker = links.create_blocker(a.token, a.csrf, A, 'Constraint check', responsible_team_id=w.team)['id']
    violates(migrator, "UPDATE task_ayuza.task_dependencies SET dependent_task_id=blocker_task_id WHERE id=:id", '23514', id=edge)
    violates(migrator, "INSERT INTO task_ayuza.task_dependencies (id, blocker_task_id, dependent_task_id, created_by) SELECT gen_random_uuid(), blocker_task_id, dependent_task_id, created_by FROM task_ayuza.task_dependencies WHERE id=:id", '23505', id=edge)
    violates(migrator, "UPDATE task_ayuza.task_dependencies SET deleted_at=now(), deleted_by=created_by WHERE id=:id", '23514', id=edge)
    violates(migrator, "UPDATE task_ayuza.blockers SET responsible_team_id=NULL, responsible_user_id=NULL WHERE id=:id", '23514', id=blocker)
    violates(migrator, "UPDATE task_ayuza.blockers SET status='resolved' WHERE id=:id", '23514', id=blocker)
    violates(migrator, "UPDATE task_ayuza.blockers SET blocking_task_id=blocked_task_id WHERE id=:id", '23514', id=blocker)
    violates(migrator, "UPDATE task_ayuza.blockers SET status='closed' WHERE id=:id", '23514', id=blocker)
    for table in ('task_dependencies', 'blockers', 'blocker_events'):
        violates(service.engine, f'TRUNCATE task_ayuza.{table}', '42501')
        violates(service.engine, f'DELETE FROM task_ayuza.{table} WHERE false', '42501')
    violates(service.engine, "UPDATE task_ayuza.blocker_events SET event_type='created' WHERE false", '42501')
