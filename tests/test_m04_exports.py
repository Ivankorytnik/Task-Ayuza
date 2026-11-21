"""M04.3 tests: release metadata and task export. Disposable PostgreSQL, synthetic data only."""
import csv
import io
import json
import uuid

import pytest

from backend.exports import ExportsService
from test_m01_acl import acl, admin_sql, mark_mfa, migrator, person, rows, status, violates, world  # noqa: F401
from test_m01_auth import service  # noqa: F401
from test_m02_work import grant, join, new_task  # noqa: F401


@pytest.fixture(scope='module')
def ex(service):
    return ExportsService(service)


@pytest.fixture(scope='module')
def w(service, acl, migrator):
    return world(service, acl, migrator)


def release(migrator, version, sha='a' * 40, env='test', age="1 hour"):
    admin_sql(migrator, f'''INSERT INTO task_ayuza.releases (id, version, commit_sha, published_at, environment)
        VALUES (:id, :v, :sha, clock_timestamp() - interval '{age}', :env)''', id=uuid.uuid4(), v=version, sha=sha, env=env)


def test_j01_release_metadata_is_real_or_undefined(service, ex, w, migrator):
    p = person(service)
    assert ex.release_info(p.token) == {'version': None, 'label': 'Версия не определена'}
    release(migrator, '1.2.0', age='2 hours')
    release(migrator, '1.3.0', sha='b' * 40, env='staging', age='1 hour')
    info = ex.release_info(p.token)
    assert info['version'] == '1.3.0' and info['environment'] == 'staging' and info['published_at'] is not None
    violates(migrator, "INSERT INTO task_ayuza.releases (id, version, commit_sha, published_at, environment) VALUES (gen_random_uuid(), '1.3.0', :s, now() - interval '1 day', 'staging')", '23505', s='c' * 40)
    violates(migrator, "INSERT INTO task_ayuza.releases (id, version, commit_sha, published_at, environment) VALUES (gen_random_uuid(), '2.0', :s, now() - interval '1 day', 'test')", '23514', s='c' * 40)
    violates(migrator, "INSERT INTO task_ayuza.releases (id, version, commit_sha, published_at, environment) VALUES (gen_random_uuid(), '2.0.0', 'xyz', now() - interval '1 day', 'test')", '23514')
    violates(migrator, "INSERT INTO task_ayuza.releases (id, version, commit_sha, published_at, environment) VALUES (gen_random_uuid(), '2.0.0', :s, now() + interval '1 day', 'test')", '23514', s='c' * 40)
    violates(migrator, "INSERT INTO task_ayuza.releases (id, version, commit_sha, published_at, environment) VALUES (gen_random_uuid(), '2.0.0', :s, now() - interval '1 day', 'prod')", '23514', s='c' * 40)
    violates(service.engine, "INSERT INTO task_ayuza.releases (id, version, commit_sha, published_at, environment) VALUES (gen_random_uuid(), '9.9.9', :s, now() - interval '1 day', 'test')", '42501', s='c' * 40)


def test_j02_export_rights_rows_and_formula_safety(service, acl, ex, w, migrator):
    a, other, stranger = join(acl, w, person(service), team=False), join(acl, w, person(service), team=False), person(service)
    t1 = new_task(ex, a, w, title='=SUM(A1) Привет')['id']
    t2 = new_task(ex, a, w, title='Обычная задача')['id']
    hidden = new_task(ex, other, w, title='Чужая закрытая')['id']
    assert status(lambda: ex.export_tasks(a.token, a.csrf, w.ws, 'csv')) == 403            # export is a separate right
    assert status(lambda: ex.export_tasks(stranger.token, stranger.csrf, w.ws, 'csv')) == 404
    grant(migrator, a, w.ws, 'export', w.sysadmin)
    admin_sql(migrator, 'UPDATE task_ayuza.sessions SET mfa_verified_at = NULL WHERE user_id=:u', u=a.id)
    assert status(lambda: ex.export_tasks(a.token, a.csrf, w.ws, 'csv')) == 403            # the grant needs a fresh MFA
    mark_mfa(migrator, a)
    assert status(lambda: ex.export_tasks(a.token, a.csrf, w.ws, 'xml')) == 422
    assert status(lambda: ex.export_tasks(a.token, a.csrf, w.ws, 'csv', status='nope')) == 422
    out = ex.export_tasks(a.token, a.csrf, w.ws, 'csv')
    assert out['content'].startswith('﻿') and out['row_count'] == 2
    table = list(csv.reader(io.StringIO(out['content'][1:])))
    titles = {r[1] for r in table[1:]}
    assert titles == {"'=SUM(A1) Привет", 'Обычная задача'}                                 # formula neutralised, Cyrillic intact
    assert str(hidden) not in out['content'] and 'Чужая закрытая' not in out['content']   # the grant does not read tasks
    data = json.loads(ex.export_tasks(a.token, a.csrf, w.ws, 'json')['content'])
    assert sorted(r['id'] for r in data) == sorted([str(t1), str(t2)]) and data[0]['title'] in ('=SUM(A1) Привет', 'Обычная задача')
    ex.set_task_archived(a.token, a.csrf, t2, True, 1)
    assert ex.export_tasks(a.token, a.csrf, w.ws, 'csv', status='new')['row_count'] == 1   # archived rows are not exported
    assert ex.export_tasks(a.token, a.csrf, w.ws, 'csv', status='done')['row_count'] == 0
    ex.EXPORT_LIMIT = 0
    try:
        assert status(lambda: ex.export_tasks(a.token, a.csrf, w.ws, 'csv')) == 422
    finally:
        ex.EXPORT_LIMIT = 2000
    events = rows(migrator, 'SELECT * FROM task_ayuza.export_events WHERE actor_id=:a ORDER BY created_at', a=a.id)
    assert [(e['format'], e['row_count'], e['filters']) for e in events] == [
        ('csv', 2, {}), ('json', 2, {}), ('csv', 1, {'status': 'new'}), ('csv', 0, {'status': 'done'})]
    dump = repr(events) + repr(rows(migrator, "SELECT * FROM task_ayuza.audit_events WHERE action='export.completed'"))
    assert 'Привет' not in dump and 'Обычная' not in dump                                   # no copy of the data
    assert len(rows(migrator, "SELECT 1 FROM task_ayuza.audit_events WHERE action='export.completed' AND actor_id=:a", a=a.id)) == 4


def test_j03_export_event_constraints(service, ex, w, migrator):
    runtime = service.engine
    for table in ('export_events', 'releases'):
        violates(runtime, f'TRUNCATE task_ayuza.{table}', '42501')
        violates(runtime, f'DELETE FROM task_ayuza.{table} WHERE false', '42501')
    violates(runtime, "UPDATE task_ayuza.export_events SET row_count=0 WHERE false", '42501')
    a = person(service)
    insert = "INSERT INTO task_ayuza.export_events (id, actor_id, workspace_id, format, filters, row_count, request_id) VALUES (gen_random_uuid(), :a, :w, :f, CAST(:filters AS jsonb), :n, gen_random_uuid())"
    violates(migrator, insert, '23514', a=a.id, w=w.ws, f='xml', filters='{}', n=1)
    violates(migrator, insert, '23514', a=a.id, w=w.ws, f='csv', filters='{"title": "x"}', n=1)
    violates(migrator, insert, '23514', a=a.id, w=w.ws, f='csv', filters='{}', n=-1)
