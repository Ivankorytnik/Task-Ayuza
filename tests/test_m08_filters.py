"""M08.4 tests: task list filters (service and HTTP). Disposable PostgreSQL, synthetic data only."""
import datetime

import pytest
from fastapi.testclient import TestClient

from backend.exports import ExportsService
from backend.main import app
from test_m01_acl import acl, admin_sql, migrator, person, rows, status, violates, world  # noqa: F401
from test_m01_auth import service  # noqa: F401
from test_m02_work import join, new_task  # noqa: F401
from test_m05_api import ORIGIN, read  # noqa: F401


@pytest.fixture(scope='module')
def work(service):
    return ExportsService(service)


@pytest.fixture(scope='module')
def client():
    with TestClient(app, base_url=ORIGIN, client=('192.0.2.89', 1234)) as c:
        yield c


@pytest.fixture(scope='module')
def f(service, acl, work, migrator):
    """One workspace with a known set; ids are returned by name."""
    w = world(service, acl, migrator)
    a, b = join(acl, w, person(service)), join(acl, w, person(service))
    day = rows(migrator, "SELECT (clock_timestamp() AT TIME ZONE 'Europe/Moscow')::date AS d")[0]['d']
    yesterday = day - datetime.timedelta(days=1)
    team2 = acl.create_team(w.sysadmin.token, w.sysadmin.csrf, 'Synthetic T2')['id']
    acl.set_workspace_team(w.admin.token, w.admin.csrf, w.ws, team2)
    project = work.create_project(a.token, a.csrf, w.ws, 'Synthetic project', 'd', a.id)
    t = {}
    t['plain'] = new_task(work, a, w)
    t['assigned'] = new_task(work, a, w)
    work.assign_task(a.token, a.csrf, t['assigned']['id'], t['assigned']['version'], assignee_user_id=b.id)
    t['in_project'] = new_task(work, a, w, project_id=project['id'])
    t['late'] = new_task(work, a, w)
    t['late_done'] = new_task(work, a, w)
    t['blocked'] = new_task(work, a, w)
    t['unblocked'] = new_task(work, a, w)
    t['other_team'] = new_task(work, a, w)
    for name in ('late', 'late_done'):
        admin_sql(migrator, 'UPDATE task_ayuza.tasks SET due_date = :d WHERE id = :t', d=yesterday, t=t[name]['id'])
    work.update_task(a.token, a.csrf, t['late_done']['id'], t['late_done']['version'], {'status': 'done'})
    work.create_blocker(a.token, a.csrf, t['blocked']['id'], 'Ждём детали', responsible_user_id=a.id)
    resolved = work.create_blocker(a.token, a.csrf, t['unblocked']['id'], 'Уже не ждём', responsible_user_id=a.id)
    work.set_blocker_resolved(a.token, a.csrf, resolved['id'], True, resolved['version'])
    admin_sql(migrator, 'UPDATE task_ayuza.tasks SET executor_team_id = :x WHERE id = :t', x=team2, t=t['other_team']['id'])
    return {'w': w, 'a': a, 'b': b, 'team2': team2, 'project': project['id'], 't': {k: str(v['id']) for k, v in t.items()}}


def ids(work, who, f, **kw):
    out, after = [], None
    while True:
        page = work.list_tasks(who.token, f['w'].ws, limit=2, after=after, **kw)
        out.extend(str(x['id']) for x in page)
        if len(page) < 2:
            return set(out)
        after = page[-1]['id']


def test_u01_each_filter_narrows_to_the_expected_tasks(work, f):
    a, b, t = f['a'], f['b'], f['t']
    assert ids(work, a, f) == set(t.values())                                    # no filter: everything a can read
    assert ids(work, a, f, mine=True) == set(t.values())                         # a created them all
    assert ids(work, b, f, mine=True) == {t['assigned']}                         # b: only the task assigned to b
    assert ids(work, a, f, overdue=True) == {t['late']}                          # the done one is not overdue
    assert ids(work, a, f, blocked=True) == {t['blocked']}                       # a resolved blocker does not count
    assert ids(work, a, f, project_id=f['project']) == {t['in_project']}
    assert ids(work, a, f, team_id=f['team2']) == {t['other_team']}
    assert ids(work, a, f, team_id=str(f['w'].team)) == set(t.values()) - {t['other_team']}
    assert ids(work, a, f, mine=True, overdue=True) == {t['late']}               # filters combine with AND
    assert ids(work, a, f, overdue=True, blocked=True) == set()
    assert ids(work, a, f, status='done') == {t['late_done']}


def test_u02_filters_never_widen_access(service, acl, work, f):
    outsider_member = join(acl, f['w'], person(service), team=False)             # a member who is not on the executor team
    assert ids(work, outsider_member, f) == set()
    for flags in ({'overdue': True}, {'blocked': True}, {'project_id': f['project']}, {'team_id': str(f['w'].team)}):
        assert ids(work, outsider_member, f, **flags) == set(), flags
    stranger = person(service)
    assert status(lambda: work.list_tasks(stranger.token, f['w'].ws, overdue=True)) == 404


def test_u03_input_is_validated(work, f):
    a = f['a']
    assert status(lambda: work.list_tasks(a.token, f['w'].ws, mine='yes')) == 422
    assert status(lambda: work.list_tasks(a.token, f['w'].ws, overdue=1)) == 422
    assert status(lambda: work.list_tasks(a.token, f['w'].ws, team_id='not-a-uuid')) in (404, 422)


def test_u04_http_query_parameters(client, f):
    a, path = f['a'], f"/api/v1/workspaces/{f['w'].ws}/tasks"
    got = lambda query: {x['id'] for x in client.get(f'{path}?{query}', headers=read(a)).json()}  # noqa: E731
    assert got('overdue=true&mine=true') == {f['t']['late']}
    assert got(f"project_id={f['project']}") == {f['t']['in_project']}
    assert got('blocked=true') == {f['t']['blocked']}
    assert client.get(f'{path}?mine=maybe', headers=read(a)).status_code == 422
    assert client.get(f'{path}?overdue=true').status_code in (401, 403)
