"""M08.2 tests: the 'Now' snapshot (service and HTTP). Disposable PostgreSQL, synthetic data only."""
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
    with TestClient(app, base_url=ORIGIN, client=('192.0.2.88', 1234)) as c:
        yield c


def today(migrator, tz):
    return rows(migrator, 'SELECT (clock_timestamp() AT TIME ZONE :tz)::date AS d', tz=tz)[0]['d']


def due(migrator, task, value):
    admin_sql(migrator, 'UPDATE task_ayuza.tasks SET due_date = :d WHERE id = :t', d=value, t=task['id'])


def setup_known(service, acl, work, migrator, w):
    a = join(acl, w, person(service))
    day, one = today(migrator, 'Europe/Moscow'), datetime.timedelta(days=1)

    def make(new_status=None, offset=None, **kw):
        t = new_task(work, a, w, **kw)
        if new_status:
            t = {**t, 'version': work.update_task(a.token, a.csrf, t['id'], t['version'], {'status': new_status})['version']}
        if offset is not None:
            due(migrator, t, day + offset * one)
        return t
    t1 = make()                                   # open, no due date
    make('in_progress', 0)                        # due today
    make(None, -1)                                # overdue
    make('blocked', 3)                            # blocked, due in 3 days
    make('done', -1)                              # done: never overdue
    make('cancelled', 0)                          # cancelled: only in the total
    make(None, 10)                                # beyond the nearest window
    make(None, None, parent_task_id=t1['id'])     # a subtask
    return a


@pytest.fixture()
def fresh(service, acl, migrator):
    return world(service, acl, migrator)


def test_s01_counts_on_a_known_set(service, acl, work, migrator, fresh):
    a = setup_known(service, acl, work, migrator, fresh)
    snap = work.snapshot(a.token, fresh.ws)
    assert snap == {'total': 7, 'active': 5, 'in_progress': 1, 'done': 1, 'blocked': 1, 'overdue': 1, 'upcoming': 2,
                    'no_due_date': 1, 'no_project': 7, 'include_subtasks': False, 'upcoming_days': 7}
    with_subs = work.snapshot(a.token, fresh.ws, include_subtasks=True)
    assert (with_subs['total'], with_subs['active'], with_subs['no_due_date']) == (8, 6, 2)


def test_s02_hidden_tasks_change_no_number(service, acl, work, migrator, fresh):
    a = setup_known(service, acl, work, migrator, fresh)
    outsider_member = join(acl, fresh, person(service), team=False)        # a workspace member without the executor team
    assert work.snapshot(a.token, fresh.ws)['total'] == 7
    assert work.snapshot(outsider_member.token, fresh.ws)['total'] == 0   # nothing readable: not even a count leaks
    own = new_task(work, outsider_member, fresh)
    assert work.snapshot(outsider_member.token, fresh.ws)['total'] == 1
    assert [str(t['id']) for t in work.list_tasks(outsider_member.token, fresh.ws)] == [str(own['id'])]   # list and snapshot agree
    stranger = person(service)
    assert status(lambda: work.snapshot(stranger.token, fresh.ws)) == 404


def test_s03_archived_tasks_are_not_counted(service, acl, work, migrator, fresh):
    a = setup_known(service, acl, work, migrator, fresh)
    first = work.list_tasks(a.token, fresh.ws, limit=1)[0]
    admin_sql(migrator, 'UPDATE task_ayuza.tasks SET archived_at = clock_timestamp() WHERE id = :t', t=first['id'])
    assert work.snapshot(a.token, fresh.ws, include_subtasks=True)['total'] == 7
    assert status(lambda: work.snapshot(a.token, fresh.ws, include_subtasks='yes')) == 422


def test_s04_today_follows_the_workspace_time_zone(service, acl, work, migrator, fresh):
    other = world(service, acl, migrator)
    a1, a2 = join(acl, fresh, person(service)), join(acl, other, person(service))
    admin_sql(migrator, "UPDATE task_ayuza.workspaces SET timezone = 'Pacific/Kiritimati' WHERE id = :w", w=fresh.ws)
    admin_sql(migrator, "UPDATE task_ayuza.workspaces SET timezone = 'Etc/GMT+12' WHERE id = :w", w=other.ws)
    west = today(migrator, 'Etc/GMT+12')
    due(migrator, new_task(work, a1, fresh), west)
    due(migrator, new_task(work, a2, other), west)                          # the same date, different local "today"
    east_snap, west_snap = work.snapshot(a1.token, fresh.ws), work.snapshot(a2.token, other.ws)
    assert (east_snap['overdue'], east_snap['upcoming']) == (1, 0)
    assert (west_snap['overdue'], west_snap['upcoming']) == (0, 1)


def test_s05_http_route(client, service, acl, work, migrator, fresh):
    a = setup_known(service, acl, work, migrator, fresh)
    path = f'/api/v1/workspaces/{fresh.ws}/snapshot'
    assert client.get(path).status_code in (401, 403)
    ok = client.get(path, headers=read(a))
    assert ok.status_code == 200 and ok.json()['total'] == 7 and ok.json()['include_subtasks'] is False
    assert client.get(path + '?include_subtasks=true', headers=read(a)).json()['total'] == 8
    assert client.get(path + '?include_subtasks=maybe', headers=read(a)).status_code == 422
    stranger = person(service)
    assert client.get(path, headers=read(stranger)).status_code == 404
