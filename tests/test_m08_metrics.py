"""M08.5 tests: metrics for a period (service and HTTP). Disposable PostgreSQL, synthetic data only."""
import datetime

import pytest
from fastapi.testclient import TestClient

from backend.exports import ExportsService
from backend.main import app
from test_m01_acl import acl, admin_sql, migrator, person, rows, status, violates, world  # noqa: F401
from test_m01_auth import service  # noqa: F401
from test_m02_work import join, new_task  # noqa: F401
from test_m05_api import ORIGIN, read  # noqa: F401

ONE = datetime.timedelta(days=1)


@pytest.fixture(scope='module')
def work(service):
    return ExportsService(service)


@pytest.fixture(scope='module')
def client():
    with TestClient(app, base_url=ORIGIN, client=('192.0.2.90', 1234)) as c:
        yield c


def local_today(migrator, tz):
    return rows(migrator, 'SELECT (clock_timestamp() AT TIME ZONE :tz)::date AS d', tz=tz)[0]['d']


def history(service, acl, work, migrator):
    """Three tasks: t1 completed then reopened, t2 cancelled, t3 untouched. Everything happens 'now'."""
    w = world(service, acl, migrator)
    a = join(acl, w, person(service))
    t1, t2, t3 = (new_task(work, a, w) for _ in range(3))
    v = work.update_task(a.token, a.csrf, t1['id'], 1, {'status': 'done'})['version']
    work.update_task(a.token, a.csrf, t1['id'], v, {'status': 'in_progress'})
    work.update_task(a.token, a.csrf, t2['id'], 1, {'status': 'cancelled'})
    return w, a


def test_v01_counts_events_for_the_period_with_inclusive_borders(service, acl, work, migrator):
    w, a = history(service, acl, work, migrator)
    today = local_today(migrator, 'Europe/Moscow')
    expected = {'created': 3, 'completed': 1, 'cancelled': 1, 'reopened': 1}
    got = work.metrics(a.token, w.ws, today.isoformat(), today.isoformat())
    assert {k: got[k] for k in expected} == expected and got['from'] == got['to'] == today.isoformat()
    wide = work.metrics(a.token, w.ws, (today - 30 * ONE).isoformat(), (today + 5 * ONE).isoformat())
    assert {k: wide[k] for k in expected} == expected
    past = work.metrics(a.token, w.ws, (today - 9 * ONE).isoformat(), (today - ONE).isoformat())
    assert [past[k] for k in expected] == [0, 0, 0, 0]
    future = work.metrics(a.token, w.ws, (today + ONE).isoformat(), (today + 3 * ONE).isoformat())
    assert [future[k] for k in expected] == [0, 0, 0, 0]


def test_v02_archived_tasks_stay_in_the_history(service, acl, work, migrator):
    w, a = history(service, acl, work, migrator)
    today = local_today(migrator, 'Europe/Moscow').isoformat()
    first = work.list_tasks(a.token, w.ws, limit=1)[0]
    admin_sql(migrator, 'UPDATE task_ayuza.tasks SET archived_at = clock_timestamp() WHERE id = :t', t=first['id'])
    assert work.metrics(a.token, w.ws, today, today)['created'] == 3


def test_v03_hidden_tasks_change_no_number(service, acl, work, migrator):
    w, a = history(service, acl, work, migrator)
    today = local_today(migrator, 'Europe/Moscow').isoformat()
    outsider_member = join(acl, w, person(service), team=False)
    quiet = work.metrics(outsider_member.token, w.ws, today, today)
    assert [quiet[k] for k in ('created', 'completed', 'cancelled', 'reopened')] == [0, 0, 0, 0]
    new_task(work, outsider_member, w)
    assert work.metrics(outsider_member.token, w.ws, today, today)['created'] == 1      # only what this member can read
    stranger = person(service)
    assert status(lambda: work.metrics(stranger.token, w.ws, today, today)) == 404


def test_v04_dates_follow_the_workspace_time_zone(service, acl, work, migrator):
    (east_w, east_a), (west_w, west_a) = history(service, acl, work, migrator), history(service, acl, work, migrator)
    admin_sql(migrator, "UPDATE task_ayuza.workspaces SET timezone = 'Pacific/Kiritimati' WHERE id = :w", w=east_w.ws)
    admin_sql(migrator, "UPDATE task_ayuza.workspaces SET timezone = 'Etc/GMT+12' WHERE id = :w", w=west_w.ws)
    east, west = local_today(migrator, 'Pacific/Kiritimati'), local_today(migrator, 'Etc/GMT+12')
    assert east > west
    west_day = west.isoformat()                                           # a date that is already "yesterday" in the east
    assert work.metrics(west_a.token, west_w.ws, west_day, west_day)['created'] == 3
    assert work.metrics(east_a.token, east_w.ws, west_day, west_day)['created'] == 0
    assert work.metrics(east_a.token, east_w.ws, east.isoformat(), east.isoformat())['created'] == 3


def test_v05_period_is_validated(service, acl, work, migrator):
    w, a = history(service, acl, work, migrator)
    day = local_today(migrator, 'Europe/Moscow') - 400 * ONE               # long before the synthetic history
    call = lambda d1, d2: status(lambda: work.metrics(a.token, w.ws, d1, d2))  # noqa: E731
    assert call('2026-11-22', '2026-11-21') == 422                         # start after end
    assert call('2026-02-30', '2026-03-01') == 422 and call('21.11.2026', '2026-11-21') == 422 and call(None, '2026-11-21') == 422
    assert call((day - 366 * ONE).isoformat(), day.isoformat()) == 422     # 367 days
    assert work.metrics(a.token, w.ws, (day - 365 * ONE).isoformat(), day.isoformat())['created'] == 0   # 366 days is allowed


def test_v06_http_route(client, service, acl, work, migrator):
    w, a = history(service, acl, work, migrator)
    today = local_today(migrator, 'Europe/Moscow').isoformat()
    path = f'/api/v1/workspaces/{w.ws}/metrics'
    assert client.get(f'{path}?from={today}&to={today}').status_code in (401, 403)
    ok = client.get(f'{path}?from={today}&to={today}', headers=read(a))
    assert ok.status_code == 200 and ok.json()['created'] == 3 and ok.json()['completed'] == 1
    assert client.get(f'{path}?from={today}', headers=read(a)).status_code == 422
    assert client.get(f'{path}?from=bad&to={today}', headers=read(a)).status_code == 422
    assert client.get(f'{path}?from={today}&to={today}', headers=read(person(service))).status_code == 404
