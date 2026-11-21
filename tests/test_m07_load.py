"""M07.3 / F25: 20 concurrent sessions and 5000 synthetic tasks. Disposable PostgreSQL, synthetic data only.
Checks completeness (no loss, no duplicates, all pages reachable, counts match). Timings are printed as measurements,
never asserted as promises."""
import statistics
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from backend.exports import ExportsService
from test_m01_acl import acl, admin_sql, migrator, person, rows, status, violates, world  # noqa: F401
from test_m01_auth import service  # noqa: F401
from test_m02_work import join, new_task  # noqa: F401

SESSIONS, BULK, PER_SESSION, TOTAL = 20, 4800, 10, 5000
PAGE = 200


@pytest.fixture(scope='module')
def work(service):
    return ExportsService(service)


@pytest.fixture(scope='module')
def w(service, acl, migrator):
    return world(service, acl, migrator)


def read_all(work, who, ws, timings=None):
    ids, after = [], None
    while True:
        started = time.perf_counter()
        page = work.list_tasks(who.token, ws, limit=PAGE, after=after)
        if timings is not None:
            timings.append(time.perf_counter() - started)
        ids.extend(str(t['id']) for t in page)
        if len(page) < PAGE:
            return ids
        after = page[-1]['id']


def test_q01_f25_five_thousand_tasks_twenty_sessions(service, acl, work, w, migrator, capsys):
    users = [join(acl, w, person(service)) for _ in range(SESSIONS)]
    admin_sql(migrator, '''INSERT INTO task_ayuza.tasks (id, workspace_id, title, status, created_by_user_id,
        result_owner_user_id, executor_team_id)
        SELECT gen_random_uuid(), :w, 'Synthetic load ' || g, 'new', :u, :u, :t FROM generate_series(1, :n) g''',
              w=w.ws, u=users[0].id, t=w.team, n=BULK)

    def session(index):
        who, timings, mine = users[index], [], []
        for _ in range(PER_SESSION):
            mine.append(new_task(work, who, w))
        for task in mine[:5]:                                              # parallel saves with versions
            assert work.update_task(who.token, who.csrf, task['id'], task['version'], {'status': 'in_progress'})['version'] == 2
        return mine, read_all(work, who, w.ws, timings), timings

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=SESSIONS) as pool:
        results = list(pool.map(session, range(SESSIONS)))           # any exception here fails the test
    elapsed = time.perf_counter() - started

    created = [str(t['id']) for mine, _, _ in results for t in mine]
    assert len(created) == len(set(created)) == SESSIONS * PER_SESSION
    count = rows(migrator, 'SELECT count(*) AS n FROM task_ayuza.tasks WHERE workspace_id=:w', w=w.ws)[0]['n']
    assert count == TOTAL
    for who in (users[0], users[SESSIONS - 1]):
        ids = read_all(work, who, w.ws)
        assert len(ids) == len(set(ids)) == TOTAL and ids == sorted(ids)      # no loss, no duplicates, stable order
    for _, ids, _ in results:
        assert len(ids) == len(set(ids)) and len(ids) >= BULK              # each concurrent reader saw whole pages
    assert set(created) <= set(read_all(work, users[0], w.ws))
    moved = rows(migrator, "SELECT count(*) AS n FROM task_ayuza.tasks WHERE workspace_id=:w AND status='in_progress'", w=w.ws)[0]['n']
    assert moved == SESSIONS * 5                                           # every parallel save landed exactly once
    deep = work.list_tasks(users[0].token, w.ws, limit=PAGE, after=read_all(work, users[0], w.ws)[2400])
    assert len(deep) == PAGE                                               # pages beyond 2000 are reachable

    pages = sorted(t for _, _, timings in results for t in timings)
    with capsys.disabled():
        print(f'\nF25 measurement: {SESSIONS} sessions, {TOTAL} tasks, total {elapsed:.1f} s, '
              f'page of {PAGE}: median {statistics.median(pages) * 1000:.0f} ms, '
              f'p95 {pages[int(len(pages) * 0.95) - 1] * 1000:.0f} ms, max {pages[-1] * 1000:.0f} ms')
