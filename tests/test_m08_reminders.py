"""M08.1 tests: due-date and overdue reminders. Disposable PostgreSQL, synthetic data only."""
import asyncio
import datetime

import pytest

from backend.notifications import NotificationsService
from backend.scheduler import outbox_loop
from test_m01_acl import acl, admin_sql, migrator, person, rows, status, violates, world  # noqa: F401
from test_m01_auth import service  # noqa: F401
from test_m02_work import join, new_task  # noqa: F401

REMINDERS = ('task_due_soon', 'task_overdue')


@pytest.fixture(scope='module')
def notes(service):
    return NotificationsService(service)


@pytest.fixture(scope='module')
def w(service, acl, migrator):
    return world(service, acl, migrator)


def today(migrator, tz):
    return rows(migrator, 'SELECT (clock_timestamp() AT TIME ZONE :tz)::date AS d', tz=tz)[0]['d']


def due(migrator, task, value):
    admin_sql(migrator, 'UPDATE task_ayuza.tasks SET due_date = :d WHERE id = :t', d=value, t=task['id'])


def reminders(migrator, tasks):
    ids = {str(t['id']) for t in tasks}
    out = {}
    for r in rows(migrator, "SELECT task_id, event_type, recipient_user_id, actor_user_id, state FROM task_ayuza.outbox_events "
                            "WHERE event_type IN ('task_due_soon', 'task_overdue')"):
        if str(r['task_id']) in ids:
            out.setdefault(str(r['task_id']), []).append(r)
    return out


def test_r01_open_tasks_get_the_right_reminder_once_per_recipient(service, acl, notes, w, migrator):
    a, b = join(acl, w, person(service)), join(acl, w, person(service))
    day = today(migrator, 'Europe/Moscow')
    one_day = datetime.timedelta(days=1)
    make = lambda: new_task(notes, a, w)  # noqa: E731
    overdue, now_, tomorrow, far, nodate, finished, archived = (make() for _ in range(7))
    versions = {}
    for t in (overdue, now_, tomorrow, far, finished, archived):
        versions[t['id']] = notes.assign_task(a.token, a.csrf, t['id'], 1, assignee_user_id=b.id)['version']
    notes.update_task(a.token, a.csrf, finished['id'], versions[finished['id']], {'status': 'done'})
    admin_sql(migrator, 'UPDATE task_ayuza.tasks SET archived_at = clock_timestamp() WHERE id = :t', t=archived['id'])
    for t, offset in ((overdue, -1), (now_, 0), (tomorrow, 1), (far, 3), (finished, 0), (archived, 0)):
        due(migrator, t, day + offset * one_day)
    version = rows(migrator, 'SELECT version FROM task_ayuza.tasks WHERE id=:t', t=overdue['id'])[0]['version']

    assert notes.enqueue_due_reminders()['queued'] >= 6
    found = reminders(migrator, [overdue, now_, tomorrow, far, nodate, finished, archived])
    kinds = {k: sorted({r['event_type'] for r in v}) for k, v in found.items()}
    assert kinds == {str(overdue['id']): ['task_overdue'], str(now_['id']): ['task_due_soon'], str(tomorrow['id']): ['task_due_soon']}
    for v in found.values():
        assert sorted(str(r['recipient_user_id']) for r in v) == sorted([str(a.id), str(b.id)])
        assert all(r['actor_user_id'] is None and r['state'] == 'pending' for r in v)
    assert rows(migrator, 'SELECT version FROM task_ayuza.tasks WHERE id=:t', t=overdue['id'])[0]['version'] == version  # tasks are untouched

    assert notes.enqueue_due_reminders()['queued'] == 0                   # a repeated pass adds nothing
    due(migrator, tomorrow, day + 2 * one_day)
    assert notes.enqueue_due_reminders()['queued'] == 0                   # outside the window
    due(migrator, tomorrow, day)
    assert notes.enqueue_due_reminders()['queued'] == 2                   # a new due date earns a new reminder

    notes.process_outbox()
    mine = [n for n in notes.list_notifications(b.token) if n['event_type'] in REMINDERS]
    assert sorted(n['event_type'] for n in mine) == ['task_due_soon', 'task_due_soon', 'task_due_soon', 'task_overdue']


def test_r02_today_is_the_date_in_the_workspace_time_zone(service, acl, notes, w, migrator):
    other = world(service, acl, migrator)
    a1, a2 = join(acl, w, person(service)), join(acl, other, person(service))
    admin_sql(migrator, "UPDATE task_ayuza.workspaces SET timezone = 'Pacific/Kiritimati' WHERE id = :w", w=w.ws)
    admin_sql(migrator, "UPDATE task_ayuza.workspaces SET timezone = 'Etc/GMT+12' WHERE id = :w", w=other.ws)
    east, west = today(migrator, 'Pacific/Kiritimati'), today(migrator, 'Etc/GMT+12')
    assert east > west                                                    # 26 hours apart: never the same date
    t1, t2 = new_task(notes, a1, w), new_task(notes, a2, other)
    due(migrator, t1, west)
    due(migrator, t2, west)                                               # the same date, opposite classification
    notes.enqueue_due_reminders()
    found = reminders(migrator, [t1, t2])
    assert {r['event_type'] for r in found[str(t1['id'])]} == {'task_overdue'}
    assert {r['event_type'] for r in found[str(t2['id'])]} == {'task_due_soon'}


def test_r03_input_is_validated(notes):
    for bad in (-1, 8, True, '1'):
        with pytest.raises(Exception):
            notes.enqueue_due_reminders(soon_days=bad)
    for bad in (0, 5001, True):
        with pytest.raises(Exception):
            notes.enqueue_due_reminders(limit=bad)


def test_r04_scheduler_loop_runs_reminders_first(service, acl, notes, w, migrator):
    a = join(acl, w, person(service))
    t = new_task(notes, a, w)
    notes.assign_task(a.token, a.csrf, t['id'], 1, assignee_user_id=join(acl, w, person(service)).id)
    due(migrator, t, today(migrator, 'Pacific/Kiritimati') - datetime.timedelta(days=5))

    async def scenario():
        stats = {}
        task = asyncio.create_task(outbox_loop(notes, 0.05, stats, reminder_every=3600))
        for _ in range(60):
            await asyncio.sleep(0.05)
            if stats.get('reminders_queued'):
                break
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        return stats
    stats = asyncio.run(scenario())
    assert stats['reminders_queued'] >= 1 and stats.get('errors', 0) == 0
    assert str(t['id']) in reminders(migrator, [t])
