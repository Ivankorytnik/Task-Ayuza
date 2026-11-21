"""M07.2 tests: in-process outbox scheduler. Disposable PostgreSQL, synthetic data only."""
import asyncio

import pytest

from backend.config import ConfigurationError
from backend.notifications import NotificationsService
from backend.scheduler import DEFAULT_INTERVAL, outbox_interval, outbox_loop, run_once
from test_m01_acl import acl, admin_sql, migrator, person, rows, status, violates, world  # noqa: F401
from test_m01_auth import service  # noqa: F401
from test_m02_work import join, new_task  # noqa: F401


@pytest.fixture(scope='module')
def notes(service):
    return NotificationsService(service)


@pytest.fixture(scope='module')
def w(service, acl, migrator):
    return world(service, acl, migrator)


def test_p01_interval_is_validated(monkeypatch):
    monkeypatch.delenv('TASK_AYUZA_OUTBOX_INTERVAL', raising=False)
    assert outbox_interval() == DEFAULT_INTERVAL
    monkeypatch.setenv('TASK_AYUZA_OUTBOX_INTERVAL', '0')
    assert outbox_interval() == 0
    for bad in ('-1', 'x', '3601', '1.5', ''):
        monkeypatch.setenv('TASK_AYUZA_OUTBOX_INTERVAL', bad)
        with pytest.raises(ConfigurationError):
            outbox_interval()


def test_p02_failure_is_counted_and_never_escapes():
    class Broken:
        def process_outbox(self):
            raise RuntimeError('secret title must not be logged')
    out = asyncio.run(run_once(Broken()))
    assert out == {'created': 0, 'failed': 0, 'error': True}


def test_p03_loop_delivers_pending_events_and_stops_cleanly(service, acl, notes, w):
    a, b = join(acl, w, person(service)), join(acl, w, person(service))
    t = new_task(notes, a, w)
    notes.assign_task(a.token, a.csrf, t['id'], 1, assignee_user_id=b.id)
    assert notes.list_notifications(b.token) == []

    async def scenario():
        stats = {}
        task = asyncio.create_task(outbox_loop(notes, 0.05, stats))
        for _ in range(60):
            await asyncio.sleep(0.05)
            if stats.get('created'):
                break
        task.cancel()
        results = await asyncio.gather(task, return_exceptions=True)
        return stats, results
    stats, results = asyncio.run(scenario())
    assert stats['created'] >= 1 and stats['passes'] >= 1 and stats.get('errors', 0) == 0
    assert isinstance(results[0], asyncio.CancelledError)
    assert [n['event_type'] for n in notes.list_notifications(b.token)] == ['task_assigned']
    assert asyncio.run(run_once(notes))['created'] == 0                  # repeating is harmless


def test_p04_loop_survives_a_failing_pass():
    calls = []

    class Flaky:
        def process_outbox(self):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError('database down')
            return {'created': 2, 'failed': 0}

    async def scenario():
        stats = {}
        task = asyncio.create_task(outbox_loop(Flaky(), 0.01, stats))
        await asyncio.sleep(0.2)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        return stats
    stats = asyncio.run(scenario())
    assert stats['errors'] == 1 and stats['created'] >= 2
