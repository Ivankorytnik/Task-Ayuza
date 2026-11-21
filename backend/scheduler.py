"""In-process background loops. No external scheduler: one loop per app instance; the work itself is safe to run
concurrently from several instances (SKIP LOCKED) and to repeat (dedupe keys)."""
import asyncio
import logging
import os
import time

from backend.config import ConfigurationError

log = logging.getLogger('task_ayuza.scheduler')
DEFAULT_INTERVAL = 30
MAX_INTERVAL = 3600
REMINDER_EVERY = 600      # seconds between due-date reminder scans (the scan is cheap but needless every 30 s)


def outbox_interval() -> int:
    """Seconds between outbox runs; 0 turns the loop off."""
    raw = os.environ.get('TASK_AYUZA_OUTBOX_INTERVAL', str(DEFAULT_INTERVAL))
    try:
        value = int(raw)
    except ValueError:
        raise ConfigurationError('Invalid outbox interval') from None
    if not 0 <= value <= MAX_INTERVAL:
        raise ConfigurationError('Invalid outbox interval')
    return value


async def run_once(service) -> dict:
    """One pass. A failure is counted and logged without any event or user data and never escapes."""
    try:
        return await asyncio.to_thread(service.process_outbox)
    except Exception as error:  # noqa: BLE001 - the loop must survive a database outage
        log.warning('outbox pass failed: %s', type(error).__name__)
        return {'created': 0, 'failed': 0, 'error': True}


async def run_reminders(service) -> dict:
    """Same contract as run_once: a failure is counted and never escapes. Services without reminders are skipped."""
    method = getattr(service, 'enqueue_due_reminders', None)
    if method is None:
        return {'queued': 0}
    try:
        return await asyncio.to_thread(method)
    except Exception as error:  # noqa: BLE001
        log.warning('reminder pass failed: %s', type(error).__name__)
        return {'queued': 0, 'error': True}


async def outbox_loop(service, interval: int, stats: dict | None = None, reminder_every: int = REMINDER_EVERY):
    stats = stats if stats is not None else {}
    last_reminders = None
    while True:
        if last_reminders is None or time.monotonic() - last_reminders >= reminder_every:
            last_reminders = time.monotonic()
            reminded = await run_reminders(service)
            stats['reminders_queued'] = stats.get('reminders_queued', 0) + reminded['queued']
            stats['errors'] = stats.get('errors', 0) + (1 if reminded.get('error') else 0)
        result = await run_once(service)
        stats['passes'] = stats.get('passes', 0) + 1
        stats['created'] = stats.get('created', 0) + result['created']
        stats['errors'] = stats.get('errors', 0) + (1 if result.get('error') else 0)
        await asyncio.sleep(interval)
