"""In-process background loops. No external scheduler: one loop per app instance; the work itself is safe to run
concurrently from several instances (SKIP LOCKED) and to repeat (dedupe keys)."""
import asyncio
import logging
import os

from backend.config import ConfigurationError

log = logging.getLogger('task_ayuza.scheduler')
DEFAULT_INTERVAL = 30
MAX_INTERVAL = 3600


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


async def outbox_loop(service, interval: int, stats: dict | None = None):
    stats = stats if stats is not None else {}
    while True:
        result = await run_once(service)
        stats['passes'] = stats.get('passes', 0) + 1
        stats['created'] = stats.get('created', 0) + result['created']
        stats['errors'] = stats.get('errors', 0) + (1 if result.get('error') else 0)
        await asyncio.sleep(interval)
