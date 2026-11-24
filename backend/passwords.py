"""Local password policy and fixed Argon2id parameters. Never log inputs."""
import re
import secrets
import threading
from contextlib import contextmanager
from pathlib import Path

from argon2 import PasswordHasher, Type
from argon2.exceptions import VerificationError, InvalidHashError

HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1,
                        salt_len=16, hash_len=32, type=Type.ID)
COMMON = frozenset(line.casefold() for filename in ('common_passwords.txt', 'common_passwords_10k.txt')
                   for line in Path(__file__).with_name(filename).read_text().splitlines())


class Argon2Busy(RuntimeError):
    """No Argon2id slot became free in time; callers answer 503 without side effects."""


class Argon2Gate:
    """Process-wide cap on simultaneous Argon2id operations (each needs 64 MiB).

    Peak Argon2 memory of one worker process is limit x 64 MiB; of a deployment,
    workers x limit x 64 MiB. Parameters of Argon2id itself are never weakened.
    A slot is re-entrant within one thread, which runs only one operation at a time.
    """
    def __init__(self, limit=4, wait=1.0):
        self._local = threading.local()
        self.configure(limit, wait)

    def configure(self, limit, wait=1.0):
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 64 or not 0 <= wait <= 10:
            raise ValueError('Invalid Argon2 concurrency limit')
        self.limit, self.wait = limit, wait
        self._semaphore = threading.BoundedSemaphore(limit)

    def held(self):
        return getattr(self._local, 'held', False)

    @contextmanager
    def slot(self):
        if self.held():
            yield
            return
        semaphore = self._semaphore
        if not semaphore.acquire(timeout=self.wait):
            raise Argon2Busy()
        self._local.held = True
        try:
            yield
        finally:
            self._local.held = False
            semaphore.release()


GATE = Argon2Gate()


def _require_slot():
    if not GATE.held():
        raise RuntimeError('Argon2id operation outside the concurrency gate')


def hash_password(password: str) -> str:
    _require_slot()
    return HASHER.hash(password)


def normalize_login(value: str) -> str:
    trimmed = value.strip()
    if not re.fullmatch(r'[a-zA-Z0-9._-]{3,64}', trimmed, flags=re.ASCII):
        raise ValueError('Invalid login')
    return trimmed.lower()


def validate_password(value: str) -> None:
    if not 15 <= len(value) <= 128 or value.casefold() in COMMON:
        raise ValueError('Password does not satisfy policy')
    # Reject non-Unicode-scalar surrogate input; preserve all ordinary Unicode/spaces.
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        raise ValueError('Password does not satisfy policy') from None


def verify(encoded: str, password: str) -> bool:
    _require_slot()
    try:
        return HASHER.verify(encoded, password)
    except (VerificationError, InvalidHashError, UnicodeEncodeError):
        return False


def temporary_password() -> str:
    return secrets.token_urlsafe(18)  # exactly 24 base64url characters / 144 bits
