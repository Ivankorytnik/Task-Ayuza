"""Local password policy and fixed Argon2id parameters. Never log inputs."""
import re
import secrets
from pathlib import Path

from argon2 import PasswordHasher, Type
from argon2.exceptions import VerificationError, InvalidHashError

HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1,
                        salt_len=16, hash_len=32, type=Type.ID)
COMMON = frozenset(line.casefold() for filename in ('common_passwords.txt', 'common_passwords_10k.txt')
                   for line in Path(__file__).with_name(filename).read_text().splitlines())


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
    try:
        return HASHER.verify(encoded, password)
    except (VerificationError, InvalidHashError, UnicodeEncodeError):
        return False


def temporary_password() -> str:
    return secrets.token_urlsafe(18)  # exactly 24 base64url characters / 144 bits
