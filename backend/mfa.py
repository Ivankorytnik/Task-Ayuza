"""M01.4 TOTP (RFC 6238) with encrypted secrets, hashed backup codes and brute-force lockout.

The TOTP secret is encrypted with AES-256-GCM under a key that lives only in the server
environment (TASK_AYUZA_MFA_KEY), never in the database or the repository. A verified code marks
the current session (sessions.mfa_verified_at); administrative operations require a fresh mark.
Failed attempts are committed (not rolled back) so that the lockout cannot be bypassed.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import uuid
from datetime import timedelta
from urllib.parse import quote

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.auth import AuthError, AuthService, clock, execute, one
from backend.config import ConfigurationError

MFA_WINDOW = timedelta(minutes=15)   # how long a verification keeps administrative operations open
MAX_FAILURES = 5
LOCK_FOR = timedelta(minutes=15)
STEP_SECONDS = 30
BACKUP_CODE_COUNT = 10


def mfa_key_from_env() -> bytes:
    raw = os.environ.get('TASK_AYUZA_MFA_KEY', '')
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        raise ConfigurationError('MFA key is not configured correctly') from None
    if len(key) != 32:
        raise ConfigurationError('MFA key is not configured correctly')
    return key


def hotp(secret: bytes, counter: int) -> str:
    mac = hmac.new(secret, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack('>I', mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return f'{value % 1_000_000:06d}'


def encrypt_secret(key: bytes, user_id: uuid.UUID, secret: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, secret, user_id.bytes)


def decrypt_secret(key: bytes, user_id: uuid.UUID, blob: bytes) -> bytes:
    return AESGCM(key).decrypt(bytes(blob[:12]), bytes(blob[12:]), user_id.bytes)


def mfa_fresh(c, session) -> bool:
    """True when this session passed MFA within MFA_WINDOW (database clock)."""
    verified = session['mfa_verified_at']
    return verified is not None and clock(c) - verified <= MFA_WINDOW


class MfaService:
    def __init__(self, auth: AuthService, key: bytes):
        if len(key) != 32:
            raise ValueError('MFA key must contain 32 bytes')
        self.auth = auth
        self.key = key

    def _backup_hash(self, code: str) -> bytes:
        return hmac.digest(self.key, b'backup\0' + code.encode(), 'sha256')

    @staticmethod
    def _event(c, u, s, action, request_id):
        execute(c, '''INSERT INTO task_ayuza.audit_events
            (id, actor_kind, actor_id, session_id, entity_kind, entity_id, action, request_id)
            VALUES (:id, 'user', :actor, :session, 'mfa', :entity, :action, :request)''',
                id=uuid.uuid4(), actor=u['id'], session=s['id'], entity=u['id'], action=action, request=request_id)

    def enroll(self, token, csrf, request_id=None):
        """Start (or restart, while not yet enabled) enrollment. Secret and codes are shown once."""
        request_id = request_id or uuid.uuid4()

        def run(c, u, s):
            row = one(c, 'SELECT enabled_at FROM task_ayuza.user_mfa WHERE user_id=:u FOR UPDATE', u=u['id'])
            if row is not None and row['enabled_at'] is not None:
                raise AuthError(409, 'MFA is already enabled')
            secret = secrets.token_bytes(20)
            execute(c, '''INSERT INTO task_ayuza.user_mfa (user_id, encrypted_secret)
                VALUES (:u, :blob)
                ON CONFLICT (user_id) DO UPDATE SET encrypted_secret = EXCLUDED.encrypted_secret,
                    last_used_step = NULL, failed_count = 0, locked_until = NULL,
                    version = task_ayuza.user_mfa.version + 1, updated_at = clock_timestamp()
                WHERE task_ayuza.user_mfa.enabled_at IS NULL''',
                    u=u['id'], blob=encrypt_secret(self.key, u['id'], secret))
            execute(c, '''UPDATE task_ayuza.mfa_backup_codes SET used_at = clock_timestamp()
                WHERE user_id=:u AND used_at IS NULL''', u=u['id'])
            codes = [f'{secrets.token_hex(3)}-{secrets.token_hex(2)}' for _ in range(BACKUP_CODE_COUNT)]
            for code in codes:
                execute(c, '''INSERT INTO task_ayuza.mfa_backup_codes (id, user_id, code_hash)
                    VALUES (:id, :u, :hash)''', id=uuid.uuid4(), u=u['id'], hash=self._backup_hash(code))
            self._event(c, u, s, 'mfa.enrolled', request_id)
            encoded = base64.b32encode(secret).decode()
            uri = (f"otpauth://totp/Task-Ayuza:{quote(u['login'])}?secret={encoded}"
                   f'&issuer=Task-Ayuza&algorithm=SHA1&digits=6&period={STEP_SECONDS}')
            return {'secret': encoded, 'otpauth_uri': uri, 'backup_codes': codes}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def confirm(self, token, csrf, code, request_id=None):
        """Finish enrollment with a code from the authenticator; also verifies this session."""
        return self._verify(token, csrf, code, confirming=True, request_id=request_id)

    def verify(self, token, csrf, code, request_id=None):
        """Verify TOTP or an unused backup code; marks the session for administrative operations."""
        return self._verify(token, csrf, code, confirming=False, request_id=request_id)

    def _verify(self, token, csrf, code, *, confirming, request_id):
        request_id = request_id or uuid.uuid4()
        normalized = code.strip().replace(' ', '').lower() if isinstance(code, str) else ''

        def run(c, u, s):
            row = one(c, 'SELECT * FROM task_ayuza.user_mfa WHERE user_id=:u FOR UPDATE', u=u['id'])
            if confirming and (row is None or row['enabled_at'] is not None):
                return ('error', 409, 'No pending MFA enrollment')
            if not confirming and (row is None or row['enabled_at'] is None):
                return ('error', 403, 'MFA is not enabled')
            now = clock(c)
            if row['locked_until'] is not None and row['locked_until'] > now:
                return ('error', 429, 'Too many verification attempts')
            step = None
            used_backup = False
            if len(normalized) == 6 and normalized.isdigit():
                secret = decrypt_secret(self.key, u['id'], row['encrypted_secret'])
                current = int(now.timestamp() // STEP_SECONDS)
                for candidate in (current - 1, current, current + 1):
                    if hmac.compare_digest(hotp(secret, candidate), normalized):
                        if row['last_used_step'] is None or candidate > row['last_used_step']:
                            step = candidate
                        break
            elif not confirming and len(normalized) == 11 and normalized[6] == '-':
                used = one(c, '''UPDATE task_ayuza.mfa_backup_codes SET used_at = clock_timestamp()
                    WHERE user_id=:u AND code_hash=:hash AND used_at IS NULL RETURNING id''',
                           u=u['id'], hash=self._backup_hash(normalized))
                used_backup = used is not None
            if step is not None or used_backup:
                execute(c, '''UPDATE task_ayuza.user_mfa SET failed_count = 0, locked_until = NULL,
                    last_used_step = COALESCE(:step, last_used_step),
                    enabled_at = COALESCE(enabled_at, clock_timestamp()),
                    version = version + 1, updated_at = clock_timestamp() WHERE user_id=:u''',
                        step=step, u=u['id'])
                execute(c, 'UPDATE task_ayuza.sessions SET mfa_verified_at = clock_timestamp() WHERE id=:id', id=s['id'])
                action = 'mfa.enabled' if confirming else ('mfa.backup_code_used' if used_backup else 'mfa.verified')
                self._event(c, u, s, action, request_id)
                return ('ok',)
            failures = row['failed_count'] + 1
            locked = failures >= MAX_FAILURES
            execute(c, '''UPDATE task_ayuza.user_mfa SET failed_count=:f, locked_until=:locked,
                version = version + 1, updated_at = clock_timestamp() WHERE user_id=:u''',
                    f=0 if locked else failures, locked=now + LOCK_FOR if locked else None, u=u['id'])
            self._event(c, u, s, 'mfa.verify_failed', request_id)
            return ('error', 403, 'Verification failed')

        outcome = self.auth.protected(token, run, csrf=csrf, mutation=True)
        if outcome[0] == 'error':  # raised after commit so counters and audit are kept
            raise AuthError(outcome[1], outcome[2])
        return True
