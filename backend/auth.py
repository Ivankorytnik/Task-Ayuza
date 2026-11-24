"""Transactional authentication. Internal provisioning/reset functions are not HTTP APIs.

All authenticated operations lock user then session until commit, including the
protected callback. Limiter reservation commits separately before costly Argon2.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
import uuid
from contextlib import contextmanager
from datetime import timedelta
from typing import Callable

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from backend.passwords import (GATE, Argon2Busy, hash_password, normalize_login, temporary_password,
                               validate_password, verify)


class AuthError(Exception):
    def __init__(self, status=401, message='Authentication failed'):
        self.status = status
        self.message = message
        super().__init__(message)


def digest(value: str) -> bytes:
    return hashlib.sha256(value.encode('utf-8')).digest()


def execute(c, sql, **params):
    return c.execute(text(sql), params)


def one(c, sql, **params):
    return execute(c, sql, **params).mappings().first()


def clock(c):
    # clock_timestamp, not transaction start time after waiting on a row lock.
    return execute(c, 'SELECT clock_timestamp()').scalar_one()


def limiter_address(ip) -> str:
    """Limiter identity of a client address. One IPv6 /64 is one client: a single host
    usually controls the whole /64, so per-address keys would let it rotate past 100/IP
    and 30/IP. IPv4-mapped IPv6 is the IPv4 client. Raises ValueError for non-addresses."""
    address = ipaddress.ip_address(ip)
    if address.version == 6:
        if address.ipv4_mapped:
            return str(address.ipv4_mapped)
        return str(ipaddress.IPv6Network((int(address) >> 64 << 64, 64)))
    return str(address)


AUTH_ACTIONS = frozenset({'user_created','password_reset','password_changed','deactivated',
                         'login_failed','login_limited','login','logout','renewed'})


def event(c, action, *, user_id=None, session_id=None, request_id):
    if action not in AUTH_ACTIONS:
        raise ValueError('Unsupported auth audit action')
    execute(c, '''INSERT INTO task_ayuza.audit_events
        (id, actor_kind, actor_id, session_id, entity_kind, entity_id, action, request_id)
        VALUES (:id, :actor_kind, :actor, :session, :kind, :entity, :action, :request)''',
        id=uuid.uuid4(), actor_kind='user' if user_id and action in {'login','logout','renewed','password_changed'} else 'system',
        actor=user_id if user_id and action in {'login','logout','renewed','password_changed'} else None,
        session=session_id, kind='user' if user_id else 'session',
        entity=user_id or session_id or uuid.uuid4(), action='auth.' + action, request=request_id)


@contextmanager
def argon2_slot():
    """Bounded wait for an Argon2id slot; taken before any limiter charge or row lock."""
    try:
        with GATE.slot():
            yield
    except Argon2Busy:
        raise AuthError(503, 'Authentication service busy') from None


class AuthService:
    def __init__(self, engine, hmac_key: bytes):
        if len(hmac_key) < 32:
            raise ValueError('Authentication key must contain at least 32 bytes')
        self.engine = engine
        self.hmac_key = hmac_key
        with argon2_slot():
            self.dummy_hash = hash_password(secrets.token_urlsafe(32))

    def transaction(self, operation: Callable):
        """At most two retries; rollback includes audit. No external side effects inside."""
        for attempt in range(3):
            try:
                with self.engine.begin() as c:
                    return operation(c)
            except DBAPIError as error:
                if getattr(error.orig, 'sqlstate', None) in {'40P01', '40001'} and attempt < 2:
                    continue
                raise AuthError(503, 'Authentication service unavailable') from None

    def key(self, namespace, value):
        return hmac.digest(self.hmac_key, (namespace + '\0' + value).encode(), 'sha256')

    def _limited_event(self, c, namespace, key, now, request_id):
        """Record at most one transactional audit event per HMAC key per 15m."""
        emitted = execute(c, """
            INSERT INTO task_ayuza.auth_limit_events (key_kind, key_hash, last_event_at)
            VALUES (:kind, :key, :now)
            ON CONFLICT (key_kind, key_hash) DO UPDATE SET last_event_at=EXCLUDED.last_event_at
              WHERE task_ayuza.auth_limit_events.last_event_at <= EXCLUDED.last_event_at - interval '15 minutes'
            RETURNING key_hash
        """, kind=namespace, key=key, now=now).first()
        if emitted:
            event(c, 'login_limited', request_id=request_id)

    def reserve(self, login, ip, request_id):
        login_key = self.key('login', login)
        ip_key = self.key('ip', limiter_address(ip))
        # Ordered transaction-scoped advisory locks serialize BOTH intersecting limits.
        # Truncated HMAC collisions only over-serialize; counts use full HMAC keys.
        locks = sorted({int.from_bytes(x[:8], 'big', signed=True) for x in (login_key, ip_key)})
        def operation(c):
            for key in locks:
                execute(c, 'SELECT pg_advisory_xact_lock(:key)', key=key)
            now = clock(c)
            counts = one(c, '''SELECT
                count(*) FILTER (WHERE login_key=:login) AS logins,
                count(*) FILTER (WHERE ip_key=:ip) AS ips
                FROM task_ayuza.login_attempts WHERE attempted_at > :cutoff
                AND (login_key=:login OR ip_key=:ip)''',
                login=login_key, ip=ip_key, cutoff=now-timedelta(minutes=15))
            if counts['logins'] >= 5 or counts['ips'] >= 100:
                if counts['logins'] >= 5:
                    self._limited_event(c, 'login', login_key, now, request_id)
                if counts['ips'] >= 100:
                    self._limited_event(c, 'ip', ip_key, now, request_id)
                return False
            execute(c, '''INSERT INTO task_ayuza.login_attempts
                (id,login_key,ip_key,attempted_at) VALUES (:id,:login,:ip,:now)''',
                id=uuid.uuid4(), login=login_key, ip=ip_key, now=now)
            return True
        if not self.transaction(operation):
            raise AuthError(429, 'Too many login attempts')

    def _session(self, c, *, user=None, kind='prelogin'):
        now = clock(c)
        absolute = now + (timedelta(hours=8) if kind == 'normal' else timedelta(minutes=10))
        if kind == 'password':
            absolute = min(absolute, user['temporary_expires_at'])
        if absolute <= now:
            raise AuthError()
        expires = min(absolute, now+timedelta(minutes=30))
        token, csrf, sid = secrets.token_urlsafe(32), secrets.token_urlsafe(32), uuid.uuid4()
        execute(c, '''INSERT INTO task_ayuza.sessions
            (id,user_id,token_hash,csrf_hash,kind,created_at,expires_at,absolute_expires_at,auth_version)
            VALUES (:id,:uid,:token,:csrf,:kind,:now,:expires,:absolute,:version)''',
            id=sid, uid=user['id'] if user else None, token=digest(token), csrf=digest(csrf),
            kind=kind, now=now, expires=expires, absolute=absolute,
            version=user['auth_version'] if user else None)
        return {'token': token, 'csrf_token': csrf, 'session_id': sid, 'kind': kind}

    def prelogin(self, ip=None, token=None):
        """Bootstrap with bounded anonymous issuance and authenticated CSRF recovery."""
        if ip is None:
            raise AuthError(503, 'Authentication service unavailable')
        try:
            ip_key = self.key('prelogin-ip', limiter_address(ip))
        except ValueError:
            raise AuthError(503, 'Authentication service unavailable') from None

        def operation(c):
            if token:
                try:
                    ref = self._lookup(c, token)
                    if ref['user_id']:
                        u = self._locked_user(c, ref['user_id'])
                        s = self._locked_session(c, ref['id'])
                        now = clock(c)
                        if (u and u['active'] and u['auth_version'] == s['auth_version']
                            and ((s['kind'] == 'normal' and not u['must_change_password'])
                              or (s['kind'] == 'password' and u['must_change_password']
                                  and u['temporary_expires_at'] > now))):
                            return self._bootstrap_existing(c, s, token)
                    else:
                        s = self._locked_session(c, ref['id'])
                        if s['kind'] == 'prelogin':
                            return self._bootstrap_existing(c, s, token)
                except AuthError:
                    pass
            lock_key = int.from_bytes(ip_key[:8], 'big', signed=True)
            execute(c, 'SELECT pg_advisory_xact_lock(:key)', key=lock_key)
            now = clock(c)
            issued = execute(c, """
                INSERT INTO task_ayuza.prelogin_limits (ip_key, window_start, issued_count, updated_at)
                VALUES (:ip, :now, 1, :now)
                ON CONFLICT (ip_key) DO UPDATE SET
                  window_start = CASE WHEN task_ayuza.prelogin_limits.window_start <= :now - interval '15 minutes'
                    THEN :now ELSE task_ayuza.prelogin_limits.window_start END,
                  issued_count = CASE WHEN task_ayuza.prelogin_limits.window_start <= :now - interval '15 minutes'
                    THEN 1 ELSE task_ayuza.prelogin_limits.issued_count + 1 END,
                  updated_at = :now
                WHERE task_ayuza.prelogin_limits.window_start <= :now - interval '15 minutes'
                   OR task_ayuza.prelogin_limits.issued_count < 30
                RETURNING issued_count
            """, ip=ip_key, now=now).first()
            if not issued:
                raise AuthError(429, 'Too many bootstrap requests')
            return self._session(c)
        return self.transaction(operation)

    def _bootstrap_existing(self, c, s, token):
        # Rotate CSRF while preserving session ID, token and absolute/idle expiry.
        csrf = secrets.token_urlsafe(32)
        execute(c, 'UPDATE task_ayuza.sessions SET csrf_hash=:hash WHERE id=:id',
                hash=digest(csrf), id=s['id'])
        return {'token': token, 'csrf_token': csrf, 'session_id': s['id'], 'kind': s['kind']}

    def _lookup(self, c, token):
        if not token or len(token) != 43:
            raise AuthError()
        row = one(c, 'SELECT id,user_id FROM task_ayuza.sessions WHERE token_hash=:hash', hash=digest(token))
        if row is None:
            raise AuthError()
        return row

    def _locked_session(self, c, sid, csrf=None):
        s = one(c, 'SELECT * FROM task_ayuza.sessions WHERE id=:id FOR UPDATE', id=sid)
        now = clock(c)
        if s is None or s['revoked_at'] or s['expires_at'] <= now or s['absolute_expires_at'] <= now:
            raise AuthError()
        if csrf is not None and (len(csrf) != 43 or not hmac.compare_digest(digest(csrf), s['csrf_hash'])):
            raise AuthError(403, 'Request verification failed')
        return s

    def _locked_user(self, c, uid):
        return one(c, 'SELECT * FROM task_ayuza.users WHERE id=:id FOR UPDATE', id=uid)

    def _authorized(self, c, token, csrf=None, allow_password=False):
        ref = self._lookup(c, token)
        if not ref['user_id']:
            raise AuthError()
        u = self._locked_user(c, ref['user_id'])
        s = self._locked_session(c, ref['id'], csrf)
        if not u or not u['active'] or s['auth_version'] != u['auth_version']:
            raise AuthError()
        if s['kind'] == 'password':
            if not allow_password or not u['must_change_password'] or u['temporary_expires_at'] <= clock(c):
                raise AuthError(403, 'Password change required')
        elif s['kind'] != 'normal' or u['must_change_password']:
            raise AuthError()
        return u, s

    def login(self, login, password, ip, token, csrf, request_id=None):
        request_id = request_id or uuid.uuid4()
        if not csrf:
            raise AuthError(403, "Request verification failed")
        # Verify prelogin CSRF before charging an attempt; recheck under lock later.
        def precheck(c):
            ref = self._lookup(c, token)
            s = self._locked_session(c, ref['id'], csrf)
            if s['kind'] != 'prelogin':
                raise AuthError()
        self.transaction(precheck)
        try:
            normalized = normalize_login(login)
            valid_login = True
        except ValueError:
            # Invalid syntax has no account but still uses the same stable key pipeline.
            normalized = login.strip().lower()
            valid_login = False
        def operation(c):
            u = one(c, 'SELECT * FROM task_ayuza.users WHERE login_normalized=:login FOR UPDATE', login=normalized) if valid_login else None
            ref = self._lookup(c, token)
            s = self._locked_session(c, ref['id'], csrf)
            if s['kind'] != 'prelogin':
                raise AuthError()
            valid = verify(u['password_hash'] if u else self.dummy_hash, password)
            if (not valid or not u or not u['active'] or
                (u['must_change_password'] and u['temporary_expires_at'] <= clock(c))):
                event(c, 'login_failed', user_id=u['id'] if u else None, session_id=s['id'], request_id=request_id)
                return None
            execute(c, 'DELETE FROM task_ayuza.sessions WHERE id=:id', id=s['id'])
            result = self._session(c, user=u, kind='password' if u['must_change_password'] else 'normal')
            event(c, 'login', user_id=u['id'], session_id=result['session_id'], request_id=request_id)
            return result
        # A busy gate answers 503 before an attempt is charged.
        with argon2_slot():
            self.reserve(normalized, ip, request_id)
            result = self.transaction(operation)
        if result is None:
            raise AuthError()
        return result

    def protected(self, token, operation, *, csrf=None, mutation=False):
        if mutation and not csrf:
            raise AuthError(403, 'Request verification failed')
        def run(c):
            u, s = self._authorized(c, token, csrf)
            return operation(c, u, s)
        return self.transaction(run)

    def me(self, token):
        return self.protected(token, lambda c,u,s: {'id':str(u['id']), 'display_name':u['display_name']})

    def renew(self, token, csrf, request_id=None):
        if not csrf:
            raise AuthError(403, 'Request verification failed')
        def run(c):
            u,s = self._authorized(c, token, csrf)
            expires = min(clock(c)+timedelta(minutes=30), s['absolute_expires_at'])
            execute(c, 'UPDATE task_ayuza.sessions SET expires_at=:expires WHERE id=:id', expires=expires, id=s['id'])
            event(c, 'renewed', user_id=u['id'], session_id=s['id'], request_id=request_id or uuid.uuid4())
        self.transaction(run)

    def logout(self, token, csrf, request_id=None):
        if not csrf:
            raise AuthError(403, 'Request verification failed')
        def run(c):
            u,s = self._authorized(c, token, csrf, allow_password=True)
            execute(c, 'UPDATE task_ayuza.sessions SET revoked_at=clock_timestamp() WHERE id=:id', id=s['id'])
            event(c, 'logout', user_id=u['id'], session_id=s['id'], request_id=request_id or uuid.uuid4())
        self.transaction(run)

    def _revoke(self, c, uid):
        # User already locked: serializes every auth operation before session writes.
        execute(c, 'UPDATE task_ayuza.users SET auth_version=auth_version+1 WHERE id=:id', id=uid)
        execute(c, 'UPDATE task_ayuza.sessions SET revoked_at=clock_timestamp() WHERE user_id=:id AND revoked_at IS NULL', id=uid)

    def change_password(self, token, csrf, new_password, current_password=None, request_id=None):
        if not csrf:
            raise AuthError(403, 'Request verification failed')
        validate_password(new_password)
        def run(c):
            u,s = self._authorized(c, token, csrf, allow_password=True)
            if s['kind'] == 'normal' and (current_password is None or not verify(u['password_hash'], current_password)):
                raise AuthError()
            encoded = hash_password(new_password)
            execute(c, '''UPDATE task_ayuza.users SET password_hash=:hash,
                must_change_password=false,temporary_expires_at=NULL WHERE id=:id''', hash=encoded,id=u['id'])
            self._revoke(c,u['id'])
            event(c,'password_changed',user_id=u['id'],session_id=s['id'],request_id=request_id or uuid.uuid4())
        with argon2_slot():
            self.transaction(run)

    def create_user(self, organization_id, login, display_name, request_id=None):
        """Closed service function. Caller authorization belongs to M01.4, no HTTP route."""
        normalized = normalize_login(login)
        if not display_name.strip() or len(display_name)>200:
            raise ValueError('Invalid display name')
        password = temporary_password()
        with argon2_slot():
            encoded = hash_password(password)
        uid = uuid.uuid4()
        def run(c):
            execute(c, '''INSERT INTO task_ayuza.users
                (id,organization_id,login,login_normalized,display_name,password_hash,temporary_expires_at)
                VALUES (:id,:org,:login,:login,:display,:hash,clock_timestamp()+interval '24 hours')''',
                id=uid,org=organization_id,login=normalized,display=display_name,hash=encoded)
            event(c,'user_created',user_id=uid,request_id=request_id or uuid.uuid4())
        self.transaction(run)
        return uid, password

    def reset_password(self, uid, request_id=None):
        password = temporary_password()
        with argon2_slot():
            encoded = hash_password(password)
        def run(c):
            if not self._locked_user(c,uid):
                raise AuthError()
            execute(c, '''UPDATE task_ayuza.users SET password_hash=:hash,
                must_change_password=true,temporary_expires_at=clock_timestamp()+interval '24 hours' WHERE id=:id''',hash=encoded,id=uid)
            self._revoke(c,uid)
            event(c,'password_reset',user_id=uid,request_id=request_id or uuid.uuid4())
        self.transaction(run)
        return password

    def deactivate(self, uid, request_id=None):
        def run(c):
            if not self._locked_user(c,uid):
                raise AuthError()
            execute(c,'UPDATE task_ayuza.users SET active=false WHERE id=:id',id=uid)
            self._revoke(c,uid)
            event(c,'deactivated',user_id=uid,request_id=request_id or uuid.uuid4())
        self.transaction(run)

    def cleanup(self):
        """Closed maintenance call: retain expired technical rows for 24h; never audit."""
        def run(c):
            execute(c,"DELETE FROM task_ayuza.login_attempts WHERE attempted_at <= clock_timestamp()-interval '24 hours 15 minutes'")
            execute(c,"DELETE FROM task_ayuza.prelogin_limits WHERE updated_at <= clock_timestamp()-interval '24 hours 15 minutes'")
            execute(c,"DELETE FROM task_ayuza.auth_limit_events WHERE last_event_at <= clock_timestamp()-interval '24 hours 15 minutes'")
            # Cleanup only locks sessions, never subsequently takes a user lock.
            execute(c,"DELETE FROM task_ayuza.sessions WHERE LEAST(expires_at,COALESCE(revoked_at,expires_at)) <= clock_timestamp()-interval '24 hours'")
        self.transaction(run)
