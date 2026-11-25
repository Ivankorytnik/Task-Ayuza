"""WEB-MEMBERS-1: adding employees from the web UI. Synthetic data only, acceptance runner only."""
import uuid

import pytest

from backend.auth import argon2_slot, execute, insert_user, one, prepare_user
from backend.passwords import verify
from test_m01_auth import read_user, service  # noqa: F401  (pytest fixture)


def _org(service):
    with service.engine.connect() as c:
        return execute(c, 'SELECT id FROM task_ayuza.organization').scalar_one()


def test_prepare_user_validates_and_hashes_outside_transaction():
    prepared = prepare_user('  New_' + uuid.uuid4().hex[:8].upper() + ' ', 'Синтетический сотрудник')
    assert prepared['login'] == prepared['login'].strip().lower()
    assert len(prepared['password']) >= 24
    assert prepared['hash'] != prepared['password']
    with argon2_slot():
        assert verify(prepared['hash'], prepared['password'])
    for login, name in (('ab', 'Имя'), ('valid_login', '  '), ('valid_login', 'x' * 201)):
        with pytest.raises(ValueError):
            prepare_user(login, name)


def test_insert_user_sets_temporary_password_state(service):
    prepared = prepare_user('ins_' + uuid.uuid4().hex, 'Synthetic')
    uid = uuid.uuid4()
    service.transaction(lambda c: insert_user(c, _org(service), uid, prepared))
    row = read_user(service, uid)
    assert row['login_normalized'] == prepared['login']
    assert row['must_change_password'] is True and row['temporary_expires_at'] is not None
    with service.engine.connect() as c:
        hours = execute(c, '''SELECT extract(epoch FROM temporary_expires_at - clock_timestamp())/3600
            FROM task_ayuza.users WHERE id=:id''', id=uid).scalar_one()
    assert 23.9 < float(hours) <= 24


def test_create_user_still_audits_as_system(service):
    uid, _ = service.create_user(_org(service), 'cli_' + uuid.uuid4().hex, 'Synthetic')
    with service.engine.connect() as c:
        ev = one(c, '''SELECT actor_kind, actor_id FROM task_ayuza.audit_events
            WHERE entity_id=:id AND action='auth.user_created' ''', id=uid)
    assert ev['actor_kind'] == 'system' and ev['actor_id'] is None
