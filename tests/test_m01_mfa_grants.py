"""M01.4 tests: TOTP MFA, administrative grants (D03), system roles, one-time setup.

Disposable loopback PostgreSQL only, synthetic data only (run by tests/run_m01_acceptance.py).
"""
import base64
import os
import time
import uuid

import pytest
from sqlalchemy.exc import DBAPIError

from backend.acl import AclError, AclService
from backend.auth import AuthError, execute
from backend.grants import GrantService
from backend.mfa import MfaService, hotp
from backend.setup import SetupError, complete_setup
from test_m01_acl import (Who, acl, admin_sql, make_workspace_admin, migrator, person, rows, status,  # noqa: F401
                          violates)
from test_m01_auth import service  # noqa: F401


@pytest.fixture(scope='module')
def mfa(service):
    return MfaService(service, bytes.fromhex(os.environ['TASK_AYUZA_MFA_KEY']))


@pytest.fixture(scope='module')
def grants(service):
    return GrantService(service)


def code(secret_b32, offset=0):
    secret = base64.b32decode(secret_b32)
    return hotp(secret, int(time.time() // 30) + offset)


def with_mfa(service, mfa):
    """Synthetic user with MFA enabled and a verified session. Returns (Who, secret, backup codes)."""
    who = person(service)
    enrolled = mfa.enroll(who.token, who.csrf)
    mfa.confirm(who.token, who.csrf, code(enrolled['secret']))
    return who, enrolled['secret'], enrolled['backup_codes']


def fail_status(call):
    with pytest.raises(AuthError) as error:
        call()
    return error.value.status


def make_owner_and_approvers(service, mfa, migrator):
    owner, _, _ = with_mfa(service, mfa)
    a1, _, _ = with_mfa(service, mfa)
    a2, _, _ = with_mfa(service, mfa)
    return owner, a1, a2


def set_roles(migrator, owner, approvers):
    with migrator.begin() as c:
        complete_setup(c, owner.id, [a.id for a in approvers])


def test_b01_totp_enroll_confirm_verify_replay_and_secret_storage(service, mfa, migrator):
    who = person(service)
    enrolled = mfa.enroll(who.token, who.csrf)
    stored = rows(migrator, 'SELECT encrypted_secret, enabled_at FROM task_ayuza.user_mfa WHERE user_id=:u', u=who.id)[0]
    assert stored['enabled_at'] is None
    assert base64.b32decode(enrolled['secret']) not in bytes(stored['encrypted_secret'])
    assert len(enrolled['backup_codes']) == 10
    assert 'otpauth://totp/' in enrolled['otpauth_uri']
    good = code(enrolled['secret'])
    assert fail_status(lambda: mfa.confirm(who.token, who.csrf, '000000' if good != '000000' else '111111')) == 403
    assert mfa.confirm(who.token, who.csrf, good) is True
    assert fail_status(lambda: mfa.enroll(who.token, who.csrf)) == 409
    # the same step cannot be used twice (replay)
    assert fail_status(lambda: mfa.verify(who.token, who.csrf, good)) == 403
    session = rows(migrator, 'SELECT mfa_verified_at FROM task_ayuza.sessions WHERE user_id=:u', u=who.id)
    assert any(r['mfa_verified_at'] is not None for r in session)
    actions = {r['action'] for r in rows(migrator, "SELECT action FROM task_ayuza.audit_events WHERE actor_id=:u", u=who.id)}
    assert {'mfa.enrolled', 'mfa.enabled', 'mfa.verify_failed'} <= actions
    assert enrolled['secret'] not in repr(rows(migrator, 'SELECT "old","new" FROM task_ayuza.audit_events'))


def test_b02_lockout_and_backup_codes(service, mfa, migrator):
    who, secret, backups = with_mfa(service, mfa)
    for _ in range(5):
        assert fail_status(lambda: mfa.verify(who.token, who.csrf, '123456')) == 403
    # locked: even a valid backup code is refused until the lock expires
    assert fail_status(lambda: mfa.verify(who.token, who.csrf, backups[0])) == 429
    admin_sql(migrator, 'UPDATE task_ayuza.user_mfa SET locked_until = clock_timestamp() - interval \'1 minute\' WHERE user_id=:u', u=who.id)
    assert mfa.verify(who.token, who.csrf, backups[0]) is True
    assert fail_status(lambda: mfa.verify(who.token, who.csrf, backups[0])) == 403  # single use
    stored = rows(migrator, 'SELECT code_hash FROM task_ayuza.mfa_backup_codes WHERE user_id=:u', u=who.id)
    assert len(stored) == 10 and all(len(bytes(r['code_hash'])) == 32 for r in stored)
    assert not any(backups[0].encode() in bytes(r['code_hash']) for r in stored)


def test_b03_unauthenticated_and_csrf(service, mfa):
    who = person(service)
    assert fail_status(lambda: mfa.enroll('x' * 43, who.csrf)) == 401
    assert fail_status(lambda: mfa.enroll(who.token, 'wrong')) in (401, 403)


def test_b04_admin_mutation_requires_fresh_mfa(service, mfa, acl, migrator):
    admin = person(service)
    other = person(service)
    from test_m01_acl import make_sysadmin
    sysadmin = person(service)
    make_sysadmin(migrator, sysadmin)
    ws = acl.create_workspace(sysadmin.token, sysadmin.csrf, 'Synthetic MFA W', 'Europe/Moscow')['id']
    make_workspace_admin(migrator, ws, admin)
    # make_workspace_admin marks MFA as fixture; clear it to test the guard itself
    admin_sql(migrator, 'UPDATE task_ayuza.sessions SET mfa_verified_at = NULL WHERE user_id=:u', u=admin.id)
    assert status(lambda: acl.set_workspace_member(admin.token, admin.csrf, ws, other.id, 'participant')) == 403
    admin_sql(migrator, "UPDATE task_ayuza.sessions SET mfa_verified_at = clock_timestamp() - interval '16 minutes' WHERE user_id=:u", u=admin.id)
    assert status(lambda: acl.set_workspace_member(admin.token, admin.csrf, ws, other.id, 'participant')) == 403
    admin_sql(migrator, 'UPDATE task_ayuza.sessions SET mfa_verified_at = clock_timestamp() WHERE user_id=:u', u=admin.id)
    assert acl.set_workspace_member(admin.token, admin.csrf, ws, other.id, 'participant')['id']


def test_b05_setup_once_closed_and_audited(service, mfa, migrator):
    owner, a1, a2 = make_owner_and_approvers(service, mfa, migrator)
    no_mfa = person(service)
    with migrator.begin() as c:
        with pytest.raises(SetupError):
            complete_setup(c, owner.id, [owner.id])  # owner is not a different approver
    with migrator.begin() as c:
        with pytest.raises(SetupError):
            complete_setup(c, owner.id, [no_mfa.id])  # approver without MFA
    # the real setup may already have run in an earlier test of this module: both outcomes keep one setup
    state = rows(migrator, 'SELECT completed_at FROM task_ayuza.setup_state')
    if not state:
        set_roles(migrator, owner, [a1, a2])
        state = rows(migrator, 'SELECT completed_at FROM task_ayuza.setup_state')
    assert len(state) == 1 and state[0]['completed_at'] is not None
    with migrator.begin() as c:
        with pytest.raises(SetupError):
            complete_setup(c, owner.id, [a1.id, a2.id])
    kinds = {r['action'] for r in rows(migrator, "SELECT action FROM task_ayuza.audit_events WHERE actor_kind='system'")}
    assert {'setup.role_assigned', 'setup.completed'} <= kinds
    violates(service.engine, "INSERT INTO task_ayuza.setup_state (singleton) VALUES (true)", '42501')


def _roles(migrator, role):
    return {r['user_id'] for r in rows(migrator, 'SELECT user_id FROM task_ayuza.system_role_assignments WHERE role_code=:r AND revoked_at IS NULL', r=role)}


def test_b06_grant_lifecycle_expiry_and_mfa(service, mfa, grants, acl, migrator):
    owner, a1, a2 = make_owner_and_approvers(service, mfa, migrator)
    with migrator.begin() as c:
        execute(c, 'DELETE FROM task_ayuza.setup_state')
        execute(c, "DELETE FROM task_ayuza.system_role_assignments WHERE role_code IN ('system_owner','access_approver')")
    set_roles(migrator, owner, [a1, a2])
    from test_m01_acl import make_sysadmin
    sysadmin = person(service)
    make_sysadmin(migrator, sysadmin)
    ws = acl.create_workspace(sysadmin.token, sysadmin.csrf, 'Synthetic Grant W', 'Europe/Moscow')['id']
    grantee, _, _ = with_mfa(service, mfa)
    plain = person(service)  # no MFA enabled
    # outside any membership: no access, and hidden (404)
    assert status(lambda: acl.run_protected(grantee.token, ws, 'read', lambda c, u, s: 'ok')) == 404
    # D03: a non-approver cannot issue; the grantee cannot approve themself; MFA on grantee required
    assert status(lambda: grants.issue_grant(sysadmin.token, sysadmin.csrf, ws, grantee.id, 'read', 'standard', 60, 'synthetic')) == 403
    assert status(lambda: grants.issue_grant(a1.token, a1.csrf, ws, a1.id, 'read', 'standard', 60, 'self')) == 403
    assert status(lambda: grants.issue_grant(a1.token, a1.csrf, ws, plain.id, 'read', 'standard', 60, 'no mfa')) == 422
    assert status(lambda: grants.issue_grant(a1.token, a1.csrf, ws, grantee.id, 'read', 'emergency', 121, 'too long')) == 422
    assert status(lambda: grants.issue_grant(a1.token, a1.csrf, ws, grantee.id, 'read', 'standard', 30 * 24 * 60 + 1, 'too long')) == 422
    assert status(lambda: grants.issue_grant(a1.token, a1.csrf, ws, grantee.id, 'root', 'standard', 5, 'bad cap')) == 422
    issued = grants.issue_grant(a1.token, a1.csrf, ws, grantee.id, 'read', 'emergency', 60, 'synthetic need')
    assert issued['created'] is True
    again = grants.issue_grant(a1.token, a1.csrf, ws, grantee.id, 'read', 'emergency', 60, 'synthetic need')
    assert again['created'] is False and again['id'] == issued['id']  # idempotent, no extra authority
    assert acl.run_protected(grantee.token, ws, 'read', lambda c, u, s: 'ok') == 'ok'
    # only the granted capability, only this workspace
    assert status(lambda: acl.run_protected(grantee.token, ws, 'content_edit', lambda c, u, s: 'ok')) == 404
    # a grant needs fresh MFA when used
    admin_sql(migrator, 'UPDATE task_ayuza.sessions SET mfa_verified_at = NULL WHERE user_id=:u', u=grantee.id)
    assert status(lambda: acl.run_protected(grantee.token, ws, 'read', lambda c, u, s: 'ok')) == 403
    admin_sql(migrator, 'UPDATE task_ayuza.sessions SET mfa_verified_at = clock_timestamp() WHERE user_id=:u', u=grantee.id)
    assert acl.run_protected(grantee.token, ws, 'read', lambda c, u, s: 'ok') == 'ok'
    # expiry: the database clock decides
    admin_sql(migrator, "UPDATE task_ayuza.administrative_grants SET valid_from = valid_from - interval '90 minutes', expires_at = clock_timestamp() - interval '1 minute' WHERE id=:id", id=issued['id'])
    assert status(lambda: acl.run_protected(grantee.token, ws, 'read', lambda c, u, s: 'ok')) == 404
    # a new approval is a new grant; revocation takes effect at once and is idempotent
    second = grants.issue_grant(a2.token, a2.csrf, ws, grantee.id, 'read', 'standard', 24 * 60, 'renewed need')
    assert second['created'] is True and second['id'] != issued['id']
    assert acl.run_protected(grantee.token, ws, 'read', lambda c, u, s: 'ok') == 'ok'
    assert status(lambda: grants.revoke_grant(a1.token, a1.csrf, second['id'], second['version'] + 5)) == 409
    revoked = grants.revoke_grant(a1.token, a1.csrf, second['id'], second['version'])
    assert revoked['revoked'] is True
    assert grants.revoke_grant(a1.token, a1.csrf, second['id'], 1)['revoked'] is True
    assert status(lambda: acl.run_protected(grantee.token, ws, 'read', lambda c, u, s: 'ok')) == 404
    assert status(lambda: grants.revoke_grant(sysadmin.token, sysadmin.csrf, second['id'], 1)) == 403
    actions = {r['action'] for r in rows(migrator, 'SELECT action FROM task_ayuza.audit_events WHERE workspace_id=:w', w=ws)}
    assert {'grant.issued', 'grant.revoked'} <= actions
    assert 'synthetic need' not in repr(rows(migrator, 'SELECT "old","new" FROM task_ayuza.audit_events'))


def test_b07_grant_constraints_in_postgres(service, mfa, migrator):
    owner, a1, a2 = make_owner_and_approvers(service, mfa, migrator)
    ins = '''INSERT INTO task_ayuza.administrative_grants
        (id, grantee_user_id, workspace_id, capability, kind, approver_user_id, reason, valid_from, expires_at)
        SELECT gen_random_uuid(), :g, w.id, :cap, :kind, :by, 'synthetic', clock_timestamp(),
               clock_timestamp() + CAST(:term AS interval) FROM task_ayuza.workspaces w LIMIT 1'''
    admin_sql(migrator, "INSERT INTO task_ayuza.workspaces (id, organization_id, name, timezone) SELECT gen_random_uuid(), id, 'Synthetic B07', 'UTC' FROM task_ayuza.organization LIMIT 1")
    violates(migrator, ins, '23514', g=a1.id, cap='read', kind='standard', by=a1.id, term='1 hour')       # self approval
    violates(migrator, ins, '23514', g=a1.id, cap='read', kind='standard', by=a2.id, term='31 days')      # too long
    violates(migrator, ins, '23514', g=a1.id, cap='read', kind='emergency', by=a2.id, term='3 hours')     # too long
    violates(migrator, ins, '23514', g=a1.id, cap='root', kind='standard', by=a2.id, term='1 hour')       # unknown capability
    for table in ('user_mfa', 'mfa_backup_codes', 'administrative_grants', 'setup_state'):
        violates(service.engine, f'TRUNCATE task_ayuza.{table}', '42501')
        violates(service.engine, f'DELETE FROM task_ayuza.{table} WHERE false', '42501')


def test_b08_system_roles_owner_only_and_two_approvers(service, mfa, grants, migrator):
    owner, a1, a2 = make_owner_and_approvers(service, mfa, migrator)
    with migrator.begin() as c:
        execute(c, 'DELETE FROM task_ayuza.setup_state')
        execute(c, "DELETE FROM task_ayuza.system_role_assignments WHERE role_code IN ('system_owner','access_approver')")
    set_roles(migrator, owner, [a1, a2])
    target = person(service)
    assert status(lambda: grants.grant_system_role(a1.token, a1.csrf, target.id, 'system_admin', 'synthetic')) == 403
    assert status(lambda: grants.grant_system_role(owner.token, owner.csrf, owner.id, 'system_admin', 'self')) == 403
    assert status(lambda: grants.grant_system_role(owner.token, owner.csrf, target.id, 'system_owner', 'no')) == 422
    granted = grants.grant_system_role(owner.token, owner.csrf, target.id, 'system_admin', 'synthetic')
    assert granted['created'] is True
    assert grants.grant_system_role(owner.token, owner.csrf, target.id, 'system_admin', 'synthetic')['created'] is False
    revoked = grants.revoke_system_role(owner.token, owner.csrf, target.id, 'system_admin', granted['version'])
    assert revoked['revoked'] is True
    # the approver floor: owner + two approvers exist, dropping to one other approver is refused
    first = [r for r in rows(migrator, "SELECT version FROM task_ayuza.system_role_assignments WHERE user_id=:u AND role_code='access_approver'", u=a1.id)][0]
    assert grants.revoke_system_role(owner.token, owner.csrf, a1.id, 'access_approver', first['version'])['revoked'] is True
    second = [r for r in rows(migrator, "SELECT version FROM task_ayuza.system_role_assignments WHERE user_id=:u AND role_code='access_approver'", u=a2.id)][0]
    assert status(lambda: grants.revoke_system_role(owner.token, owner.csrf, a2.id, 'access_approver', second['version'])) == 409


def test_b09_bootstrap_first_workspace_admin(service, mfa, grants, acl, migrator):
    """Owner decision 24.11.2026: a system_owner with fresh MFA appoints the first workspace_admin."""
    owner, _, _ = with_mfa(service, mfa)
    admin_sql(migrator, '''INSERT INTO task_ayuza.system_role_assignments (id, user_id, role_code, reason)
        VALUES (:id, :u, 'system_owner', 'synthetic bootstrap')''', id=uuid.uuid4(), u=owner.id)
    sysadmin, _, _ = with_mfa(service, mfa)
    admin_sql(migrator, '''INSERT INTO task_ayuza.system_role_assignments (id, user_id, role_code, reason)
        VALUES (:id, :u, 'system_admin', 'synthetic bootstrap')''', id=uuid.uuid4(), u=sysadmin.id)
    ws = acl.create_workspace(sysadmin.token, sysadmin.csrf, 'Bootstrap W', 'Europe/Moscow')['id']
    first, second, outsider = person(service), person(service), person(service)
    bootstrap = lambda who, target, w=ws: grants.bootstrap_workspace_admin(who.token, who.csrf, w, target.id)
    # Not an owner (even a system admin), self-appointment, unknown workspace: refused, nothing written.
    assert status(lambda: bootstrap(sysadmin, first)) == 403
    assert status(lambda: bootstrap(owner, owner)) == 403
    assert status(lambda: bootstrap(owner, first, str(uuid.uuid4()))) == 404
    admin_sql(migrator, 'UPDATE task_ayuza.sessions SET mfa_verified_at = NULL WHERE user_id=:u', u=owner.id)
    assert status(lambda: bootstrap(owner, first)) == 403          # MFA is not fresh
    assert rows(migrator, 'SELECT 1 FROM task_ayuza.workspace_members WHERE workspace_id=:w', w=ws) == []
    # A participant is promoted; the change is audited with the owner as actor.
    admin_sql(migrator, 'UPDATE task_ayuza.sessions SET mfa_verified_at = clock_timestamp() WHERE user_id=:u', u=owner.id)
    admin_sql(migrator, '''INSERT INTO task_ayuza.workspace_members (id, workspace_id, user_id, role)
        VALUES (:id, :w, :u, 'participant')''', id=uuid.uuid4(), w=ws, u=first.id)
    result = bootstrap(owner, first)
    assert result['created'] is False
    member = rows(migrator, 'SELECT role, active FROM task_ayuza.workspace_members WHERE workspace_id=:w AND user_id=:u',
                  w=ws, u=first.id)
    assert member == [{'role': 'workspace_admin', 'active': True}]
    events = rows(migrator, '''SELECT actor_id, action, workspace_id FROM task_ayuza.audit_events
        WHERE entity_id=:e ORDER BY occurred_at''', e=result['id'])
    assert events[-1] == {'actor_id': owner.id, 'action': 'acl.workspace_member_changed', 'workspace_id': ws}
    # Once the workspace has an administrator, the owner can no longer add one: the admin does.
    assert status(lambda: bootstrap(owner, second)) == 409
    # The new administrator manages members through the normal path (needs their own fresh MFA).
    admin_sql(migrator, 'UPDATE task_ayuza.sessions SET mfa_verified_at = clock_timestamp() WHERE user_id=:u', u=first.id)
    acl.set_workspace_member(first.token, first.csrf, ws, second.id, 'participant')
    assert status(lambda: acl.set_workspace_member(outsider.token, outsider.csrf, ws, outsider.id, 'participant')) in (403, 404)
    # An inactive target is refused in a workspace that has no administrator yet.
    ws2 = acl.create_workspace(sysadmin.token, sysadmin.csrf, 'Bootstrap W2', 'Europe/Moscow')['id']
    service.deactivate(outsider.id)
    assert status(lambda: bootstrap(owner, outsider, ws2)) == 422


def test_b10_bootstrap_workspace_admin_concurrent_once(service, mfa, grants, acl, migrator):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    # Two different owners: their own user/session locks do not serialize them, only the workspace lock does.
    owners = [with_mfa(service, mfa)[0] for _ in range(2)]
    for owner in owners:
        admin_sql(migrator, '''INSERT INTO task_ayuza.system_role_assignments (id, user_id, role_code, reason)
            VALUES (:id, :u, 'system_owner', 'synthetic bootstrap')''', id=uuid.uuid4(), u=owner.id)
    sysadmin, _, _ = with_mfa(service, mfa)
    admin_sql(migrator, '''INSERT INTO task_ayuza.system_role_assignments (id, user_id, role_code, reason)
        VALUES (:id, :u, 'system_admin', 'synthetic bootstrap')''', id=uuid.uuid4(), u=sysadmin.id)
    ws = acl.create_workspace(sysadmin.token, sysadmin.csrf, 'Bootstrap race', 'Europe/Moscow')['id']
    targets = [person(service), person(service)]
    barrier = Barrier(2)

    def attempt(pair):
        owner, target = pair
        barrier.wait(10)
        try:
            return grants.bootstrap_workspace_admin(owner.token, owner.csrf, ws, target.id)
        except AclError as error:
            return error.status
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, zip(owners, targets)))
    assert sorted(str(r) if isinstance(r, int) else 'ok' for r in results) == ['409', 'ok']
    assert len(rows(migrator, '''SELECT 1 FROM task_ayuza.workspace_members
        WHERE workspace_id=:w AND role='workspace_admin' AND active''', w=ws)) == 1
