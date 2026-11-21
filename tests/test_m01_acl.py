"""M01.3 ACL integration tests: disposable loopback PostgreSQL only, synthetic data only.

Run by tests/run_m01_acceptance.py after the foundation and auth suites. Projects and tasks do
not exist yet, so project/task ACL checks (D02 matrix rows for objects) are deferred to M02 and
are not counted as passed here.
"""
import secrets
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import DBAPIError

import backend.acl as acl_module
from backend.acl import AclError, AclService
from backend.auth import AuthError, execute
from test_m01_auth import PASSWORD, service, user  # noqa: F401  (service: module-scoped runtime AuthService fixture)
from test_m01_foundation import _test_url


class Who:
    def __init__(self, uid, session):
        self.id = uid
        self.token = session['token']
        self.csrf = session['csrf_token']


class World:
    pass


@pytest.fixture(scope='module')
def migrator():
    engine = create_engine(_test_url('TASK_AYUZA_TEST_MIGRATOR_URL'), hide_parameters=True)
    with engine.begin() as c:
        execute(c, "INSERT INTO task_ayuza.organization (id, name) VALUES (:id, 'Synthetic') ON CONFLICT DO NOTHING",
                id=uuid.uuid4())
    yield engine
    engine.dispose()


@pytest.fixture(scope='module')
def acl(service):
    return AclService(service)


def _ip():
    """Distinct synthetic client address per call: the M01.2 limiter caps attempts per address."""
    return f'10.{secrets.randbelow(256)}.{secrets.randbelow(256)}.{secrets.randbelow(254) + 1}'


def person(auth_service):
    """Synthetic user with a normal session (temporary password changed), no ACL rights."""
    uid, name, temporary = user(auth_service)

    def sign_in(password):
        ip = _ip()
        pre = auth_service.prelogin(ip=ip)
        return auth_service.login(name, password, _ip(), pre['token'], pre['csrf_token'])

    first = sign_in(temporary)
    auth_service.change_password(first['token'], first['csrf_token'], PASSWORD)
    return Who(uid, sign_in(PASSWORD))


def admin_sql(migrator, statement, **params):
    """Fixture-only privileged changes (bootstrap and state flips that have no API in M01.3)."""
    with migrator.begin() as c:
        execute(c, statement, **params)


def rows(migrator, statement, **params):
    with migrator.connect() as c:
        return [dict(r) for r in execute(c, statement, **params).mappings()]


def mark_mfa(migrator, who):
    """Fixture-only: the M01.3 scenarios predate MFA, so mark the session as MFA-verified."""
    admin_sql(migrator, 'UPDATE task_ayuza.sessions SET mfa_verified_at = clock_timestamp() WHERE user_id=:u', u=who.id)


def make_sysadmin(migrator, who):
    mark_mfa(migrator, who)
    admin_sql(migrator, '''INSERT INTO task_ayuza.system_role_assignments (id, user_id, role_code, reason)
        VALUES (:id, :u, 'system_admin', 'synthetic bootstrap')''', id=uuid.uuid4(), u=who.id)


def make_workspace_admin(migrator, workspace_id, who):
    mark_mfa(migrator, who)
    admin_sql(migrator, '''INSERT INTO task_ayuza.workspace_members (id, workspace_id, user_id, role)
        VALUES (:id, :w, :u, 'workspace_admin')''', id=uuid.uuid4(), w=workspace_id, u=who.id)


def world(auth_service, acl, migrator):
    w = World()
    w.sysadmin, w.admin, w.admin2, w.member, w.outsider = (person(auth_service) for _ in range(5))
    make_sysadmin(migrator, w.sysadmin)
    w.ws = acl.create_workspace(w.sysadmin.token, w.sysadmin.csrf, 'Synthetic W', 'Europe/Moscow')['id']
    w.team = acl.create_team(w.sysadmin.token, w.sysadmin.csrf, 'Synthetic T')['id']
    make_workspace_admin(migrator, w.ws, w.admin)
    make_workspace_admin(migrator, w.ws, w.admin2)
    acl.set_workspace_member(w.admin.token, w.admin.csrf, w.ws, w.member.id, 'participant')
    acl.set_team_member(w.sysadmin.token, w.sysadmin.csrf, w.team, w.member.id)
    acl.set_workspace_team(w.admin.token, w.admin.csrf, w.ws, w.team)
    w.access = acl.grant_team_access(w.admin.token, w.admin.csrf, w.ws, w.team, w.member.id,
                                     'read', 'synthetic need')['id']
    return w


def read_as(acl, who, workspace_id, capability='read'):
    return acl.run_protected(who.token, workspace_id, capability, lambda c, u, s: 'ok')


def status(call):
    with pytest.raises(AclError) as error:
        call()
    return error.value.status


def violates(engine, statement, sqlstate, **params):
    with engine.connect() as c:
        with pytest.raises(DBAPIError) as error:
            execute(c, statement, **params)
        assert error.value.orig.sqlstate == sqlstate


def audit_actions(migrator, workspace_id):
    return {r['action'] for r in rows(migrator, 'SELECT action FROM task_ayuza.audit_events WHERE workspace_id=:w',
                                      w=workspace_id)}


# ---- schema: privileges and constraints (negative INSERT/UPDATE on real PostgreSQL) ----

def test_runtime_privileges_and_constraints(service, acl, migrator):
    w = world(service, acl, migrator)
    runtime = service.engine
    new_tables = ('workspaces', 'teams', 'workspace_members', 'team_members', 'workspace_teams',
                  'workspace_team_access', 'system_role_assignments')
    for table in new_tables:
        violates(runtime, f'TRUNCATE task_ayuza.{table}', '42501')
        violates(runtime, f'DELETE FROM task_ayuza.{table} WHERE false', '42501')

    backup = create_engine(_test_url('TASK_AYUZA_TEST_BACKUP_URL'), hide_parameters=True)
    try:
        with backup.connect() as c:
            for table in new_tables:
                execute(c, f'SELECT count(*) FROM task_ayuza.{table}').scalar_one()
        violates(backup, '''INSERT INTO task_ayuza.teams (id, organization_id, name)
            SELECT gen_random_uuid(), organization_id, 'x' FROM task_ayuza.users LIMIT 1''', '42501')
    finally:
        backup.dispose()

    member_insert = '''INSERT INTO task_ayuza.workspace_members (id, workspace_id, user_id, role)
        VALUES (gen_random_uuid(), :w, :u, :role)'''
    violates(runtime, member_insert, '23503', w=uuid.uuid4(), u=w.outsider.id, role='participant')
    violates(runtime, member_insert, '23503', w=w.ws, u=uuid.uuid4(), role='participant')
    violates(runtime, member_insert, '23514', w=w.ws, u=w.outsider.id, role='root')
    violates(runtime, member_insert, '23505', w=w.ws, u=w.member.id, role='participant')
    workspace_insert = '''INSERT INTO task_ayuza.workspaces (id, organization_id, name, timezone, version)
        SELECT gen_random_uuid(), id, :name, :tz, :version FROM task_ayuza.organization'''
    violates(runtime, workspace_insert, '23514', name='V0', tz='UTC', version=0)
    violates(runtime, workspace_insert, '23514', name='   ', tz='UTC', version=1)
    violates(runtime, workspace_insert, '23514', name='Bad zone', tz='Mars/Base', version=1)
    violates(runtime, "UPDATE task_ayuza.workspaces SET timezone='Mars/Base' WHERE id=:id", '23514', id=w.ws)
    violates(runtime, "UPDATE task_ayuza.workspaces SET version=0 WHERE id=:id", '23514', id=w.ws)
    violates(runtime, '''INSERT INTO task_ayuza.teams (id, organization_id, name)
        SELECT gen_random_uuid(), id, '   ' FROM task_ayuza.organization''', '23514')
    access_insert = '''INSERT INTO task_ayuza.workspace_team_access
        (id, workspace_id, team_id, user_id, capability, granted_by, reason)
        VALUES (gen_random_uuid(), :w, :t, :u, :cap, :by, 'synthetic')'''
    violates(runtime, access_insert, '23514', w=w.ws, t=w.team, u=w.member.id, cap='superpower', by=w.admin.id)
    violates(runtime, access_insert, '23514', w=w.ws, t=w.team, u=w.member.id, cap='export', by=w.member.id)
    violates(runtime, access_insert, '23503', w=w.ws, t=w.team, u=w.outsider.id, cap='read', by=w.admin.id)
    violates(runtime, access_insert, '23505', w=w.ws, t=w.team, u=w.member.id, cap='read', by=w.admin.id)
    violates(runtime, '''UPDATE task_ayuza.workspace_team_access SET revoked_at = granted_at - interval '1 day'
        WHERE id=:id''', '23514', id=w.access)

    audit_insert = '''INSERT INTO task_ayuza.audit_events
        (id, actor_kind, actor_id, session_id, workspace_id, entity_kind, entity_id, action, request_id, "new")
        VALUES (gen_random_uuid(), 'user', :actor, :session, :w, 'workspace_member', gen_random_uuid(),
                'acl.workspace_member_added', gen_random_uuid(), CAST(:new AS jsonb))'''
    session_id = uuid.uuid4()
    violates(runtime, audit_insert, '23514', actor=w.admin.id, session=session_id, w=w.ws, new='{"password":"x"}')
    violates(runtime, audit_insert, '23514', actor=w.admin.id, session=session_id, w=w.ws, new='{"active":"yes"}')
    violates(runtime, audit_insert, '23514', actor=w.admin.id, session=None, w=w.ws, new='{"active":true}')
    violates(runtime, audit_insert, '23503', actor=w.admin.id, session=session_id, w=uuid.uuid4(), new='{"active":true}')

    system_insert = '''INSERT INTO task_ayuza.system_role_assignments (id, user_id, role_code, granted_by, reason)
        VALUES (gen_random_uuid(), :u, :role, :by, 'synthetic')'''
    migrator_engine = create_engine(_test_url('TASK_AYUZA_TEST_MIGRATOR_URL'), hide_parameters=True)
    try:
        violates(migrator_engine, system_insert, '23514', u=w.outsider.id, role='root', by=None)
        violates(migrator_engine, system_insert, '23514', u=w.outsider.id, role='system_admin', by=w.outsider.id)
        violates(migrator_engine, system_insert, '23505', u=w.sysadmin.id, role='system_admin', by=None)
    finally:
        migrator_engine.dispose()


# ---- D01: positive and negative paths ----

def test_d01_authorized_member_is_visible_and_audited(service, acl, migrator):
    w = world(service, acl, migrator)
    assert read_as(acl, w.member, w.ws) == 'ok'
    assert acl.count_workspaces(w.member.token) == 1
    assert [r['id'] for r in acl.list_workspaces(w.member.token)] == [w.ws]
    assert acl.get_workspace(w.member.token, w.ws)['timezone'] == 'Europe/Moscow'
    assert audit_actions(migrator, w.ws) == {
        'acl.workspace_created', 'acl.workspace_member_added', 'acl.workspace_team_added',
        'acl.team_access_granted'}
    granted = rows(migrator, '''SELECT * FROM task_ayuza.audit_events
        WHERE entity_id=:id AND action='acl.team_access_granted' ''', id=w.access)
    assert len(granted) == 1
    event = granted[0]
    assert event['actor_kind'] == 'user' and event['actor_id'] == w.admin.id and event['session_id'] is not None
    assert event['new'] == {'capability': 'read', 'revoked': False} and event['old'] is None
    assert 'synthetic need' not in repr(rows(migrator, 'SELECT "old", "new" FROM task_ayuza.audit_events'))
    team_event = rows(migrator, "SELECT workspace_id FROM task_ayuza.audit_events WHERE action='acl.team_created' AND entity_id=:id",
                      id=w.team)
    assert team_event == [{'workspace_id': None}]


def test_d01_negative_paths(service, acl, migrator):
    w = world(service, acl, migrator)
    assert read_as(acl, w.member, w.ws) == 'ok'
    assert status(lambda: read_as(acl, w.member, w.ws, 'content_edit')) == 403  # capability absent

    def flip(statement, **params):
        admin_sql(migrator, statement, **params)

    flip('UPDATE task_ayuza.team_members SET active=false WHERE team_id=:t AND user_id=:u', t=w.team, u=w.member.id)
    assert status(lambda: read_as(acl, w.member, w.ws)) == 403  # inactive team member
    flip('UPDATE task_ayuza.team_members SET active=true WHERE team_id=:t AND user_id=:u', t=w.team, u=w.member.id)
    assert read_as(acl, w.member, w.ws) == 'ok'

    flip('UPDATE task_ayuza.workspace_teams SET active=false WHERE team_id=:t', t=w.team)
    assert status(lambda: read_as(acl, w.member, w.ws)) == 403  # team not allowed in this workspace
    flip('UPDATE task_ayuza.workspace_teams SET active=true WHERE team_id=:t', t=w.team)

    flip('UPDATE task_ayuza.teams SET active=false WHERE id=:t', t=w.team)
    assert status(lambda: read_as(acl, w.member, w.ws)) == 403  # inactive team
    flip('UPDATE task_ayuza.teams SET active=true WHERE id=:t', t=w.team)

    flip('UPDATE task_ayuza.workspace_team_access SET revoked_at=clock_timestamp() WHERE id=:id', id=w.access)
    assert status(lambda: read_as(acl, w.member, w.ws)) == 403  # revoked access
    flip('UPDATE task_ayuza.workspace_team_access SET revoked_at=NULL WHERE id=:id', id=w.access)
    assert read_as(acl, w.member, w.ws) == 'ok'

    flip('UPDATE task_ayuza.workspace_members SET active=false WHERE workspace_id=:w AND user_id=:u',
         w=w.ws, u=w.member.id)
    assert status(lambda: read_as(acl, w.member, w.ws)) == 404  # inactive workspace member: hidden
    flip('UPDATE task_ayuza.workspace_members SET active=true WHERE workspace_id=:w AND user_id=:u',
         w=w.ws, u=w.member.id)

    # Another area: the team member has no membership in a second workspace, and vice versa.
    ws2 = acl.create_workspace(w.sysadmin.token, w.sysadmin.csrf, 'Synthetic W2', 'UTC')['id']
    make_workspace_admin(migrator, ws2, w.outsider)
    assert status(lambda: read_as(acl, w.member, ws2)) == 404
    assert status(lambda: read_as(acl, w.outsider, w.ws)) == 404
    assert status(lambda: acl.set_workspace_team(w.outsider.token, w.outsider.csrf, w.ws, w.team)) == 404


def test_d01_indirect_self_grant_is_denied(service, acl, migrator):
    w = world(service, acl, migrator)
    admin, member, sysadmin = w.admin, w.member, w.sysadmin
    assert status(lambda: acl.grant_team_access(admin.token, admin.csrf, w.ws, w.team, admin.id, 'read', 'self')) == 403
    assert status(lambda: acl.set_workspace_member(admin.token, admin.csrf, w.ws, admin.id, 'participant',
                                                   expected_version=1)) == 403
    assert status(lambda: acl.set_workspace_member(member.token, member.csrf, w.ws, member.id, 'workspace_admin',
                                                   expected_version=1)) == 403
    assert status(lambda: acl.grant_team_access(member.token, member.csrf, w.ws, w.team, member.id,
                                                'content_edit', 'self')) == 403
    # A system administrator gains no content access by joining teams or workspaces himself.
    assert status(lambda: acl.set_team_member(sysadmin.token, sysadmin.csrf, w.team, sysadmin.id)) == 403
    assert status(lambda: acl.set_workspace_member(sysadmin.token, sysadmin.csrf, w.ws, sysadmin.id,
                                                   'workspace_admin')) == 404
    assert status(lambda: acl.grant_team_access(sysadmin.token, sysadmin.csrf, w.ws, w.team, sysadmin.id,
                                                'read', 'self')) == 404
    # Ordinary users cannot create structure.
    assert status(lambda: acl.create_team(member.token, member.csrf, 'No')) == 403
    assert status(lambda: acl.create_workspace(admin.token, admin.csrf, 'No', 'UTC')) == 403
    assert status(lambda: acl.set_team_member(admin.token, admin.csrf, w.team, w.outsider.id)) == 403
    # Capabilities beyond the delegable set need the M01.4 approval flow.
    for capability in ('export', 'manage_access', 'assign', 'archive_restore'):
        assert status(lambda: acl.grant_team_access(admin.token, admin.csrf, w.ws, w.team, member.id,
                                                    capability, 'synthetic')) == 403
    state = rows(migrator, '''SELECT role, active, version FROM task_ayuza.workspace_members
        WHERE workspace_id=:w AND user_id=:u''', w=w.ws, u=member.id)
    assert state == [{'role': 'participant', 'active': True, 'version': 1}]
    assert status(lambda: read_as(acl, sysadmin, w.ws)) == 404


# ---- D02: read is not export or manage_access; no administrator bypass ----

def test_d02_capabilities_are_distinct_and_there_is_no_admin_bypass(service, acl, migrator):
    w = world(service, acl, migrator)
    for capability in ('comment', 'link', 'content_edit', 'assign', 'archive_restore', 'manage_access', 'export'):
        assert status(lambda: read_as(acl, w.member, w.ws, capability)) == 403
    admin_sql(migrator, '''INSERT INTO task_ayuza.workspace_team_access
        (id, workspace_id, team_id, user_id, capability, granted_by, reason)
        VALUES (:id, :w, :t, :u, 'export', :by, 'synthetic export')''',
              id=uuid.uuid4(), w=w.ws, t=w.team, u=w.member.id, by=w.admin.id)
    assert read_as(acl, w.member, w.ws, 'export') == 'ok'
    assert status(lambda: read_as(acl, w.member, w.ws, 'manage_access')) == 403
    # System administrator and workspace administrator hold no content capability by role.
    assert status(lambda: read_as(acl, w.sysadmin, w.ws)) == 404
    assert status(lambda: read_as(acl, w.admin, w.ws)) == 403
    assert status(lambda: read_as(acl, w.admin, w.ws, 'export')) == 403
    # An observer keeps only read, even with another capability granted.
    changed = acl.set_workspace_member(w.admin.token, w.admin.csrf, w.ws, w.member.id, 'observer',
                                       expected_version=1)
    assert changed['version'] == 2
    acl.grant_team_access(w.admin.token, w.admin.csrf, w.ws, w.team, w.member.id, 'content_edit', 'synthetic')
    assert read_as(acl, w.member, w.ws, 'read') == 'ok'
    assert status(lambda: read_as(acl, w.member, w.ws, 'content_edit')) == 403
    assert status(lambda: acl.run_protected(w.member.token, w.ws, 'nonsense', lambda c, u, s: 'ok')) == 422


# ---- versions, idempotency, UUID validation, hidden objects ----

def test_versions_idempotency_and_audit(service, acl, migrator):
    w = world(service, acl, migrator)
    same = acl.set_workspace_member(w.admin.token, w.admin.csrf, w.ws, w.member.id, 'participant')
    assert same['created'] is False and same['version'] == 1
    assert not rows(migrator, "SELECT 1 FROM task_ayuza.audit_events WHERE action='acl.workspace_member_changed'"
                              " AND workspace_id=:w", w=w.ws)
    assert acl.set_workspace_member(w.admin.token, w.admin.csrf, w.ws, w.member.id, 'observer',
                                    expected_version=1)['version'] == 2
    assert status(lambda: acl.set_workspace_member(w.admin.token, w.admin.csrf, w.ws, w.member.id, 'participant',
                                                   expected_version=1)) == 409
    assert status(lambda: acl.set_workspace_member(w.admin.token, w.admin.csrf, w.ws, w.member.id, 'participant')) == 409
    assert acl.set_workspace_member(w.admin.token, w.admin.csrf, w.ws, w.member.id, 'participant',
                                    expected_version=2)['version'] == 3
    changed = rows(migrator, '''SELECT "old", "new" FROM task_ayuza.audit_events
        WHERE action='acl.workspace_member_changed' AND workspace_id=:w ORDER BY occurred_at, id''', w=w.ws)
    assert [(e['old'], e['new']) for e in changed] == [
        ({'role': 'participant', 'active': True}, {'role': 'observer', 'active': True}),
        ({'role': 'observer', 'active': True}, {'role': 'participant', 'active': True})]

    repeat = acl.grant_team_access(w.admin.token, w.admin.csrf, w.ws, w.team, w.member.id, 'read', 'synthetic need')
    assert repeat == {'id': w.access, 'version': 1, 'created': False}
    assert len(rows(migrator, "SELECT 1 FROM task_ayuza.audit_events WHERE entity_id=:id AND action='acl.team_access_granted'",
                    id=w.access)) == 1
    assert status(lambda: acl.revoke_team_access(w.admin.token, w.admin.csrf, w.ws, w.access, expected_version=5)) == 409
    assert status(lambda: acl.revoke_team_access(w.admin.token, w.admin.csrf, w.ws, w.access)) == 409
    revoked = acl.revoke_team_access(w.admin.token, w.admin.csrf, w.ws, w.access, expected_version=1)
    assert revoked == {'id': w.access, 'version': 2, 'revoked': True}
    assert acl.revoke_team_access(w.admin.token, w.admin.csrf, w.ws, w.access, expected_version=1)['version'] == 2
    assert len(rows(migrator, "SELECT 1 FROM task_ayuza.audit_events WHERE entity_id=:id AND action='acl.team_access_revoked'",
                    id=w.access)) == 1
    assert status(lambda: read_as(acl, w.member, w.ws)) == 403
    again = acl.grant_team_access(w.admin.token, w.admin.csrf, w.ws, w.team, w.member.id, 'read', 'synthetic again')
    assert again == {'id': w.access, 'version': 3, 'created': True}
    assert read_as(acl, w.member, w.ws) == 'ok'
    reactivated = rows(migrator, '''SELECT "old", "new" FROM task_ayuza.audit_events
        WHERE entity_id=:id AND action='acl.team_access_granted' ORDER BY occurred_at, id''', id=w.access)
    assert reactivated[-1]['old'] == {'revoked': True}


def test_lost_access_does_not_leak_conflict_or_object(service, acl, migrator):
    w = world(service, acl, migrator)
    removed = acl.set_workspace_member(w.admin2.token, w.admin2.csrf, w.ws, w.admin.id, 'workspace_admin',
                                       active=False, expected_version=1)
    assert removed['version'] == 2
    # Stale version, but the caller lost access: always the generic 404, never 409 or object data.
    assert status(lambda: acl.set_workspace_member(w.admin.token, w.admin.csrf, w.ws, w.member.id, 'observer',
                                                   expected_version=1)) == 404
    assert status(lambda: acl.get_workspace(w.admin.token, w.ws)) == 404
    assert acl.count_workspaces(w.admin.token) == 0 and acl.list_workspaces(w.admin.token) == []
    # A revoke id from another workspace is as hidden as a random one.
    ws2 = acl.create_workspace(w.sysadmin.token, w.sysadmin.csrf, 'Synthetic W2', 'UTC')['id']
    make_workspace_admin(migrator, ws2, w.outsider)
    with pytest.raises(AclError) as foreign:
        acl.revoke_team_access(w.outsider.token, w.outsider.csrf, ws2, w.access, expected_version=1)
    with pytest.raises(AclError) as missing:
        acl.revoke_team_access(w.outsider.token, w.outsider.csrf, ws2, uuid.uuid4(), expected_version=1)
    assert (foreign.value.status, foreign.value.message) == (missing.value.status, missing.value.message) == (404, 'Not found')


def test_bad_uuid_is_rejected_and_hidden_equals_missing(service, acl, migrator):
    w = world(service, acl, migrator)
    admin, member = w.admin, w.member
    bad = 'not-a-uuid'
    calls = (
        lambda: acl.get_workspace(member.token, bad),
        lambda: acl.run_protected(member.token, bad, 'read', lambda c, u, s: 'ok'),
        lambda: acl.set_workspace_member(admin.token, admin.csrf, bad, member.id, 'participant'),
        lambda: acl.set_workspace_member(admin.token, admin.csrf, w.ws, bad, 'participant'),
        lambda: acl.set_workspace_team(admin.token, admin.csrf, w.ws, bad),
        lambda: acl.grant_team_access(admin.token, admin.csrf, w.ws, bad, member.id, 'read', 'x'),
        lambda: acl.revoke_team_access(admin.token, admin.csrf, w.ws, bad),
        lambda: acl.set_team_member(w.sysadmin.token, w.sysadmin.csrf, bad, member.id),
    )
    for call in calls:
        assert status(call) == 422
    assert status(lambda: acl.set_workspace_member(admin.token, admin.csrf, w.ws, member.id, 'root')) == 422
    assert status(lambda: acl.set_workspace_member(admin.token, admin.csrf, w.ws, member.id, 'observer',
                                                   expected_version=0)) == 422
    assert status(lambda: acl.create_workspace(w.sysadmin.token, w.sysadmin.csrf, 'x' * 201, 'UTC')) == 422
    assert status(lambda: acl.create_workspace(w.sysadmin.token, w.sysadmin.csrf, 'Zone', 'Mars/Base')) == 422
    assert status(lambda: acl.list_workspaces(member.token, limit=0)) == 422
    # Hidden and nonexistent workspaces are indistinguishable.
    with pytest.raises(AclError) as hidden:
        acl.get_workspace(w.outsider.token, w.ws)
    with pytest.raises(AclError) as missing:
        acl.get_workspace(w.outsider.token, uuid.uuid4())
    assert (hidden.value.status, hidden.value.message) == (missing.value.status, missing.value.message)
    # Unknown targets are indistinguishable from other-organization targets.
    assert status(lambda: acl.set_workspace_member(admin.token, admin.csrf, w.ws, uuid.uuid4(), 'participant')) == 404
    assert status(lambda: acl.set_workspace_team(admin.token, admin.csrf, w.ws, uuid.uuid4())) == 404
    # Mutations require CSRF.
    with pytest.raises(AuthError) as no_csrf:
        acl.set_workspace_member(admin.token, None, w.ws, member.id, 'observer', expected_version=1)
    assert no_csrf.value.status == 403


def test_list_and_count_expose_only_visible_workspaces_with_stable_pages(service, acl, migrator):
    w = world(service, acl, migrator)
    tag = 'Page-' + uuid.uuid4().hex
    reader = person(service)
    created = []
    for index in range(3):
        wid = acl.create_workspace(w.sysadmin.token, w.sysadmin.csrf, f'{tag}-{index}', 'UTC')['id']
        make_workspace_admin(migrator, wid, reader)
        created.append(wid)
    assert acl.count_workspaces(reader.token) == 3
    first = acl.list_workspaces(reader.token, limit=2)
    last = first[-1]
    second = acl.list_workspaces(reader.token, limit=2, after=(last['name'], last['id']))
    assert [r['id'] for r in first + second] == created
    assert acl.count_workspaces(w.outsider.token) == 0
    assert acl.list_workspaces(w.outsider.token) == []
    assert w.ws not in [r['id'] for r in acl.list_workspaces(reader.token)]


def test_structure_creation_audit(service, acl, migrator):
    w = world(service, acl, migrator)
    created = acl.create_workspace(w.sysadmin.token, w.sysadmin.csrf, 'Zone ok', 'Asia/Yekaterinburg')
    event = rows(migrator, "SELECT * FROM task_ayuza.audit_events WHERE entity_id=:id", id=created['id'])
    assert len(event) == 1 and event[0]['workspace_id'] == created['id']
    assert event[0]['new'] == {'name': 'Zone ok', 'timezone': 'Asia/Yekaterinburg'}
    assert event[0]['actor_id'] == w.sysadmin.id


# ---- atomicity and retries ----

def test_audit_failure_rolls_back_access_change(service, acl, migrator):
    w = world(service, acl, migrator)

    def member_rows():
        return rows(migrator, 'SELECT 1 FROM task_ayuza.workspace_members WHERE workspace_id=:w AND user_id=:u',
                    w=w.ws, u=w.outsider.id)

    def boom(*args, **kwargs):
        raise RuntimeError('synthetic audit failure')

    with patch.object(acl_module, 'audit', boom):
        with pytest.raises(RuntimeError):
            acl.set_workspace_member(w.admin.token, w.admin.csrf, w.ws, w.outsider.id, 'participant')
    assert member_rows() == []

    real = acl_module.audit

    def refused_by_database(c, u, s, **kwargs):
        return real(c, u, s, **{**kwargs, 'action': 'acl.team_created'})  # violates the scope CHECK

    with patch.object(acl_module, 'audit', refused_by_database):
        with pytest.raises(AuthError) as error:
            acl.set_workspace_member(w.admin.token, w.admin.csrf, w.ws, w.outsider.id, 'participant')
    assert error.value.status == 503
    assert member_rows() == []

    acl.set_workspace_member(w.admin.token, w.admin.csrf, w.ws, w.outsider.id, 'participant')
    acl.set_team_member(w.sysadmin.token, w.sysadmin.csrf, w.team, w.outsider.id)
    with patch.object(acl_module, 'audit', boom):
        with pytest.raises(RuntimeError):
            acl.grant_team_access(w.admin.token, w.admin.csrf, w.ws, w.team, w.outsider.id, 'read', 'synthetic')
    assert rows(migrator, 'SELECT 1 FROM task_ayuza.workspace_team_access WHERE user_id=:u', u=w.outsider.id) == []


def test_serialization_retry_does_not_duplicate_audit_or_access(service, acl, migrator):
    w = world(service, acl, migrator)
    real = acl_module.audit
    calls = []

    def flaky(c, u, s, **kwargs):
        real(c, u, s, **kwargs)
        calls.append(1)
        if len(calls) == 1:
            original = Exception('synthetic')
            original.sqlstate = '40001'
            raise DBAPIError('synthetic', {}, original)

    request = uuid.uuid4()
    with patch.object(acl_module, 'audit', flaky):
        result = acl.set_workspace_member(w.admin.token, w.admin.csrf, w.ws, w.outsider.id, 'participant',
                                          request_id=request)
    assert len(calls) == 2 and result['created'] is True
    assert len(rows(migrator, 'SELECT 1 FROM task_ayuza.audit_events WHERE request_id=:r', r=request)) == 1
    assert len(rows(migrator, 'SELECT 1 FROM task_ayuza.workspace_members WHERE workspace_id=:w AND user_id=:u',
                    w=w.ws, u=w.outsider.id)) == 1

    calls.clear()
    request = uuid.uuid4()

    def always(c, u, s, **kwargs):
        real(c, u, s, **kwargs)
        calls.append(1)
        original = Exception('synthetic')
        original.sqlstate = '40P01'
        raise DBAPIError('synthetic', {}, original)

    with patch.object(acl_module, 'audit', always):
        with pytest.raises(AuthError) as error:
            acl.set_team_member(w.sysadmin.token, w.sysadmin.csrf, w.team, w.outsider.id, request_id=request)
    assert error.value.status == 503 and len(calls) == 3
    assert rows(migrator, 'SELECT 1 FROM task_ayuza.audit_events WHERE request_id=:r', r=request) == []
    assert rows(migrator, 'SELECT 1 FROM task_ayuza.team_members WHERE team_id=:t AND user_id=:u',
                t=w.team, u=w.outsider.id) == []


# ---- races on two independent PostgreSQL connections with explicit barriers ----

def test_race_revocation_committed_first_rejects_operation(service, acl, migrator):
    w = world(service, acl, migrator)
    updated, release = threading.Event(), threading.Event()
    real = acl_module.audit

    def hooked(c, u, s, **kwargs):
        if kwargs['action'] == 'acl.team_access_revoked':
            updated.set()  # revocation row change is pending, transaction still open
            assert release.wait(30)
        return real(c, u, s, **kwargs)

    with patch.object(acl_module, 'audit', hooked), ThreadPoolExecutor(max_workers=2) as pool:
        revoke = pool.submit(acl.revoke_team_access, w.admin.token, w.admin.csrf, w.ws, w.access, 1)
        assert updated.wait(30)
        operation = pool.submit(read_as, acl, w.member, w.ws)
        time.sleep(1.0)
        assert not operation.done()  # protected check waits on the uncommitted revocation
        release.set()
        assert revoke.result(timeout=30)['revoked'] is True
        with pytest.raises(AclError) as error:
            operation.result(timeout=30)
        assert error.value.status == 403


def test_race_operation_serialized_first_completes_before_revocation(service, acl, migrator):
    w = world(service, acl, migrator)
    inside, release = threading.Event(), threading.Event()

    def hold(c, u, s):
        inside.set()  # check passed, transaction open with ACL rows share-locked
        assert release.wait(30)
        return 'done'

    with ThreadPoolExecutor(max_workers=2) as pool:
        operation = pool.submit(acl.run_protected, w.member.token, w.ws, 'read', hold)
        assert inside.wait(30)
        revoke = pool.submit(acl.revoke_team_access, w.admin.token, w.admin.csrf, w.ws, w.access, 1)
        time.sleep(1.0)
        assert not revoke.done()  # revocation cannot commit under a running checked operation
        release.set()
        assert operation.result(timeout=30) == 'done'
        assert revoke.result(timeout=30)['revoked'] is True
    assert status(lambda: read_as(acl, w.member, w.ws)) == 403


def test_race_same_version_edits_give_one_success_and_one_409(service, acl, migrator):
    w = world(service, acl, migrator)
    barrier = threading.Barrier(2)

    def edit(admin, role):
        barrier.wait(30)
        return acl.set_workspace_member(admin.token, admin.csrf, w.ws, w.member.id, role, expected_version=1)

    outcomes = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(edit, w.admin, 'observer'), pool.submit(edit, w.admin2, 'workspace_admin')]
        for future in futures:
            try:
                outcomes.append(('ok', future.result(timeout=60)['version']))
            except AclError as error:
                outcomes.append(('error', error.status))
    assert sorted(outcomes, key=lambda item: item[0]) == [('error', 409), ('ok', 2)]
    final = rows(migrator, 'SELECT version FROM task_ayuza.workspace_members WHERE workspace_id=:w AND user_id=:u',
                 w=w.ws, u=w.member.id)
    assert final == [{'version': 2}]
    assert len(rows(migrator, "SELECT 1 FROM task_ayuza.audit_events WHERE action='acl.workspace_member_changed'"
                              " AND workspace_id=:w", w=w.ws)) == 1


def test_race_identical_grants_create_one_row_and_one_audit_event(service, acl, migrator):
    w = world(service, acl, migrator)
    barrier = threading.Barrier(2)

    def grant(admin):
        barrier.wait(30)
        return acl.grant_team_access(admin.token, admin.csrf, w.ws, w.team, w.member.id, 'comment', 'synthetic')

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [f.result(timeout=60) for f in [pool.submit(grant, w.admin), pool.submit(grant, w.admin2)]]
    assert sorted(r['created'] for r in results) == [False, True]
    assert results[0]['id'] == results[1]['id']
    assert len(rows(migrator, "SELECT 1 FROM task_ayuza.workspace_team_access WHERE capability='comment' AND user_id=:u",
                    u=w.member.id)) == 1
    assert len(rows(migrator, "SELECT 1 FROM task_ayuza.audit_events WHERE entity_id=:id AND action='acl.team_access_granted'",
                    id=results[0]['id'])) == 1
