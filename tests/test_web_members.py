"""WEB-MEMBERS-1: adding employees from the web UI. Synthetic data only, acceptance runner only."""
import uuid
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from backend.acl import EMPLOYEE_LIMIT, AclError
from backend.auth import AuthError, argon2_slot, execute, insert_user, one, prepare_user
from backend.main import app
from backend.passwords import verify
from test_m01_acl import (acl, admin_sql, make_sysadmin, make_workspace_admin, mark_mfa,  # noqa: F401
                          migrator, person, world)
from test_m01_acl import _ip
from test_m01_acl import rows as db_rows
from test_m01_auth import login as sign_in
from test_m01_mfa_grants import code, mfa, with_mfa  # noqa: F401
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


# ---- AclService.add_employees (phase 2) ----

@pytest.fixture(scope='module')
def w(service, acl, migrator):
    return world(service, acl, migrator)


def uniq(prefix='emp'):
    return f'{prefix}_{uuid.uuid4().hex[:12]}'


def row(login=None, role='participant', team=None, name='Синтетический сотрудник'):
    item = {'login': login or uniq(), 'display_name': name, 'role': role}
    if team is not None:
        item['team'] = team
    return item


def present(migrator, logins):
    found = db_rows(migrator, 'SELECT login_normalized FROM task_ayuza.users '
                    'WHERE login_normalized = ANY(CAST(:l AS text[]))', l=list(logins))
    return {r['login_normalized'] for r in found}


def login_of(migrator, who):
    return db_rows(migrator, 'SELECT login_normalized FROM task_ayuza.users WHERE id=:id', id=who.id)[0]['login_normalized']


def sysadmin_and_ws_admin(service, migrator, ws):
    who = person(service)
    make_sysadmin(migrator, who)
    make_workspace_admin(migrator, ws, who)
    return who


def add(acl, who, ws, rows, dry_run=False):
    return acl.add_employees(who.token, who.csrf, ws, rows, dry_run=dry_run)


def status_of(call):
    with pytest.raises(AclError) as error:
        call()
    return error.value.status


def test_only_this_workspaces_admin_may_add(service, acl, migrator, w):
    participant, observer, outsider, foreign = (person(service) for _ in range(4))
    acl.set_workspace_member(w.admin.token, w.admin.csrf, w.ws, participant.id, 'participant')
    acl.set_workspace_member(w.admin.token, w.admin.csrf, w.ws, observer.id, 'observer')
    other = acl.create_workspace(w.sysadmin.token, w.sysadmin.csrf, 'Synthetic W2 ' + uniq(), 'Europe/Moscow')['id']
    make_workspace_admin(migrator, other, foreign)
    for who in (participant, observer, outsider):
        mark_mfa(migrator, who)  # reach the role check, not the MFA check
    logins = [uniq() for _ in range(3)]
    assert status_of(lambda: add(acl, participant, w.ws, [row(logins[0])])) == 403
    assert status_of(lambda: add(acl, observer, w.ws, [row(logins[1])])) == 403
    assert status_of(lambda: add(acl, outsider, w.ws, [row(logins[2])])) == 404
    assert status_of(lambda: add(acl, foreign, w.ws, [row(logins[2])])) == 404  # admin of another workspace
    assert not present(migrator, logins)


def test_fresh_mfa_is_required(service, acl, migrator, w):
    who = person(service)
    admin_sql(migrator, "INSERT INTO task_ayuza.workspace_members (id, workspace_id, user_id, role) "
              "VALUES (:id, :w, :u, 'workspace_admin')", id=uuid.uuid4(), w=w.ws, u=who.id)
    login = uniq()
    assert status_of(lambda: add(acl, who, w.ws, [row(login)])) == 403
    assert not present(migrator, [login])


def test_dry_run_reports_and_writes_nothing(service, acl, migrator, w):
    logins = [uniq(), uniq()]
    result = add(acl, w.admin, w.ws, [row(logins[0]), row(logins[1], 'observer')], dry_run=True)
    assert result['ok'] and result['dry_run'] and result['created'] == []
    assert [r['errors'] for r in result['rows']] == [[], []]
    assert not present(migrator, logins)


def test_add_creates_accounts_with_temporary_passwords_and_audit(service, acl, migrator, w):
    first, second = uniq('Mixed'), uniq()
    result = add(acl, w.admin, w.ws, [row(first, 'participant'), row(second, 'workspace_admin', name='  Админ  ')])
    assert result['ok'] and not result['dry_run'] and len(result['created']) == 2
    by_login = {item['login']: item for item in result['created']}
    assert set(by_login) == {first.lower(), second}
    assert by_login[second]['display_name'] == 'Админ'
    for item in result['created']:
        user_row = read_user(service, item['id'])
        assert user_row['must_change_password'] is True and user_row['temporary_expires_at'] is not None
        with service.engine.connect() as c:
            hours = execute(c, '''SELECT extract(epoch FROM temporary_expires_at - clock_timestamp())/3600
                FROM task_ayuza.users WHERE id=:id''', id=item['id']).scalar_one()
        assert 23.9 < float(hours) <= 24
        member = db_rows(migrator, 'SELECT role, active FROM task_ayuza.workspace_members '
                         'WHERE workspace_id=:w AND user_id=:u', w=w.ws, u=item['id'])
        assert member == [{'role': item['role'], 'active': True}]
        # the temporary password opens only a password-change session
        assert sign_in(service, item['login'], item['password'], ip=_ip())['kind'] == 'password'
        events = db_rows(migrator, '''SELECT actor_kind, actor_id, session_id, workspace_id, "new"
            FROM task_ayuza.audit_events WHERE entity_id=:id AND action='acl.user_created' ''', id=item['id'])
        assert len(events) == 1
        assert events[0]['actor_kind'] == 'user' and events[0]['actor_id'] == w.admin.id
        assert events[0]['session_id'] is not None and events[0]['workspace_id'] == w.ws
        assert events[0]['new'] == {'role': item['role']}
        added = db_rows(migrator, '''SELECT actor_id FROM task_ayuza.audit_events
            WHERE entity_id=(SELECT id FROM task_ayuza.workspace_members WHERE workspace_id=:w AND user_id=:u)
              AND action='acl.workspace_member_added' ''', w=w.ws, u=item['id'])
        assert added == [{'actor_id': w.admin.id}]
        leaked = db_rows(migrator, 'SELECT count(*) AS n FROM task_ayuza.audit_events a '
                         'WHERE strpos(to_jsonb(a)::text, :pw) > 0', pw=item['password'])
        assert leaked[0]['n'] == 0  # a password never reaches the audit table


def test_errors_are_reported_per_row_and_nothing_is_created(service, acl, migrator, w):
    taken, fresh = uniq(), uniq()
    add(acl, w.admin, w.ws, [row(taken)])
    own = login_of(migrator, w.admin)
    batch = [row(fresh), row(taken), row(fresh), row('a b'), row(role='boss'), row(own), row(name='   '),
             {'login': uniq(), 'display_name': 'x', 'role': 'participant', 'password': 'smuggled'}]
    result = add(acl, w.admin, w.ws, batch)
    assert not result['ok'] and result['created'] == []
    assert [r['errors'] for r in result['rows']] == [
        [], ['login_taken'], ['duplicate_login'], ['invalid_login'], ['invalid_role'], ['self'],
        ['invalid_name'], ['invalid_row']]
    assert not present(migrator, [fresh])  # all or nothing: the valid row was not created either
    assert all(r['row'] == i + 1 for i, r in enumerate(result['rows']))


def test_team_in_a_row_needs_a_system_administrator(service, acl, migrator, w):
    team_name = uniq('Team')
    team = acl.create_team(w.sysadmin.token, w.sysadmin.csrf, team_name)['id']
    plain = uniq()
    refused = add(acl, w.admin, w.ws, [row(plain, team=team_name)])
    assert not refused['ok'] and refused['rows'][0]['errors'] == ['team_requires_system_admin']
    assert not present(migrator, [plain])
    both = sysadmin_and_ws_admin(service, migrator, w.ws)
    result = add(acl, both, w.ws, [row(uniq(), team=team_name), row(uniq(), team='')])
    assert result['ok']
    uid = result['created'][0]['id']
    assert db_rows(migrator, 'SELECT active FROM task_ayuza.team_members WHERE team_id=:t AND user_id=:u',
                   t=team, u=uid) == [{'active': True}]
    assert db_rows(migrator, "SELECT count(*) AS n FROM task_ayuza.team_members WHERE user_id=:u",
                   u=result['created'][1]['id'])[0]['n'] == 0
    assert db_rows(migrator, "SELECT actor_id FROM task_ayuza.audit_events WHERE action='acl.team_member_added' "
                   "AND entity_id=(SELECT id FROM task_ayuza.team_members WHERE team_id=:t AND user_id=:u)",
                   t=team, u=uid) == [{'actor_id': both.id}]


def test_unknown_and_ambiguous_team_names(service, acl, migrator, w):
    twin = uniq('Twin')
    for _ in range(2):
        acl.create_team(w.sysadmin.token, w.sysadmin.csrf, twin)
    both = sysadmin_and_ws_admin(service, migrator, w.ws)
    result = add(acl, both, w.ws, [row(team=twin), row(team=uniq('Missing')), row(team='x' * 201)])
    assert not result['ok']
    assert [r['errors'] for r in result['rows']] == [['team_ambiguous'], ['team_unknown'], ['invalid_team']]


def test_nothing_is_hashed_before_authorization_and_validation(service, acl, migrator, w):
    # Argon2id costs 64 MiB per password: it must not run for a caller who may not be here or for a list that fails.
    participant, no_mfa = person(service), person(service)
    acl.set_workspace_member(w.admin.token, w.admin.csrf, w.ws, participant.id, 'participant')
    mark_mfa(migrator, participant)
    admin_sql(migrator, "INSERT INTO task_ayuza.workspace_members (id, workspace_id, user_id, role) "
              "VALUES (:id, :w, :u, 'workspace_admin')", id=uuid.uuid4(), w=w.ws, u=no_mfa.id)
    taken = uniq()
    add(acl, w.admin, w.ws, [row(taken)])
    with patch('backend.acl.prepare_user', side_effect=AssertionError('hashed too early')):
        with pytest.raises(AuthError):
            acl.add_employees('forged-token', 'forged-csrf', w.ws, [row()])
        assert status_of(lambda: add(acl, participant, w.ws, [row()])) == 403
        assert status_of(lambda: add(acl, no_mfa, w.ws, [row()])) == 403
        assert add(acl, w.admin, w.ws, [row(taken)])['ok'] is False          # a taken login is found without hashing
        assert add(acl, w.admin, w.ws, [row('a b')])['ok'] is False
        assert add(acl, w.admin, w.ws, [row()], dry_run=True)['ok'] is True


def test_row_limit_and_malformed_requests(service, acl, migrator, w):
    assert EMPLOYEE_LIMIT == 200
    for bad in ([], 'rows', None, [row()] * (EMPLOYEE_LIMIT + 1)):
        assert status_of(lambda: add(acl, w.admin, w.ws, bad)) == 422
    assert status_of(lambda: acl.add_employees(w.admin.token, w.admin.csrf, w.ws, [row()], dry_run='yes')) == 422
    assert status_of(lambda: add(acl, w.admin, 'not-a-uuid', [row()])) == 422
    twohundred = add(acl, w.admin, w.ws, [row() for _ in range(EMPLOYEE_LIMIT)], dry_run=True)
    assert twohundred['ok'] and len(twohundred['rows']) == EMPLOYEE_LIMIT


# ---- HTTP routes (phase 3) ----

ORIGIN = 'https://test.local'


@pytest.fixture(scope='module')
def client():
    with TestClient(app, base_url=ORIGIN, client=('192.0.2.78', 1234)) as c:
        yield c


def read(who):
    return {'Cookie': f'__Host-ay_session={who.token}'}


def write(who):
    return {**read(who), 'Origin': ORIGIN, 'X-CSRF-Token': who.csrf}


def clear_mfa(migrator, who):
    admin_sql(migrator, 'UPDATE task_ayuza.sessions SET mfa_verified_at = NULL WHERE user_id=:u', u=who.id)


def mfa_marked(migrator, who):
    rows = db_rows(migrator, 'SELECT mfa_verified_at FROM task_ayuza.sessions WHERE user_id=:u', u=who.id)
    return any(row['mfa_verified_at'] is not None for row in rows)  # a user may hold several sessions, no order


def test_http_mfa_verify_accepts_code_and_backup_code_and_rejects_the_rest(client, service, mfa, migrator):
    who, secret, backups = with_mfa(service, mfa)
    url = '/api/v1/auth/mfa/verify'
    clear_mfa(migrator, who)
    assert client.post(url, json={'code': code(secret, 1)}, headers=read(who)).status_code == 403  # no Origin, no CSRF
    assert client.post(url, json={'code': code(secret, 1)}, headers={**write(who), 'Origin': 'https://evil.test'}
                       ).status_code == 403
    assert client.post(url, json={'code': code(secret, 1)}, headers={**write(who), 'X-CSRF-Token': 'wrong'}
                       ).status_code == 403
    assert client.post(url, json={'code': code(secret, 1)}).status_code in (401, 403)  # no session
    bad = client.post(url, json={'code': '000000' if code(secret, 1) != '000000' else '111111'}, headers=write(who))
    assert bad.status_code == 403 and not mfa_marked(migrator, who)
    assert client.post(url, json={}, headers=write(who)).status_code == 422
    ok = client.post(url, json={'code': code(secret, 1)}, headers=write(who))
    assert ok.status_code == 200 and ok.json() == {'ok': True} and mfa_marked(migrator, who)
    assert ok.headers['cache-control'] == 'no-store'
    clear_mfa(migrator, who)
    assert client.post(url, json={'code': backups[0]}, headers=write(who)).status_code == 200
    assert mfa_marked(migrator, who)
    clear_mfa(migrator, who)
    assert client.post(url, json={'code': backups[0]}, headers=write(who)).status_code == 403  # used once only
    assert not mfa_marked(migrator, who)
    plain = person(service)  # no MFA enrolled
    assert client.post(url, json={'code': '123456'}, headers=write(plain)).status_code == 403


def test_http_admin_lists(client, service, w):
    mine = client.get('/api/v1/admin/workspaces', headers=read(w.admin))
    assert mine.status_code == 200 and mine.headers['cache-control'] == 'no-store'
    assert str(w.ws) in {item['id'] for item in mine.json()['workspaces']} and mine.json()['system_admin'] is False
    assert client.get('/api/v1/admin/workspaces', headers=read(w.member)).json()['workspaces'] == []
    assert client.get('/api/v1/admin/workspaces').status_code in (401, 403)
    assert client.get('/api/v1/admin/teams', headers=read(w.admin)).status_code == 403
    assert client.get('/api/v1/admin/teams').status_code in (401, 403)
    teams = client.get('/api/v1/admin/teams', headers=read(w.sysadmin))
    assert teams.status_code == 200 and str(w.team) in {item['id'] for item in teams.json()}
    assert set(teams.json()[0]) == {'id', 'name'}


def test_http_add_employees(client, service, migrator, w):
    url = f'/api/v1/admin/workspaces/{w.ws}/employees'
    first, second = uniq(), uniq()
    body = {'rows': [row(first), row(second, 'observer')]}
    # request verification and sessions
    assert client.post(url, json=body, headers=read(w.admin)).status_code == 403
    assert client.post(url, json=body, headers={**write(w.admin), 'Origin': 'https://evil.test'}).status_code == 403
    assert client.post(url, json=body, headers={**write(w.admin), 'X-CSRF-Token': 'wrong'}).status_code == 403
    assert client.post(url, json=body).status_code in (401, 403)
    with patch('backend.acl.prepare_user', side_effect=AssertionError('hashed for an anonymous caller')):
        forged = {'Origin': ORIGIN, 'X-CSRF-Token': 'forged'}  # the headers are not a secret: only the session is
        assert client.post(url, json=body, headers=forged).status_code == 401
        assert client.post(url, json=body, headers={**forged, 'Cookie': '__Host-ay_session=forged'}).status_code == 401
        assert client.post(url, json=body, headers={**write(w.admin), 'X-CSRF-Token': 'forged'}).status_code == 403
    # roles
    for who, status in ((w.member, 403), (w.outsider, 404)):
        mark_mfa(migrator, who)
        assert client.post(url, json=body, headers=write(who)).status_code == status
    no_mfa = person(service)
    admin_sql(migrator, "INSERT INTO task_ayuza.workspace_members (id, workspace_id, user_id, role) "
              "VALUES (:id, :w, :u, 'workspace_admin')", id=uuid.uuid4(), w=w.ws, u=no_mfa.id)
    refused = client.post(url, json=body, headers=write(no_mfa))
    assert refused.status_code == 403 and refused.json() == {'detail': 'MFA required'}
    assert not present(migrator, [first, second])
    # malformed input echoes nothing
    for bad in ({'rows': 'x'}, {'rows': [row()] * 201}, {}, {'rows': [row()], 'dry_run': 'maybe'}):
        response = client.post(url, json=bad, headers=write(w.admin))
        assert response.status_code == 422 and response.json() == {'detail': 'Invalid request'}
    assert client.post(url.replace(str(w.ws), 'not-a-uuid'), json=body, headers=write(w.admin)).status_code == 422
    # dry run, errors, success
    preview = client.post(url, json={**body, 'dry_run': True}, headers=write(w.admin))
    assert preview.status_code == 200 and preview.json()['ok'] and preview.json()['created'] == []
    assert not present(migrator, [first, second])
    invalid = client.post(url, json={'rows': [row(first), row('a b')]}, headers=write(w.admin))
    assert invalid.status_code == 422 and invalid.json()['ok'] is False and invalid.json()['created'] == []
    assert invalid.json()['rows'][1]['errors'] == ['invalid_login'] and 'password' not in invalid.text
    assert not present(migrator, [first])
    flagged = client.post(url, json={'rows': [row('a b')], 'dry_run': True}, headers=write(w.admin))
    assert flagged.status_code == 200 and flagged.json()['ok'] is False  # a preview reports, it does not fail
    created = client.post(url, json=body, headers=write(w.admin))
    assert created.status_code == 200 and created.headers['cache-control'] == 'no-store'
    data = created.json()
    assert data['ok'] and [item['login'] for item in data['created']] == [first, second]
    assert all(item['password'] and item['id'] for item in data['created'])
    assert present(migrator, [first, second]) == {first, second}
    assert client.post(url, json=body, headers=write(w.admin)).status_code == 422  # logins are taken now
