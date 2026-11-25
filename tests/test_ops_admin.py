"""OPS-BOOTSTRAP-1: operator commands bring a fresh installation to a usable state.

Disposable loopback PostgreSQL only, synthetic data only (run by tests/run_m01_acceptance.py).
The suite's one-time setup is already completed by earlier modules, so the owner here is a
synthetic system_owner; `setup` itself is checked to refuse a second run cleanly.
"""
import base64
import os
import re
import sys
import time
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import admin as admin_cli  # noqa: E402
from backend.mfa import hotp  # noqa: E402
from test_m01_acl import acl, admin_sql, migrator, rows  # noqa: F401,E402
from test_m01_auth import PASSWORD, service  # noqa: F401,E402
from backend.work import WorkService  # noqa: E402


class Console:
    """Scripted operator: answers prompts and captures output. The first MFA check of a person uses
    a TOTP computed from the printed setup key; later ones use the printed one-time backup codes,
    since a TOTP time step cannot be replayed."""
    def __init__(self):
        self.lines, self.passwords, self.secrets, self.backup, self.used = [], {}, {}, {}, set()
        self.current, self.script = None, []

    def out(self, line):
        line = str(line)
        self.lines.append(line)
        found = re.search(r'setup key: ([A-Z2-7=]+)', line)
        if found:
            self.secrets[self.current] = found.group(1)
        if re.fullmatch(r'  [0-9a-f]{6}-[0-9a-f]{4}', line):
            self.backup.setdefault(self.current, []).append(line.strip())

    def ask_secret(self, prompt):
        self.current = prompt.removeprefix('Password for ').removesuffix(': ')
        return self.passwords[self.current]

    def ask(self, prompt):
        if prompt.endswith('> '):          # a `session` prompt: next scripted line, EOF at the end
            if not self.script:
                raise EOFError
            return self.script.pop(0)
        secret = self.secrets[self.current]
        step = int(time.time() // 30)
        if (secret, step) not in self.used:
            self.used.add((secret, step))
            return hotp(base64.b32decode(secret), step)
        return self.backup[self.current].pop()


def run(console, *argv):
    env = {'TASK_AYUZA_DATABASE_URL': os.environ['TASK_AYUZA_TEST_RUNTIME_URL'],
           'TASK_AYUZA_MIGRATOR_URL': os.environ['TASK_AYUZA_TEST_MIGRATOR_URL'],
           'TASK_AYUZA_AUTH_HMAC_KEY': os.environ['TASK_AYUZA_AUTH_HMAC_KEY'],
           'TASK_AYUZA_MFA_KEY': os.environ['TASK_AYUZA_MFA_KEY']}
    start = len(console.lines)
    code = admin_cli.main(list(argv), ask_secret=console.ask_secret, ask=console.ask, out=console.out, environ=env)
    return code, '\n'.join(console.lines[start:])


def temporary(output):
    return re.search(r'shown once\): (\S+)', output).group(1)


def first_password_change(service, login, temporary_password):
    """What the person does on the website after receiving the temporary password."""
    pre = service.prelogin(ip='198.51.100.150')
    s = service.login(login, temporary_password, '198.51.100.150', pre['token'], pre['csrf_token'])
    service.change_password(s['token'], s['csrf_token'], PASSWORD)


def test_operator_bootstrap_to_a_working_workspace(service, migrator):
    console = Console()
    suffix = uuid.uuid4().hex[:8]
    owner, sysadmin, lead, member = (f'{r}_{suffix}' for r in ('owner', 'sysadmin', 'lead', 'member'))

    code, out = run(console, 'init-org', 'Synthetic')
    assert code == 0 and 'already exists' in out
    for login in (owner, sysadmin, lead, member):
        code, out = run(console, 'create-user', login, 'Synthetic ' + login)
        assert code == 0
        # MFA enrollment is refused while the temporary password is still in place
        if login == owner:
            console.passwords[login] = temporary(out)
            code, refused = run(console, 'enroll-mfa', login)
            assert code == 1 and 'temporary password' in refused
        first_password_change(service, login, temporary(out))
        console.passwords[login] = PASSWORD
    for login in (owner, sysadmin, lead):
        code, out = run(console, 'enroll-mfa', login)
        assert code == 0 and 'MFA is enabled' in out and out.count('\n  ') >= 12
    # The suite already completed the one-time setup: a second run is refused, nothing changes.
    code, out = run(console, 'setup', owner, lead)
    assert code == 1 and 'already completed' in out
    uid = rows(migrator, 'SELECT id FROM task_ayuza.users WHERE login=:l', l=owner)[0]['id']
    admin_sql(migrator, '''INSERT INTO task_ayuza.system_role_assignments (id, user_id, role_code, reason)
        VALUES (:id, :u, 'system_owner', 'synthetic owner')''', id=uuid.uuid4(), u=uid)

    console.script = [f'grant-role {sysadmin} system_admin', f'grant-role {sysadmin} root']
    code, out = run(console, 'session', owner)
    assert f'{sysadmin} now has system_admin' in out and 'error: Role must be one of' in out
    assert run(console, 'grant-role', sysadmin, lead, 'system_admin')[0] == 1        # not an owner
    ws, team = f'Ops W {suffix}', f'Ops T {suffix}'
    # One sign-in for several commands: the 5-per-15-minutes login limit stays untouched.
    attempts = lambda login: rows(migrator, 'SELECT count(*) AS n FROM task_ayuza.login_attempts WHERE login_key=:k',
                                  k=service.key('login', login))[0]['n']
    before = attempts(sysadmin)
    console.script = [f'create-workspace "{ws}"', f'create-team "{team}"', 'no-such-command',
                      'add-team-member "missing team" x', 'create-team', 'exit']
    code, out = run(console, 'session', sysadmin)
    assert code == 0 and attempts(sysadmin) == before + 1
    assert f"Workspace '{ws}' created" in out and f"Team '{team}' created" in out
    assert "error: 'no-such-command' is not available here" in out and 'error: No team' in out
    assert out.count('error:') == 3                                                   # incl. the usage error
    console.script = [f'first-workspace-admin "{ws}" {lead}', f'first-workspace-admin "{ws}" {member}']
    code, out = run(console, 'session', owner)
    assert f"{lead} is the first administrator of '{ws}'" in out and 'already has an administrator' in out
    # Exactly 5: temporary sign-in, the refused enroll above, enroll, two sessions. Without the
    # deliberate refusal the documented order leaves the owner one sign-in for the website.
    assert attempts(owner) == 5
    console.script = [f'add-member "{ws}" {member} participant', f'link-team "{ws}" "{team}"']
    assert 'error' not in run(console, 'session', lead)[1]
    assert run(console, 'add-team-member', sysadmin, team, member)[0] == 0
    code, out = run(console, 'status')
    assert code == 0 and f'{lead}:workspace_admin' in out and f'{member}:participant' in out and f'{sysadmin} system_admin' in out

    # The result is usable: the member signs in on the website and creates a task for the team.
    pre = service.prelogin(ip='198.51.100.151')
    s = service.login(member, PASSWORD, '198.51.100.151', pre['token'], pre['csrf_token'])
    wid = rows(migrator, 'SELECT id FROM task_ayuza.workspaces WHERE name=:n', n=ws)[0]['id']
    tid = rows(migrator, 'SELECT id FROM task_ayuza.teams WHERE name=:n', n=team)[0]['id']
    mid = rows(migrator, 'SELECT id FROM task_ayuza.users WHERE login=:l', l=member)[0]['id']
    task = WorkService(service).create_task(s['token'], s['csrf_token'], wid, 'First real task', mid, tid)
    assert task['id']

    # A forgotten password: reset revokes the sessions and prints a new temporary one.
    code, out = run(console, 'reset-password', member)
    assert code == 0 and len(temporary(out)) == 24
    with pytest.raises(Exception):
        service.me(s['token'])
    # No secret is left in the audit trail.
    audit = str(rows(migrator, 'SELECT * FROM task_ayuza.audit_events'))
    for secret in (PASSWORD, temporary(out), *console.secrets.values()):
        assert secret not in audit


def test_operator_errors_are_reported_not_raised(service):
    console = Console()
    assert run(console, 'create-user', 'x', 'Too short')[1].startswith('error:')
    assert run(console, 'add-member', 'nobody_here', 'No such workspace', 'nobody', 'participant')[1].startswith('error: No workspace')
    assert admin_cli.main(['status'], out=console.out, environ={}) == 2


def test_single_person_first_run_as_in_deploy_readme(service, migrator):
    """deploy/README.md, one person: a daily account and two admin accounts, step by step."""
    console = Console()
    suffix = uuid.uuid4().hex[:6]
    me, owner, adm = f'ivan{suffix}', f'ivan{suffix}-owner', f'ivan{suffix}-admin'
    for login in (me, owner, adm):                                     # step 1
        code, out = run(console, 'create-user', login, 'Ivan')
        assert code == 0
        first_password_change(service, login, temporary(out))          # step 2 (website)
        console.passwords[login] = PASSWORD
    for login in (owner, adm):                                         # step 3
        assert run(console, 'enroll-mfa', login)[0] == 0
    # step 4 already ran once in this suite's database; stand in for it as the earlier tests do
    with migrator.begin() as c:
        for login, role in ((owner, 'system_owner'), (adm, 'access_approver')):
            uid = c.execute(text('SELECT id FROM task_ayuza.users WHERE login=:l'), {'l': login}).scalar_one()
            c.execute(text('''INSERT INTO task_ayuza.system_role_assignments (id, user_id, role_code, reason)
                VALUES (:id, :u, :r, 'synthetic setup')'''), {'id': uuid.uuid4(), 'u': uid, 'r': role})
    ws, team = f'Rabota {suffix}', f'Komanda {suffix}'
    steps = [(owner, [f'grant-role {adm} system_admin']),                                         # step 5
             (adm, [f'create-workspace "{ws}"', f'create-team "{team}"', f'add-team-member "{team}" {me}']),  # 6
             (owner, [f'first-workspace-admin "{ws}" {adm}']),                                    # step 7
             (adm, [f'add-member "{ws}" {me} participant', f'link-team "{ws}" "{team}"'])]        # step 8
    for actor, script in steps:
        console.script = list(script)
        code, out = run(console, 'session', actor)
        assert code == 0 and 'error' not in out, out
    code, out = run(console, 'status')                                                            # step 9
    assert f'{me}:participant' in out and f'{adm}:workspace_admin' in out
    for login in (me, owner, adm):     # nobody is locked out by the 5-per-15-minutes limit
        n = rows(migrator, 'SELECT count(*) AS n FROM task_ayuza.login_attempts WHERE login_key=:k',
                 k=service.key('login', login))[0]['n']
        assert n <= 4, (login, n)
    pre = service.prelogin(ip='198.51.100.152')
    s = service.login(me, PASSWORD, '198.51.100.152', pre['token'], pre['csrf_token'])
    wid = rows(migrator, 'SELECT id FROM task_ayuza.workspaces WHERE name=:n', n=ws)[0]['id']
    tid = rows(migrator, 'SELECT id FROM task_ayuza.teams WHERE name=:n', n=team)[0]['id']
    mid = rows(migrator, 'SELECT id FROM task_ayuza.users WHERE login=:l', l=me)[0]['id']
    assert WorkService(service).create_task(s['token'], s['csrf_token'], wid, 'Solo task', mid, tid)['id']


class QuickConsole(Console):
    """Like Console, but the person is named in every prompt, and each account has its own password."""
    def __init__(self):
        super().__init__()
        self.secret_prompts, self.mismatch = [], 0

    def password(self, login):
        return f'{PASSWORD}-{login}'

    def out(self, line):
        found = re.match(r'Add (\S+) to an authenticator app', str(line))
        if found:
            self.current = found.group(1)
        super().out(line)

    def ask_secret(self, prompt):
        self.secret_prompts.append(prompt)
        self.current = re.search(r'for (\S+?)(?: \(|: )', prompt).group(1)
        if self.mismatch and prompt.startswith('Repeat'):
            self.mismatch -= 1
            return 'not the same password'
        return self.password(self.current)

    def ask(self, prompt):
        if not prompt.endswith('> '):
            self.current = re.search(r'for (\S+?)(?: to confirm)?: ', prompt).group(1)
        return super().ask(prompt)


def test_quickstart_one_person_in_one_command(service, migrator):
    """deploy/README.md quickstart: same services and checks as the single commands, resumable."""
    console = QuickConsole()
    console.mismatch = 1
    suffix = uuid.uuid4().hex[:6]
    me, owner, adm = f'ivan{suffix}', f'ivan{suffix}-owner', f'ivan{suffix}-admin'
    ws, team = f'Работа {suffix}', f'Команда {suffix}'
    argv = ('quickstart', 'Synthetic', '--login', me, '--name', 'Ivan', '--workspace', ws, '--team', team)
    # An interrupted earlier attempt left the daily account with a temporary password.
    assert run(console, 'create-user', me, 'Ivan')[0] == 0

    # This suite's one-time setup belongs to other people: quickstart stops there and says so.
    code, out = run(console, *argv)
    assert code == 1 and 'Setup was completed for other accounts' in out, out
    assert f'User {me} still had a temporary password; it was replaced.' in out
    assert 'error: the passwords do not match' in out
    assert 'shown once' not in out and 'Temporary password' not in out      # never printed
    users = {r['login']: r for r in rows(migrator, '''SELECT u.login, u.must_change_password,
        m.enabled_at IS NOT NULL AS mfa FROM task_ayuza.users u LEFT JOIN task_ayuza.user_mfa m ON m.user_id=u.id
        WHERE u.login IN (:a, :b, :c)''', a=me, b=owner, c=adm)}
    assert all(not u['must_change_password'] for u in users.values()) and len(users) == 3
    assert not users[me]['mfa'] and users[owner]['mfa'] and users[adm]['mfa']

    # Stand in for the one-time setup, as the tests above do; the rerun continues from here.
    with migrator.begin() as c:
        for login, role in ((owner, 'system_owner'), (adm, 'access_approver')):
            uid = c.execute(text('SELECT id FROM task_ayuza.users WHERE login=:l'), {'l': login}).scalar_one()
            c.execute(text('''INSERT INTO task_ayuza.system_role_assignments (id, user_id, role_code, reason)
                VALUES (:id, :u, :r, 'synthetic setup')'''), {'id': uuid.uuid4(), 'u': uid, 'r': role})
    code, out = run(console, *argv)
    assert code == 0 and 'error' not in out, out
    assert f'User {owner} already exists; password unchanged.' in out and f'MFA is already enabled for {adm}' in out
    assert 'Setup is already completed.' in out and f'{adm} now has system_admin' in out
    assert f'{me}:participant' in out and f'{adm}:workspace_admin' in out and f'{adm} access_approver,system_admin' in out
    assert f"Team '{team}' works in '{ws}'" in out

    # Nothing left to do: a third run changes nothing and asks for no password or code.
    prompts = len(console.secret_prompts)
    code, out = run(console, *argv)
    assert code == 0 and 'error' not in out and len(console.secret_prompts) == prompts
    assert out.count('already') >= 7 and 'created' not in out

    for login in (me, owner, adm):     # nobody is locked out by the 5-per-15-minutes limit
        n = rows(migrator, 'SELECT count(*) AS n FROM task_ayuza.login_attempts WHERE login_key=:k',
                 k=service.key('login', login))[0]['n']
        assert n <= 4, (login, n)
    # The rules still hold: the owner cannot make themselves a workspace administrator.
    console.script = [f'first-workspace-admin "{ws}" {owner}']
    assert 'error' in run(console, 'session', owner)[1]
    # The daily account works on the website.
    pre = service.prelogin(ip='198.51.100.153')
    s = service.login(me, console.password(me), '198.51.100.153', pre['token'], pre['csrf_token'])
    wid = rows(migrator, 'SELECT id FROM task_ayuza.workspaces WHERE name=:n', n=ws)[0]['id']
    tid = rows(migrator, 'SELECT id FROM task_ayuza.teams WHERE name=:n', n=team)[0]['id']
    mid = rows(migrator, 'SELECT id FROM task_ayuza.users WHERE login=:l', l=me)[0]['id']
    assert WorkService(service).create_task(s['token'], s['csrf_token'], wid, 'Quickstart task', mid, tid)['id']
    audit = str(rows(migrator, 'SELECT * FROM task_ayuza.audit_events'))
    for secret in (*(console.password(x) for x in (me, owner, adm)), *console.secrets.values()):
        assert secret not in audit
