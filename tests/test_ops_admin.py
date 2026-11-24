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
