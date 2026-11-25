"""Operator commands for a Task-Ayuza installation (no web administration exists yet).

Run inside the deployment (deploy/admin.ps1) with the runtime and migrator database URLs and the
HMAC and MFA keys in the environment. Every change goes through the application services with
their checks: a real session (the acting person types their password), CSRF, a fresh MFA code for
administrative changes, and audit in the same transaction. Only the organization row and the
one-time setup use the migrator role directly, as backend/setup.py intends. Secrets (temporary
passwords, MFA keys and backup codes) are printed once and never stored or logged.

  init-org NAME                         create the single organization (once)
  create-user LOGIN "DISPLAY NAME"      new account with a 24-hour temporary password
  reset-password LOGIN                  new temporary password, all sessions revoked
  enroll-mfa LOGIN                      connect an authenticator app (after the first password change)
  setup OWNER APPROVER                  one-time: system owner and a second, different approver
  grant-role ACTOR TARGET ROLE          system_owner ACTOR gives system_admin / risk_controller / access_approver
  create-workspace ACTOR NAME [--timezone TZ]   system_admin ACTOR
  create-team ACTOR NAME                system_admin ACTOR
  first-workspace-admin ACTOR WORKSPACE TARGET  system_owner ACTOR, only while the workspace has no admin
  add-member ACTOR WORKSPACE TARGET ROLE        workspace_admin ACTOR; ROLE participant|observer|workspace_admin
  link-team ACTOR WORKSPACE TEAM        workspace_admin ACTOR allows TEAM in WORKSPACE
  add-team-member ACTOR TEAM TARGET     system_admin ACTOR
  status                                organization, people, roles, workspaces, teams
  session ACTOR                         sign in once, then run several ACTOR commands without the actor
                                        (each sign-in counts against the 5-per-15-minutes login limit)
  quickstart ORG [--login ivan] [--name NAME] [--workspace Работа] [--team Команда]
                                        one person, first run: the commands above in the documented order
                                        for LOGIN, LOGIN-owner and LOGIN-admin; asks for each permanent
                                        password and MFA code, never shows a temporary password, skips what
                                        is already done (safe to run again after an interruption)
"""
from __future__ import annotations

import argparse
import getpass
import os
import shlex
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from backend.acl import AclError, AclService  # noqa: E402
from backend.audit import OrganizationAlreadyExistsError, create_organization  # noqa: E402
from backend.auth import AuthError, AuthService  # noqa: E402
from backend.grants import ASSIGNABLE_ROLES, GrantService  # noqa: E402
from backend.mfa import MfaService  # noqa: E402
from backend.passwords import normalize_login, validate_password  # noqa: E402
from backend.setup import SetupError, complete_setup  # noqa: E402

OPERATOR_IP = '127.0.0.1'   # the limiter still applies: 5 attempts per login, 100 per address
MFA_REVERIFY_SECONDS = 14 * 60   # backend accepts an MFA check for 15 minutes
ACTOR_COMMANDS = ('grant-role', 'create-workspace', 'create-team', 'first-workspace-admin', 'add-member',
                  'link-team', 'add-team-member')


class OperatorError(RuntimeError):
    pass


class Admin:
    def __init__(self, runtime_url, migrator_url, hmac_key, mfa_key, ask_secret, ask, out):
        self.runtime = create_engine(runtime_url, hide_parameters=True)
        self.migrator_url = migrator_url
        self.auth = AuthService(self.runtime, hmac_key)
        self.acl = AclService(self.auth)
        self.grants = GrantService(self.auth)
        self.mfa = MfaService(self.auth, mfa_key)
        self.ask_secret, self.ask, self.out = ask_secret, ask, out
        self.sessions = {}   # login -> session, reused within one run only (never written to disk)

    # ---- helpers ----

    def migrator(self):
        if not self.migrator_url:
            raise OperatorError('TASK_AYUZA_MIGRATOR_URL is not set')
        return create_engine(self.migrator_url, hide_parameters=True)

    def scalar(self, sql, **params):
        with self.runtime.connect() as c:
            return c.execute(text(sql), params).scalar_one_or_none()

    def user_id(self, login):
        uid = self.scalar('SELECT id FROM task_ayuza.users WHERE login_normalized=:l', l=normalize_login(login))
        if uid is None:
            raise OperatorError(f'No user {login!r}')
        return uid

    LIVE = {'workspaces': 'archived_at IS NULL', 'teams': 'active'}  # constant SQL, never user input

    def named(self, table, name):
        with self.runtime.connect() as c:
            ids = c.execute(text(f'SELECT id FROM task_ayuza.{table} WHERE name=:n AND {self.LIVE[table]}'),
                            {'n': name}).scalars().all()
        if len(ids) != 1:
            raise OperatorError(f'{"No" if not ids else "More than one"} {table[:-1]} named {name!r}')
        return ids[0]

    def organization(self):
        org = self.scalar('SELECT id FROM task_ayuza.organization')
        if org is None:
            raise OperatorError('No organization yet: run init-org first')
        return org

    def sign_in(self, login, *, mfa=True):
        """A real session for the acting person; administrative changes also need their MFA code.
        Within one run the session is reused, so `session` costs one login attempt."""
        key = normalize_login(login)
        session = self.sessions.get(key)
        if session is not None:
            try:
                self.auth.me(session['token'])
            except AuthError:  # expired or revoked: sign in again
                del self.sessions[key]
                session = None
        if session is None:
            password = self.ask_secret(f'Password for {login}: ')
            pre = self.auth.prelogin(ip=OPERATOR_IP)
            session = self.auth.login(login, password, OPERATOR_IP, pre['token'], pre['csrf_token'])
            if session['kind'] != 'normal':
                raise OperatorError(f'{login} still has a temporary password: sign in on the website and change it first')
            session['mfa_at'] = None
            self.sessions[key] = session
        if mfa and (session['mfa_at'] is None or time.monotonic() - session['mfa_at'] > MFA_REVERIFY_SECONDS):
            self.mfa.verify(session['token'], session['csrf_token'], self.ask(f'MFA code for {login}: '))
            session['mfa_at'] = time.monotonic()
        return session

    def session(self, actor):
        self.sign_in(actor)
        self.out(f'Signed in as {actor}. Type commands without the actor, e.g.: create-team Sales')
        self.out(f'Available: {", ".join(ACTOR_COMMANDS)}, status, exit')
        while True:
            try:
                line = self.ask(f'{actor}> ')
            except EOFError:
                break
            try:
                words = shlex.split(line)
            except ValueError as error:
                self.out(f'error: {error}')
                continue
            if not words:
                continue
            if words[0] in ('exit', 'quit'):
                break
            if words[0] not in ACTOR_COMMANDS + ('status',):
                self.out(f'error: {words[0]!r} is not available here')
                continue
            dispatch(self, [words[0], actor, *words[1:]] if words[0] in ACTOR_COMMANDS else words)

    # ---- commands ----

    def init_org(self, name):
        engine = self.migrator()
        try:
            with Session(engine) as session, session.begin():
                org = create_organization(session, name=name, request_id=uuid.uuid4())
                self.out(f'Organization created: {org.id}')
        except OrganizationAlreadyExistsError:
            self.out('Organization already exists; nothing changed.')
        finally:
            engine.dispose()

    def create_user(self, login, display_name):
        uid, password = self.auth.create_user(self.organization(), login, display_name)
        self.out(f'User {normalize_login(login)} created ({uid}).')
        self.out(f'Temporary password (valid 24 hours, shown once): {password}')
        self.out('Sign in on the website with it; you will be asked to choose a permanent password.')

    def reset_password(self, login):
        password = self.auth.reset_password(self.user_id(login))
        self.out(f'All sessions of {login} are revoked. Temporary password (24 hours, shown once): {password}')

    def enroll_mfa(self, login):
        session = self.sign_in(login, mfa=False)
        enrolled = self.mfa.enroll(session['token'], session['csrf_token'])
        self.out(f'Add {normalize_login(login)} to an authenticator app (Yandex Key, Google Authenticator, ...):')
        self.out(f'  setup key: {enrolled["secret"]}')
        self.out(f'  or link:   {enrolled["otpauth_uri"]}')
        self.out('Backup codes, each usable once. Keep them offline:')
        for code in enrolled['backup_codes']:
            self.out(f'  {code}')
        self.mfa.confirm(session['token'], session['csrf_token'], self.ask(f'Code from the app for {login} to confirm: '))
        session['mfa_at'] = time.monotonic()   # confirming also verifies this session
        self.out(f'MFA is enabled for {login}.')

    def setup(self, owner, approver):
        owner_id, approver_id = self.user_id(owner), self.user_id(approver)
        engine = self.migrator()
        try:
            with engine.begin() as c:
                complete_setup(c, owner_id, [approver_id])
        finally:
            engine.dispose()
        self.out(f'Setup completed: {owner} is system_owner, {approver} is access_approver.')

    def grant_role(self, actor, target, role):
        if role not in ASSIGNABLE_ROLES:
            raise OperatorError(f'Role must be one of {", ".join(sorted(ASSIGNABLE_ROLES))}')
        target_id = self.user_id(target)
        s = self.sign_in(actor)
        self.grants.grant_system_role(s['token'], s['csrf_token'], target_id, role, f'granted by operator command: {actor}')
        self.out(f'{target} now has {role}.')

    def create_workspace(self, actor, name, timezone):
        s = self.sign_in(actor)
        created = self.acl.create_workspace(s['token'], s['csrf_token'], name, timezone)
        self.out(f'Workspace {name!r} created ({created["id"]}).')

    def create_team(self, actor, name):
        s = self.sign_in(actor)
        created = self.acl.create_team(s['token'], s['csrf_token'], name)
        self.out(f'Team {name!r} created ({created["id"]}).')

    def first_workspace_admin(self, actor, workspace, target):
        wid, target_id = self.named('workspaces', workspace), self.user_id(target)
        s = self.sign_in(actor)
        self.grants.bootstrap_workspace_admin(s['token'], s['csrf_token'], wid, target_id)
        self.out(f'{target} is the first administrator of {workspace!r}.')

    def add_member(self, actor, workspace, target, role):
        wid, target_id = self.named('workspaces', workspace), self.user_id(target)
        s = self.sign_in(actor)
        self.acl.set_workspace_member(s['token'], s['csrf_token'], wid, target_id, role)
        self.out(f'{target} is {role} in {workspace!r}.')

    def link_team(self, actor, workspace, team):
        wid, tid = self.named('workspaces', workspace), self.named('teams', team)
        s = self.sign_in(actor)
        self.acl.set_workspace_team(s['token'], s['csrf_token'], wid, tid)
        self.out(f'Team {team!r} works in {workspace!r}.')

    def add_team_member(self, actor, team, target):
        tid, target_id = self.named('teams', team), self.user_id(target)
        s = self.sign_in(actor)
        self.acl.set_team_member(s['token'], s['csrf_token'], tid, target_id)
        self.out(f'{target} is in team {team!r}.')

    # ---- quickstart: one person, first run ----

    def exists(self, sql, **params):
        with self.runtime.connect() as c:
            return c.execute(text(sql), params).first() is not None

    def ask_new_password(self, login):
        while True:
            password = self.ask_secret(f'New permanent password for {login} (15-128 characters): ')
            if password != self.ask_secret(f'Repeat the password for {login}: '):
                self.out('error: the passwords do not match, try again')
                continue
            try:
                validate_password(password)
            except ValueError as error:
                self.out(f'error: {error}')
                continue
            return password

    def first_password(self, login, display_name, *, keep_session):
        """Account with a permanent password chosen by the person. The temporary password stays
        inside this process: it is used for the one sign-in that changes it and is never shown."""
        key = normalize_login(login)
        with self.runtime.connect() as c:
            row = c.execute(text('SELECT id, must_change_password FROM task_ayuza.users WHERE login_normalized=:l'),
                            {'l': key}).first()
        if row is None:
            _, temporary = self.auth.create_user(self.organization(), login, display_name)
            self.out(f'User {key} created.')
        elif row.must_change_password:   # an earlier run stopped before the change: a fresh temporary one
            temporary = self.auth.reset_password(row.id)
            self.out(f'User {key} still had a temporary password; it was replaced.')
        else:
            self.out(f'User {key} already exists; password unchanged.')
            return
        # Ask first: the password-change session lives 10 minutes, and a person may take longer to choose.
        password = self.ask_new_password(key)
        pre = self.auth.prelogin(ip=OPERATOR_IP)
        s = self.auth.login(login, temporary, OPERATOR_IP, pre['token'], pre['csrf_token'])
        del temporary
        self.auth.change_password(s['token'], s['csrf_token'], password)   # revokes every session of the user
        if keep_session:   # the next commands act as this account: one sign-in now instead of a prompt
            pre = self.auth.prelogin(ip=OPERATOR_IP)
            s = self.auth.login(login, password, OPERATOR_IP, pre['token'], pre['csrf_token'])
            s['mfa_at'] = None
            self.sessions[key] = s
        del password
        self.out(f'Permanent password set for {key}.')

    def quickstart(self, org, login, name, workspace, team):
        """deploy/README.md for one person, in one run. Every change goes through the same services
        as the single commands: no rule is skipped, only the typing is."""
        me = normalize_login(login)
        owner, adm = f'{me}-owner', f'{me}-admin'
        name = name or me
        self.out(f'Quickstart for one person: {me} (daily work), {owner} (system owner), {adm} (administrator).')
        self.out('Use a different password for each account and keep them in a password manager.')
        self.init_org(org)
        for who, title, keep in ((me, name, False), (owner, f'{name} (owner)', True), (adm, f'{name} (admin)', True)):
            self.first_password(who, title, keep_session=keep)
        for who in (owner, adm):
            if self.exists('''SELECT 1 FROM task_ayuza.user_mfa m JOIN task_ayuza.users u ON u.id=m.user_id
                    WHERE u.login_normalized=:l AND m.enabled_at IS NOT NULL''', l=who):
                self.out(f'MFA is already enabled for {who}.')
            else:
                self.enroll_mfa(who)
        has_role = lambda who, code: self.exists('''SELECT 1 FROM task_ayuza.system_role_assignments r
            JOIN task_ayuza.users u ON u.id=r.user_id
            WHERE u.login_normalized=:l AND r.role_code=:r AND r.revoked_at IS NULL''', l=who, r=code)
        if not self.exists('SELECT 1 FROM task_ayuza.setup_state WHERE completed_at IS NOT NULL'):
            self.setup(owner, adm)
        elif has_role(owner, 'system_owner') and has_role(adm, 'access_approver'):
            self.out('Setup is already completed.')
        else:
            raise OperatorError('Setup was completed for other accounts: continue with the single commands')
        if has_role(adm, 'system_admin'):
            self.out(f'{adm} already has system_admin.')
        else:
            self.grant_role(owner, adm, 'system_admin')
        if self.exists('SELECT 1 FROM task_ayuza.workspaces WHERE name=:n AND archived_at IS NULL', n=workspace):
            self.out(f'Workspace {workspace!r} already exists.')
        else:
            self.create_workspace(adm, workspace, 'Europe/Moscow')
        if self.exists('SELECT 1 FROM task_ayuza.teams WHERE name=:n AND active', n=team):
            self.out(f'Team {team!r} already exists.')
        else:
            self.create_team(adm, team)
        wid, tid, my_id = self.named('workspaces', workspace), self.named('teams', team), self.user_id(me)
        if not self.exists('SELECT 1 FROM task_ayuza.team_members WHERE team_id=:t AND user_id=:u AND active',
                           t=tid, u=my_id):
            self.add_team_member(adm, team, me)
        if not self.exists('''SELECT 1 FROM task_ayuza.workspace_members
                WHERE workspace_id=:w AND role='workspace_admin' AND active''', w=wid):
            self.first_workspace_admin(owner, workspace, adm)
        if not self.exists('SELECT 1 FROM task_ayuza.workspace_members WHERE workspace_id=:w AND user_id=:u AND active',
                           w=wid, u=my_id):
            self.add_member(adm, workspace, me, 'participant')
        if not self.exists('SELECT 1 FROM task_ayuza.workspace_teams WHERE workspace_id=:w AND team_id=:t AND active',
                           w=wid, t=tid):
            self.link_team(adm, workspace, team)
        self.status()
        self.out(f'Done. Work on the website as {me}; use {owner} and {adm} only for administration.')

    def status(self):
        with self.runtime.connect() as c:
            q = lambda sql: c.execute(text(sql)).mappings().all()
            org = q('SELECT name FROM task_ayuza.organization')
            self.out(f'Organization: {org[0]["name"] if org else "(none)"}')
            for u in q('''SELECT u.login, u.active, u.must_change_password,
                    (SELECT string_agg(role_code, ',' ORDER BY role_code) FROM task_ayuza.system_role_assignments r
                     WHERE r.user_id=u.id AND r.revoked_at IS NULL) AS roles
                    FROM task_ayuza.users u ORDER BY u.login'''):
                flags = ('' if u['active'] else ' inactive') + (' temporary-password' if u['must_change_password'] else '')
                self.out(f'  user {u["login"]}{flags} {u["roles"] or ""}'.rstrip())
            for w in q('''SELECT w.name, (SELECT string_agg(u.login || ':' || m.role, ', ' ORDER BY u.login)
                    FROM task_ayuza.workspace_members m JOIN task_ayuza.users u ON u.id=m.user_id
                    WHERE m.workspace_id=w.id AND m.active) AS members
                    FROM task_ayuza.workspaces w WHERE w.archived_at IS NULL ORDER BY w.name'''):
                self.out(f'  workspace {w["name"]!r}: {w["members"] or "(no members)"}')
            for t in q('SELECT name FROM task_ayuza.teams WHERE active ORDER BY name'):
                self.out(f'  team {t["name"]!r}')


def parser(cls=argparse.ArgumentParser):
    p = cls(prog='admin', description=__doc__.split('\n\n')[0])
    sub = p.add_subparsers(dest='command', required=True)
    for name, args in [('init-org', ['name']), ('create-user', ['login', 'display_name']),
                       ('reset-password', ['login']), ('enroll-mfa', ['login']), ('setup', ['owner', 'approver']),
                       ('grant-role', ['actor', 'target', 'role']), ('create-team', ['actor', 'name']),
                       ('first-workspace-admin', ['actor', 'workspace', 'target']),
                       ('add-member', ['actor', 'workspace', 'target', 'role']),
                       ('link-team', ['actor', 'workspace', 'team']), ('add-team-member', ['actor', 'team', 'target']),
                       ('status', []), ('session', ['actor'])]:
        sp = sub.add_parser(name)
        for a in args:
            sp.add_argument(a)
    sp = sub.add_parser('quickstart')
    sp.add_argument('org')
    sp.add_argument('--login', default='ivan')
    sp.add_argument('--name', default='')
    sp.add_argument('--workspace', default='Работа')
    sp.add_argument('--team', default='Команда')
    sp = sub.add_parser('create-workspace')
    sp.add_argument('actor')
    sp.add_argument('name')
    sp.add_argument('--timezone', default='Europe/Moscow')
    return p


class _Usage(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # inside `session` a typo must not end the run
        raise _Usage(message)


def dispatch(admin, argv):
    try:
        args = parser(_Parser).parse_args(argv)
    except _Usage as error:
        admin.out(f'error: {error}')
        return 2
    params = {k: v for k, v in vars(args).items() if k != 'command'}
    try:
        getattr(admin, args.command.replace('-', '_'))(**params)
        return 0
    except (AuthError, AclError) as error:
        admin.out(f'error: {error.message} ({error.status})')
    except (OperatorError, SetupError, ValueError) as error:
        admin.out(f'error: {error}')
    return 1


def main(argv=None, *, ask_secret=getpass.getpass, ask=input, out=print, environ=os.environ):
    parser().parse_args(argv)  # usage errors and --help exit here, before any connection
    try:
        admin = Admin(environ['TASK_AYUZA_DATABASE_URL'], environ.get('TASK_AYUZA_MIGRATOR_URL', ''),
                      bytes.fromhex(environ['TASK_AYUZA_AUTH_HMAC_KEY']), bytes.fromhex(environ['TASK_AYUZA_MFA_KEY']),
                      ask_secret, ask, out)
    except (KeyError, ValueError):
        out('error: the database URL, HMAC key and MFA key must be configured')
        return 2
    try:
        return dispatch(admin, argv)
    finally:
        admin.runtime.dispose()


if __name__ == '__main__':
    sys.exit(main())
