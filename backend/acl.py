"""M01.3 internal ACL service: workspaces, teams, memberships, team access (D01/D02).

Closed service layer: no HTTP routes, no public CRUD. Every call is authenticated through
AuthService.protected, so the session is verified and the user and session rows are locked
first. ACL rows follow in a fixed table order: workspace_members, team_members, teams,
workspace_teams, workspace_team_access. Access checks take FOR SHARE locks that are held until
commit, so a revocation that commits first rejects the next protected operation, and an
operation already past its check completes before the revocation can commit. Deadlock and
serialization failures are retried by AuthService.transaction (at most two retries); the
audit event is written in the same transaction, so a retry never duplicates it.

M01.4 adds MFA for administrative mutations and administrative grants (backend/grants.py).
Still open: delegation of assign, archive_restore, manage_access and export through
workspace_team_access, bootstrap of the first workspace administrator, project/task ACL.
"""
from __future__ import annotations

import json
import uuid

from sqlalchemy.exc import IntegrityError

from backend.auth import AuthService, execute, one
from backend.mfa import mfa_fresh

CAPABILITIES = frozenset({'read', 'comment', 'content_edit', 'link', 'assign',
                          'archive_restore', 'manage_access', 'export'})
GRANT_CAPABILITIES = CAPABILITIES | {'audit_read'}
# Capabilities a workspace administrator may hand to a team member in M01.3.
DELEGABLE = frozenset({'read', 'comment', 'content_edit', 'link'})
WORKSPACE_ROLES = frozenset({'participant', 'observer', 'workspace_admin'})
SNAPSHOT_FIELDS = frozenset({'name', 'role', 'active', 'capability', 'timezone', 'revoked',
                             'kind', 'expires_at', 'role_code',
                             # M02.1 work objects: identifiers and enums only, never titles or text
                             'status', 'priority', 'archived', 'project_id', 'owner_user_id',
                             'result_owner_user_id', 'executor_team_id', 'assignee_user_id', 'fields',
                             'parent_task_id', 'stage_id', 'label_id', 'checked', 'deleted', 'hidden', 'position',
                             'user_id'})


class AclError(Exception):
    """Safe service error. 404 is identical for hidden and nonexistent objects."""

    def __init__(self, status: int, message: str):
        self.status = status
        self.message = message
        super().__init__(message)


def _not_found() -> AclError:
    return AclError(404, 'Not found')


def _forbidden() -> AclError:
    return AclError(403, 'Operation not permitted')


def as_uuid(value) -> uuid.UUID:
    if isinstance(value, uuid.UUID):
        return value
    if not isinstance(value, str) or len(value) != 36:
        raise AclError(422, 'Invalid identifier')
    try:
        return uuid.UUID(value)
    except ValueError:
        raise AclError(422, 'Invalid identifier') from None


def clean_text(value, limit: int = 200) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise AclError(422, 'Invalid value')
    return value


def check_version(value):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise AclError(422, 'Invalid version')
    return value


def _snapshot(values):
    if values is None:
        return None
    if not isinstance(values, dict) or not values or set(values) - SNAPSHOT_FIELDS:
        raise ValueError('Disallowed audit snapshot fields')
    return json.dumps(values, ensure_ascii=False, sort_keys=True, default=str)


def audit(c, u, s, *, request_id, entity_kind, entity_id, action, workspace_id=None, old=None, new=None):
    """Same-transaction audit event with allowlisted snapshots only (no reasons, secrets, tokens)."""
    execute(c, '''INSERT INTO task_ayuza.audit_events
        (id, actor_kind, actor_id, session_id, workspace_id, entity_kind, entity_id, action, request_id, "old", "new")
        VALUES (:id, 'user', :actor, :session, :ws, :kind, :entity, :action, :request,
                CAST(:old AS jsonb), CAST(:new AS jsonb))''',
            id=uuid.uuid4(), actor=u['id'], session=s['id'], ws=workspace_id, kind=entity_kind,
            entity=entity_id, action=action, request=request_id, old=_snapshot(old), new=_snapshot(new))


# ---- authorization primitives (call inside an AuthService.protected transaction) ----

def has_system_role(c, user_id, role) -> bool:
    """Plain read inside the caller's transaction (no row lock).

    System roles gate structure creation and access approval, never workspace content.
    """
    return execute(c, '''SELECT 1 FROM task_ayuza.system_role_assignments
        WHERE user_id=:u AND role_code=:r AND revoked_at IS NULL''',
                   u=user_id, r=role).first() is not None


def membership(c, user_id, workspace_id):
    """Active workspace membership, share-locked; None hides absent and inactive alike."""
    return one(c, '''SELECT id, role, version FROM task_ayuza.workspace_members
        WHERE workspace_id=:w AND user_id=:u AND active FOR SHARE''', w=workspace_id, u=user_id)


def has_capability(c, user_id, workspace_id, capability) -> bool:
    """D01/D02 check for one workspace and capability, with no administrator bypass.

    Requires an active workspace membership, an active team membership, an active team
    explicitly allowed in the workspace, and an unrevoked workspace_team_access row for
    exactly this capability. Observers only ever hold read.
    """
    if capability not in CAPABILITIES:
        raise ValueError('Unknown capability')
    member = membership(c, user_id, workspace_id)
    if member is None or (member['role'] == 'observer' and capability != 'read'):
        return False
    teams = execute(c, '''SELECT team_id FROM task_ayuza.workspace_team_access
        WHERE workspace_id=:w AND user_id=:u AND capability=:cap AND revoked_at IS NULL
        ORDER BY team_id''', w=workspace_id, u=user_id, cap=capability).scalars().all()
    steps = (
        'SELECT team_id FROM task_ayuza.team_members '
        'WHERE user_id=:u AND team_id = ANY(CAST(:teams AS uuid[])) AND active ORDER BY id FOR SHARE',
        'SELECT id FROM task_ayuza.teams '
        'WHERE id = ANY(CAST(:teams AS uuid[])) AND active ORDER BY id FOR SHARE',
        'SELECT team_id FROM task_ayuza.workspace_teams '
        'WHERE workspace_id=:w AND team_id = ANY(CAST(:teams AS uuid[])) AND active ORDER BY id FOR SHARE',
    )
    for sql in steps:
        if not teams:
            return False
        params = {'u': user_id, 'w': workspace_id, 'teams': teams}
        teams = execute(c, sql, **{k: v for k, v in params.items() if f':{k}' in sql}).scalars().all()
    if not teams:
        return False
    return execute(c, '''SELECT id FROM task_ayuza.workspace_team_access
        WHERE workspace_id=:w AND user_id=:u AND capability=:cap AND revoked_at IS NULL
          AND team_id = ANY(CAST(:teams AS uuid[])) ORDER BY id FOR SHARE''',
                   w=workspace_id, u=user_id, cap=capability, teams=teams).first() is not None


def grant_capability(c, user_id, workspace_id, capability) -> bool:
    """Active administrative grant (D03) for exactly this workspace and capability, share-locked.

    Time is the database clock at check time: expired and revoked grants never apply.
    """
    return execute(c, '''SELECT id FROM task_ayuza.administrative_grants
        WHERE grantee_user_id=:u AND workspace_id=:w AND capability=:cap AND revoked_at IS NULL
          AND valid_from <= clock_timestamp() AND expires_at > clock_timestamp()
        ORDER BY id FOR SHARE''', u=user_id, w=workspace_id, cap=capability).first() is not None


def require_member(c, user_id, workspace_id):
    member = membership(c, user_id, workspace_id)
    if member is None:
        raise _not_found()
    return member


def require_workspace_admin(c, user_id, workspace_id):
    member = require_member(c, user_id, workspace_id)
    if member['role'] != 'workspace_admin':
        raise _forbidden()
    return member


def require_system_admin(c, user_id):
    if not has_system_role(c, user_id, 'system_admin'):
        raise _forbidden()


def _target_user(c, actor, user_id, *, require_active):
    target = one(c, 'SELECT id, organization_id, active FROM task_ayuza.users WHERE id=:id', id=user_id)
    if target is None or target['organization_id'] != actor['organization_id']:
        raise _not_found()
    if require_active and not target['active']:
        raise AclError(422, 'Target user is inactive')


def _reject_self(actor, user_id):
    if user_id == actor['id']:
        raise _forbidden()  # no self-grant, including indirect membership changes


def _upsert(c, u, s, *, table, keys, values, entity_kind, actions, workspace_id, expected, request_id):
    """Idempotent create/update with optimistic version. Table and column names are constants."""
    where = ' AND '.join(f'{k}=:k_{k}' for k in keys)
    key_params = {f'k_{k}': v for k, v in keys.items()}
    lookup = f'SELECT * FROM task_ayuza.{table} WHERE {where} FOR UPDATE'
    row = one(c, lookup, **key_params)
    if row is None:
        if expected is not None:
            raise AclError(409, 'Version conflict')
        columns = ['id', *keys, *values]
        placeholders = ', '.join(f':c_{name}' for name in columns)
        params = {f'c_{name}': value for name, value in {**keys, **values}.items()}
        inserted = one(c, f'''INSERT INTO task_ayuza.{table} ({', '.join(columns)})
            VALUES ({placeholders}) ON CONFLICT ({', '.join(keys)}) DO NOTHING
            RETURNING id, version''', c_id=uuid.uuid4(), **params)
        if inserted is not None:
            audit(c, u, s, request_id=request_id, entity_kind=entity_kind, entity_id=inserted['id'],
                  action=actions[0], workspace_id=workspace_id, old=None, new=dict(values))
            return {'id': inserted['id'], 'version': inserted['version'], 'created': True}
        row = one(c, lookup, **key_params)  # a concurrent insert won; treat as existing
        if row is None:
            raise AclError(409, 'Version conflict')
    if all(row[name] == value for name, value in values.items()):
        return {'id': row['id'], 'version': row['version'], 'created': False}
    if expected is None or expected != row['version']:
        raise AclError(409, 'Version conflict')
    assignments = ', '.join(f'{name}=:v_{name}' for name in values)
    updated = one(c, f'''UPDATE task_ayuza.{table} SET {assignments}, version=version+1,
        updated_at=clock_timestamp() WHERE id=:id AND version=:version RETURNING id, version''',
                  id=row['id'], version=expected, **{f'v_{name}': value for name, value in values.items()})
    if updated is None:
        raise AclError(409, 'Version conflict')
    audit(c, u, s, request_id=request_id, entity_kind=entity_kind, entity_id=row['id'],
          action=actions[1], workspace_id=workspace_id,
          old={name: row[name] for name in values}, new=dict(values))
    return {'id': updated['id'], 'version': updated['version'], 'created': False}


def _team_member(c, u, s, team, target, active, expected, request_id):
    """Team membership change by a system administrator (inside mfa_mutation)."""
    require_system_admin(c, u['id'])
    _reject_self(u, target)  # a system administrator cannot join a team to reach data
    if one(c, 'SELECT 1 AS x FROM task_ayuza.teams WHERE id=:id AND organization_id=:org',
           id=team, org=u['organization_id']) is None:
        raise _not_found()
    _target_user(c, u, target, require_active=active)
    return _upsert(c, u, s, table='team_members', keys={'team_id': team, 'user_id': target},
                   values={'active': active}, entity_kind='team_member',
                   actions=('acl.team_member_added', 'acl.team_member_changed'),
                   workspace_id=None, expected=expected, request_id=request_id)


def _workspace_member(c, u, s, wid, target, role, active, expected, request_id):
    """Workspace membership change by that workspace's administrator (inside mfa_mutation)."""
    require_workspace_admin(c, u['id'], wid)
    _reject_self(u, target)
    _target_user(c, u, target, require_active=active)
    return _upsert(c, u, s, table='workspace_members', keys={'workspace_id': wid, 'user_id': target},
                   values={'role': role, 'active': active}, entity_kind='workspace_member',
                   actions=('acl.workspace_member_added', 'acl.workspace_member_changed'),
                   workspace_id=wid, expected=expected, request_id=request_id)


def mfa_mutation(auth: AuthService, token, csrf, run):
    """Administrative mutation: valid session, CSRF and a fresh MFA verification (D03)."""
    def guarded(c, u, s):
        if not mfa_fresh(c, s):
            raise AclError(403, 'MFA required')
        return run(c, u, s)
    return auth.protected(token, guarded, csrf=csrf, mutation=True)


class AclService:
    def __init__(self, auth: AuthService):
        self.auth = auth

    def _mutation(self, token, csrf, run):
        return mfa_mutation(self.auth, token, csrf, run)

    # ---- generic hook for future objects (M02): capability-checked transaction ----

    def run_protected(self, token, workspace_id, capability, operation, *, csrf=None, mutation=False):
        wid = as_uuid(workspace_id)
        if capability not in CAPABILITIES:
            raise AclError(422, 'Invalid capability')

        def run(c, u, s):
            member = membership(c, u['id'], wid)
            if member is not None and has_capability(c, u['id'], wid, capability):
                return operation(c, u, s)
            if grant_capability(c, u['id'], wid, capability):
                if not mfa_fresh(c, s):
                    raise AclError(403, 'MFA required')  # an administrative grant needs MFA
                return operation(c, u, s)
            raise _forbidden() if member is not None else _not_found()
        return self.auth.protected(token, run, csrf=csrf, mutation=mutation)

    # ---- reads: only workspaces where the caller is an active member ----

    def get_workspace(self, token, workspace_id):
        wid = as_uuid(workspace_id)

        def run(c, u, s):
            require_member(c, u['id'], wid)
            row = one(c, '''SELECT id, name, timezone, version FROM task_ayuza.workspaces WHERE id=:id''', id=wid)
            return {'id': row['id'], 'name': row['name'], 'timezone': row['timezone'], 'version': row['version']}
        return self.auth.protected(token, run)

    def list_workspaces(self, token, *, limit=50, after=None):
        """Stable keyset pagination by (name, id); `after` is the (name, id) of the last row."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise AclError(422, 'Invalid limit')
        cursor = None
        if after is not None:
            try:
                cursor = (clean_text(after[0]), as_uuid(after[1]))
            except (TypeError, IndexError, KeyError):
                raise AclError(422, 'Invalid cursor') from None
        base = '''SELECT w.id, w.name, w.timezone, w.version FROM task_ayuza.workspaces w
            JOIN task_ayuza.workspace_members m ON m.workspace_id = w.id AND m.user_id = :u AND m.active'''
        order = ' ORDER BY w.name, w.id LIMIT :limit'

        def run(c, u, s):
            if cursor is None:
                rows = execute(c, base + order, u=u['id'], limit=limit)
            else:
                rows = execute(c, base + ' WHERE (w.name, w.id) > (:an, :ai)' + order,
                               u=u['id'], limit=limit, an=cursor[0], ai=cursor[1])
            return [dict(r) for r in rows.mappings()]
        return self.auth.protected(token, run)

    def count_workspaces(self, token):
        def run(c, u, s):
            return execute(c, '''SELECT count(*) FROM task_ayuza.workspaces w
                JOIN task_ayuza.workspace_members m ON m.workspace_id = w.id AND m.user_id = :u AND m.active''',
                           u=u['id']).scalar_one()
        return self.auth.protected(token, run)

    # ---- system administrator: structure only, never workspace content ----

    def create_workspace(self, token, csrf, name, timezone, request_id=None):
        name = clean_text(name)
        timezone = clean_text(timezone, 64)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            require_system_admin(c, u['id'])
            wid = uuid.uuid4()
            try:
                execute(c, '''INSERT INTO task_ayuza.workspaces (id, organization_id, name, timezone)
                    VALUES (:id, :org, :name, :tz)''', id=wid, org=u['organization_id'], name=name, tz=timezone)
            except IntegrityError:
                raise AclError(422, 'Invalid value') from None
            audit(c, u, s, request_id=request_id, entity_kind='workspace', entity_id=wid,
                  action='acl.workspace_created', workspace_id=wid, old=None,
                  new={'name': name, 'timezone': timezone})
            return {'id': wid, 'version': 1}
        return self._mutation(token, csrf, run)

    def create_team(self, token, csrf, name, request_id=None):
        name = clean_text(name)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            require_system_admin(c, u['id'])
            tid = uuid.uuid4()
            execute(c, '''INSERT INTO task_ayuza.teams (id, organization_id, name)
                VALUES (:id, :org, :name)''', id=tid, org=u['organization_id'], name=name)
            audit(c, u, s, request_id=request_id, entity_kind='team', entity_id=tid,
                  action='acl.team_created', workspace_id=None, old=None, new={'name': name})
            return {'id': tid, 'version': 1}
        return self._mutation(token, csrf, run)

    def set_team_member(self, token, csrf, team_id, user_id, active=True, expected_version=None, request_id=None):
        team, target = as_uuid(team_id), as_uuid(user_id)
        if not isinstance(active, bool):
            raise AclError(422, 'Invalid value')
        expected = check_version(expected_version)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            return _team_member(c, u, s, team, target, active, expected, request_id)
        return self._mutation(token, csrf, run)

    # ---- workspace administrator: members, allowed teams, delegated access ----

    def set_workspace_member(self, token, csrf, workspace_id, user_id, role, active=True,
                             expected_version=None, request_id=None):
        wid, target = as_uuid(workspace_id), as_uuid(user_id)
        if role not in WORKSPACE_ROLES or not isinstance(active, bool):
            raise AclError(422, 'Invalid value')
        expected = check_version(expected_version)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            return _workspace_member(c, u, s, wid, target, role, active, expected, request_id)
        return self._mutation(token, csrf, run)

    def set_workspace_team(self, token, csrf, workspace_id, team_id, active=True,
                           expected_version=None, request_id=None):
        wid, team = as_uuid(workspace_id), as_uuid(team_id)
        if not isinstance(active, bool):
            raise AclError(422, 'Invalid value')
        expected = check_version(expected_version)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            require_workspace_admin(c, u['id'], wid)
            found = one(c, '''SELECT active FROM task_ayuza.teams WHERE id=:id AND organization_id=:org''',
                        id=team, org=u['organization_id'])
            if found is None:
                raise _not_found()
            if active and not found['active']:
                raise AclError(422, 'Team is inactive')
            return _upsert(c, u, s, table='workspace_teams', keys={'workspace_id': wid, 'team_id': team},
                           values={'active': active}, entity_kind='workspace_team',
                           actions=('acl.workspace_team_added', 'acl.workspace_team_changed'),
                           workspace_id=wid, expected=expected, request_id=request_id)
        return self._mutation(token, csrf, run)

    def grant_team_access(self, token, csrf, workspace_id, team_id, user_id, capability, reason, request_id=None):
        wid, team, target = as_uuid(workspace_id), as_uuid(team_id), as_uuid(user_id)
        if capability not in CAPABILITIES:
            raise AclError(422, 'Invalid capability')
        reason = clean_text(reason, 500)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            require_workspace_admin(c, u['id'], wid)
            if capability not in DELEGABLE:
                raise _forbidden()  # delegation of the rest needs M01.4 approval flow
            _reject_self(u, target)
            _target_user(c, u, target, require_active=True)
            eligible = (
                one(c, '''SELECT 1 AS x FROM task_ayuza.workspace_members
                    WHERE workspace_id=:w AND user_id=:u AND active FOR SHARE''', w=wid, u=target),
                one(c, '''SELECT 1 AS x FROM task_ayuza.team_members
                    WHERE team_id=:t AND user_id=:u AND active FOR SHARE''', t=team, u=target),
                one(c, '''SELECT 1 AS x FROM task_ayuza.teams
                    WHERE id=:t AND organization_id=:org AND active FOR SHARE''', t=team, org=u['organization_id']),
                one(c, '''SELECT 1 AS x FROM task_ayuza.workspace_teams
                    WHERE workspace_id=:w AND team_id=:t AND active FOR SHARE''', w=wid, t=team),
            )
            if any(item is None for item in eligible):
                raise AclError(422, 'Target is not eligible')
            row = one(c, '''INSERT INTO task_ayuza.workspace_team_access
                    (id, workspace_id, team_id, user_id, capability, granted_by, reason, granted_at)
                VALUES (:id, :w, :t, :u, :cap, :by, :reason, clock_timestamp())
                ON CONFLICT (workspace_id, team_id, user_id, capability) DO UPDATE
                  SET revoked_at = NULL, granted_by = EXCLUDED.granted_by, reason = EXCLUDED.reason,
                      granted_at = EXCLUDED.granted_at, version = task_ayuza.workspace_team_access.version + 1
                  WHERE task_ayuza.workspace_team_access.revoked_at IS NOT NULL
                RETURNING id, version, version > 1 AS reactivated''',
                      id=uuid.uuid4(), w=wid, t=team, u=target, cap=capability, by=u['id'], reason=reason)
            if row is None:  # already active: repeat is a no-op without a second audit event
                existing = one(c, '''SELECT id, version FROM task_ayuza.workspace_team_access
                    WHERE workspace_id=:w AND team_id=:t AND user_id=:u AND capability=:cap''',
                               w=wid, t=team, u=target, cap=capability)
                return {'id': existing['id'], 'version': existing['version'], 'created': False}
            audit(c, u, s, request_id=request_id, entity_kind='workspace_team_access', entity_id=row['id'],
                  action='acl.team_access_granted', workspace_id=wid,
                  old={'revoked': True} if row['reactivated'] else None,
                  new={'capability': capability, 'revoked': False})
            return {'id': row['id'], 'version': row['version'], 'created': True}
        return self._mutation(token, csrf, run)

    def revoke_team_access(self, token, csrf, workspace_id, access_id, expected_version=None, request_id=None):
        wid, access = as_uuid(workspace_id), as_uuid(access_id)
        expected = check_version(expected_version)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            require_workspace_admin(c, u['id'], wid)
            row = one(c, '''SELECT id, capability, revoked_at, version FROM task_ayuza.workspace_team_access
                WHERE id=:id AND workspace_id=:w FOR UPDATE''', id=access, w=wid)
            if row is None:
                raise _not_found()
            if row['revoked_at'] is not None:  # already revoked: idempotent
                return {'id': row['id'], 'version': row['version'], 'revoked': True}
            if expected is None or expected != row['version']:
                raise AclError(409, 'Version conflict')
            updated = one(c, '''UPDATE task_ayuza.workspace_team_access
                SET revoked_at = clock_timestamp(), version = version + 1
                WHERE id=:id AND version=:version RETURNING id, version''', id=access, version=expected)
            if updated is None:
                raise AclError(409, 'Version conflict')
            audit(c, u, s, request_id=request_id, entity_kind='workspace_team_access', entity_id=access,
                  action='acl.team_access_revoked', workspace_id=wid,
                  old={'capability': row['capability'], 'revoked': False},
                  new={'capability': row['capability'], 'revoked': True})
            return {'id': updated['id'], 'version': updated['version'], 'revoked': True}
        return self._mutation(token, csrf, run)
