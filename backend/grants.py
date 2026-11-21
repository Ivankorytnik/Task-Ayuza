"""M01.4 administrative grants (D03) and system role management. Closed service, no HTTP.

An administrative grant is issued by an approver (system_owner or access_approver, set up by the
one-time procedure in backend/setup.py), never by the grantee. Every call needs a valid session,
CSRF and a fresh MFA verification; the grantee must have MFA enabled. Normal grants last at most
30 days, emergency grants at most 2 hours (CHECK in PostgreSQL too). There is no extension: a new
term is a new approval. Audit events are written in the same transaction as the change.
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import timedelta

from backend.acl import (AclError, GRANT_CAPABILITIES, _forbidden, _not_found, as_uuid, audit,
                         check_version, clean_text, mfa_mutation)
from backend.auth import AuthService, clock, execute, one

APPROVER_ROLES = ('system_owner', 'access_approver')
ASSIGNABLE_ROLES = frozenset({'system_admin', 'risk_controller', 'access_approver'})
MAX_STANDARD_MINUTES = 30 * 24 * 60
MAX_EMERGENCY_MINUTES = 2 * 60
MIN_APPROVERS = 2
APPROVER_LOCK = 4101  # serializes changes that could drop the approver count below the minimum


def has_role(c, user_id, *roles) -> bool:
    return execute(c, '''SELECT 1 FROM task_ayuza.system_role_assignments
        WHERE user_id=:u AND role_code = ANY(CAST(:roles AS text[])) AND revoked_at IS NULL''',
                   u=user_id, roles=list(roles)).first() is not None


def _active_user(c, actor, user_id):
    target = one(c, 'SELECT id, organization_id, active FROM task_ayuza.users WHERE id=:id', id=user_id)
    if target is None or target['organization_id'] != actor['organization_id']:
        raise _not_found()
    if not target['active']:
        raise AclError(422, 'Target user is inactive')


class GrantService:
    def __init__(self, auth: AuthService):
        self.auth = auth

    def issue_grant(self, token, csrf, workspace_id, grantee_id, capability, kind, minutes, reason,
                    request_id=None):
        wid, grantee = as_uuid(workspace_id), as_uuid(grantee_id)
        if capability not in GRANT_CAPABILITIES or kind not in ('standard', 'emergency'):
            raise AclError(422, 'Invalid value')
        limit = MAX_STANDARD_MINUTES if kind == 'standard' else MAX_EMERGENCY_MINUTES
        if isinstance(minutes, bool) or not isinstance(minutes, int) or not 1 <= minutes <= limit:
            raise AclError(422, 'Invalid term')
        reason = clean_text(reason, 500)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            if not has_role(c, u['id'], *APPROVER_ROLES):
                raise _forbidden()
            if grantee == u['id']:
                raise _forbidden()  # no self-approval, the owner included
            if one(c, 'SELECT 1 AS x FROM task_ayuza.workspaces WHERE id=:w AND organization_id=:o',
                   w=wid, o=u['organization_id']) is None:
                raise _not_found()
            _active_user(c, u, grantee)
            if one(c, 'SELECT 1 AS x FROM task_ayuza.user_mfa WHERE user_id=:u AND enabled_at IS NOT NULL',
                   u=grantee) is None:
                raise AclError(422, 'Grantee MFA is not enabled')
            digest = hashlib.sha256(f'{grantee}:{wid}:{capability}:{kind}'.encode()).digest()
            execute(c, 'SELECT pg_advisory_xact_lock(:k)', k=int.from_bytes(digest[:8], 'big', signed=True))
            existing = one(c, '''SELECT id, version, expires_at FROM task_ayuza.administrative_grants
                WHERE grantee_user_id=:g AND workspace_id=:w AND capability=:cap AND kind=:kind
                  AND revoked_at IS NULL AND expires_at > clock_timestamp()
                ORDER BY expires_at DESC LIMIT 1''', g=grantee, w=wid, cap=capability, kind=kind)
            if existing is not None:  # a repeat never adds authority
                return {'id': existing['id'], 'version': existing['version'], 'created': False,
                        'expires_at': existing['expires_at']}
            now = clock(c)
            row = one(c, '''INSERT INTO task_ayuza.administrative_grants
                (id, grantee_user_id, workspace_id, capability, kind, approver_user_id, reason, valid_from, expires_at)
                VALUES (:id, :g, :w, :cap, :kind, :by, :reason, :now, :expires)
                RETURNING id, version, expires_at''',
                      id=uuid.uuid4(), g=grantee, w=wid, cap=capability, kind=kind, by=u['id'],
                      reason=reason, now=now, expires=now + timedelta(minutes=minutes))
            audit(c, u, s, request_id=request_id, entity_kind='administrative_grant', entity_id=row['id'],
                  action='grant.issued', workspace_id=wid, old=None,
                  new={'capability': capability, 'kind': kind, 'expires_at': row['expires_at'].isoformat()})
            return {'id': row['id'], 'version': row['version'], 'created': True, 'expires_at': row['expires_at']}
        return mfa_mutation(self.auth, token, csrf, run)

    def revoke_grant(self, token, csrf, grant_id, expected_version=None, request_id=None):
        gid = as_uuid(grant_id)
        expected = check_version(expected_version)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            if not has_role(c, u['id'], *APPROVER_ROLES):
                raise _forbidden()
            row = one(c, '''SELECT id, workspace_id, capability, revoked_at, version
                FROM task_ayuza.administrative_grants WHERE id=:id FOR UPDATE''', id=gid)
            if row is None:
                raise _not_found()
            if row['revoked_at'] is not None:  # idempotent
                return {'id': row['id'], 'version': row['version'], 'revoked': True}
            if expected is None or expected != row['version']:
                raise AclError(409, 'Version conflict')
            updated = one(c, '''UPDATE task_ayuza.administrative_grants
                SET revoked_at = clock_timestamp(), revoked_by = :by, version = version + 1
                WHERE id=:id AND version=:version RETURNING id, version''', id=gid, by=u['id'], version=expected)
            if updated is None:
                raise AclError(409, 'Version conflict')
            audit(c, u, s, request_id=request_id, entity_kind='administrative_grant', entity_id=gid,
                  action='grant.revoked', workspace_id=row['workspace_id'],
                  old={'capability': row['capability'], 'revoked': False},
                  new={'capability': row['capability'], 'revoked': True})
            return {'id': updated['id'], 'version': updated['version'], 'revoked': True}
        return mfa_mutation(self.auth, token, csrf, run)

    # ---- system roles: only the system owner manages them; the owner role itself is set once ----

    def grant_system_role(self, token, csrf, user_id, role_code, reason, request_id=None):
        target = as_uuid(user_id)
        if role_code not in ASSIGNABLE_ROLES:
            raise AclError(422, 'Invalid role')
        reason = clean_text(reason, 500)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            if not has_role(c, u['id'], 'system_owner'):
                raise _forbidden()
            if target == u['id']:
                raise _forbidden()  # no self-grant
            _active_user(c, u, target)
            row = one(c, '''INSERT INTO task_ayuza.system_role_assignments
                    (id, user_id, role_code, granted_by, reason, granted_at)
                VALUES (:id, :t, :role, :by, :reason, clock_timestamp())
                ON CONFLICT (user_id, role_code) DO UPDATE
                  SET revoked_at = NULL, granted_by = EXCLUDED.granted_by, reason = EXCLUDED.reason,
                      granted_at = EXCLUDED.granted_at,
                      version = task_ayuza.system_role_assignments.version + 1
                  WHERE task_ayuza.system_role_assignments.revoked_at IS NOT NULL
                RETURNING id, version''', id=uuid.uuid4(), t=target, role=role_code, by=u['id'], reason=reason)
            if row is None:
                existing = one(c, '''SELECT id, version FROM task_ayuza.system_role_assignments
                    WHERE user_id=:t AND role_code=:role''', t=target, role=role_code)
                return {'id': existing['id'], 'version': existing['version'], 'created': False}
            audit(c, u, s, request_id=request_id, entity_kind='system_role', entity_id=row['id'],
                  action='acl.system_role_granted', workspace_id=None, old=None,
                  new={'role_code': role_code, 'revoked': False})
            return {'id': row['id'], 'version': row['version'], 'created': True}
        return mfa_mutation(self.auth, token, csrf, run)

    def revoke_system_role(self, token, csrf, user_id, role_code, expected_version=None, request_id=None):
        target = as_uuid(user_id)
        if role_code not in ASSIGNABLE_ROLES:
            raise AclError(422, 'Invalid role')
        expected = check_version(expected_version)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            if not has_role(c, u['id'], 'system_owner'):
                raise _forbidden()
            if role_code == 'access_approver':
                execute(c, 'SELECT pg_advisory_xact_lock(:k)', k=APPROVER_LOCK)
            row = one(c, '''SELECT id, revoked_at, version FROM task_ayuza.system_role_assignments
                WHERE user_id=:t AND role_code=:role FOR UPDATE''', t=target, role=role_code)
            if row is None:
                raise _not_found()
            if row['revoked_at'] is not None:
                return {'id': row['id'], 'version': row['version'], 'revoked': True}
            if expected is None or expected != row['version']:
                raise AclError(409, 'Version conflict')
            if role_code == 'access_approver':
                remaining = execute(c, '''SELECT count(DISTINCT user_id) FROM task_ayuza.system_role_assignments
                    WHERE role_code IN ('system_owner', 'access_approver') AND revoked_at IS NULL AND id <> :id''',
                                    id=row['id']).scalar_one()
                if remaining < MIN_APPROVERS:
                    raise AclError(409, 'At least two approvers are required')
            updated = one(c, '''UPDATE task_ayuza.system_role_assignments
                SET revoked_at = clock_timestamp(), version = version + 1
                WHERE id=:id AND version=:version RETURNING id, version''', id=row['id'], version=expected)
            if updated is None:
                raise AclError(409, 'Version conflict')
            audit(c, u, s, request_id=request_id, entity_kind='system_role', entity_id=row['id'],
                  action='acl.system_role_revoked', workspace_id=None,
                  old={'role_code': role_code, 'revoked': False}, new={'role_code': role_code, 'revoked': True})
            return {'id': updated['id'], 'version': updated['version'], 'revoked': True}
        return mfa_mutation(self.auth, token, csrf, run)
