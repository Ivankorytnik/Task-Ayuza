"""M01.4 MFA, first setup state, administrative grants (D03); no HTTP API.

Revision ID: 0004_m01_mfa_grants
Revises: 0003_m01_acl

Grants cover workspaces only: projects/tasks do not exist yet, so no project_id/task_id
columns and no placeholder foreign keys are created.
"""
from alembic import op

revision = '0004_m01_mfa_grants'
down_revision = '0003_m01_acl'
branch_labels = None
depends_on = None

UPGRADE_SQL = """
ALTER TABLE task_ayuza.sessions ADD COLUMN mfa_verified_at timestamptz;

CREATE TABLE task_ayuza.user_mfa (
    user_id uuid PRIMARY KEY REFERENCES task_ayuza.users(id),
    encrypted_secret bytea NOT NULL,
    enabled_at timestamptz,
    last_used_step bigint,
    failed_count integer NOT NULL DEFAULT 0,
    locked_until timestamptz,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_user_mfa_secret CHECK (octet_length(encrypted_secret) = 48),
    CONSTRAINT ck_user_mfa_failed CHECK (failed_count BETWEEN 0 AND 1000),
    CONSTRAINT ck_user_mfa_version CHECK (version >= 1)
);

CREATE TABLE task_ayuza.mfa_backup_codes (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES task_ayuza.users(id),
    code_hash bytea NOT NULL,
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_mfa_backup_user_hash UNIQUE (user_id, code_hash),
    CONSTRAINT ck_mfa_backup_hash CHECK (octet_length(code_hash) = 32)
);
CREATE INDEX ix_mfa_backup_user ON task_ayuza.mfa_backup_codes(user_id);

CREATE TABLE task_ayuza.administrative_grants (
    id uuid PRIMARY KEY,
    grantee_user_id uuid NOT NULL REFERENCES task_ayuza.users(id),
    workspace_id uuid NOT NULL REFERENCES task_ayuza.workspaces(id),
    capability varchar(20) NOT NULL,
    kind varchar(10) NOT NULL,
    approver_user_id uuid NOT NULL REFERENCES task_ayuza.users(id),
    reason varchar(500) NOT NULL,
    valid_from timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revoked_by uuid REFERENCES task_ayuza.users(id),
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_ag_capability CHECK (capability IN
        ('read','comment','content_edit','link','assign','archive_restore','manage_access','export','audit_read')),
    CONSTRAINT ck_ag_kind CHECK (kind IN ('standard','emergency')),
    CONSTRAINT ck_ag_reason CHECK (length(reason) BETWEEN 1 AND 500 AND btrim(reason) <> ''),
    CONSTRAINT ck_ag_no_self_approval CHECK (approver_user_id <> grantee_user_id),
    CONSTRAINT ck_ag_term CHECK (expires_at > valid_from AND (
        (kind = 'standard' AND expires_at - valid_from <= interval '30 days') OR
        (kind = 'emergency' AND expires_at - valid_from <= interval '2 hours'))),
    CONSTRAINT ck_ag_revoked CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)
        AND (revoked_at IS NULL OR revoked_at >= valid_from)),
    CONSTRAINT ck_ag_version CHECK (version >= 1)
);
CREATE INDEX ix_ag_grantee_workspace ON task_ayuza.administrative_grants(grantee_user_id, workspace_id);
CREATE INDEX ix_ag_workspace ON task_ayuza.administrative_grants(workspace_id);

CREATE TABLE task_ayuza.setup_state (
    singleton boolean PRIMARY KEY DEFAULT true,
    completed_at timestamptz NOT NULL DEFAULT now(),
    owner_user_id uuid NOT NULL REFERENCES task_ayuza.users(id),
    CONSTRAINT ck_setup_singleton CHECK (singleton IS TRUE)
);

ALTER TABLE task_ayuza.system_role_assignments DROP CONSTRAINT ck_system_role_code;
ALTER TABLE task_ayuza.system_role_assignments ADD CONSTRAINT ck_system_role_code CHECK (
    role_code IN ('system_admin','risk_controller','system_owner','access_approver'));

CREATE OR REPLACE FUNCTION task_ayuza.audit_acl_snapshot_ok(snap jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
    SELECT jsonb_typeof(snap) = 'object'
       AND (snap - ARRAY['name','role','active','capability','timezone','revoked','kind','expires_at','role_code']) = '{}'::jsonb
       AND (NOT (snap ? 'name') OR (jsonb_typeof(snap->'name') = 'string' AND length(snap->>'name') BETWEEN 1 AND 200))
       AND (NOT (snap ? 'timezone') OR (jsonb_typeof(snap->'timezone') = 'string' AND length(snap->>'timezone') BETWEEN 1 AND 64))
       AND (NOT (snap ? 'role') OR (jsonb_typeof(snap->'role') = 'string' AND snap->>'role' IN ('participant','observer','workspace_admin')))
       AND (NOT (snap ? 'capability') OR (jsonb_typeof(snap->'capability') = 'string' AND snap->>'capability' IN ('read','comment','content_edit','link','assign','archive_restore','manage_access','export','audit_read')))
       AND (NOT (snap ? 'kind') OR (jsonb_typeof(snap->'kind') = 'string' AND snap->>'kind' IN ('standard','emergency')))
       AND (NOT (snap ? 'expires_at') OR (jsonb_typeof(snap->'expires_at') = 'string' AND length(snap->>'expires_at') BETWEEN 10 AND 40))
       AND (NOT (snap ? 'role_code') OR (jsonb_typeof(snap->'role_code') = 'string' AND snap->>'role_code' IN ('system_admin','risk_controller','system_owner','access_approver')))
       AND (NOT (snap ? 'active') OR jsonb_typeof(snap->'active') = 'boolean')
       AND (NOT (snap ? 'revoked') OR jsonb_typeof(snap->'revoked') = 'boolean')
$$;

ALTER TABLE task_ayuza.audit_events DROP CONSTRAINT ck_audit_scope_m01;
ALTER TABLE task_ayuza.audit_events ADD CONSTRAINT ck_audit_scope_m01 CHECK (
    (entity_kind = 'organization' AND action IN ('organization.created','organization.updated')) OR
    (entity_kind = 'user' AND action IN ('auth.user_created','auth.password_reset','auth.password_changed','auth.deactivated','auth.login_failed','auth.login_limited','auth.login','auth.logout','auth.renewed')) OR
    (entity_kind = 'session' AND action IN ('auth.login_failed','auth.login_limited')) OR
    (entity_kind = 'workspace' AND action = 'acl.workspace_created') OR
    (entity_kind = 'team' AND action = 'acl.team_created') OR
    (entity_kind = 'workspace_member' AND action IN ('acl.workspace_member_added','acl.workspace_member_changed')) OR
    (entity_kind = 'team_member' AND action IN ('acl.team_member_added','acl.team_member_changed')) OR
    (entity_kind = 'workspace_team' AND action IN ('acl.workspace_team_added','acl.workspace_team_changed')) OR
    (entity_kind = 'workspace_team_access' AND action IN ('acl.team_access_granted','acl.team_access_revoked')) OR
    (entity_kind = 'mfa' AND action IN ('mfa.enrolled','mfa.enabled','mfa.verified','mfa.verify_failed','mfa.backup_code_used')) OR
    (entity_kind = 'administrative_grant' AND action IN ('grant.issued','grant.revoked')) OR
    (entity_kind = 'system_role' AND action IN ('acl.system_role_granted','acl.system_role_revoked','setup.role_assigned')) OR
    (entity_kind = 'setup' AND action = 'setup.completed')
);
ALTER TABLE task_ayuza.audit_events DROP CONSTRAINT ck_audit_old_allowlist;
ALTER TABLE task_ayuza.audit_events DROP CONSTRAINT ck_audit_new_allowlist;
ALTER TABLE task_ayuza.audit_events ADD CONSTRAINT ck_audit_old_allowlist CHECK (
    "old" IS NULL OR (
        (action LIKE 'organization.%' AND jsonb_typeof("old") = 'object' AND "old" ? 'name'
            AND ("old" - 'name') = '{}'::jsonb AND jsonb_typeof("old"->'name') = 'string'
            AND length("old"->>'name') BETWEEN 1 AND 200)
        OR ((action LIKE 'acl.%' OR action LIKE 'grant.%' OR action LIKE 'setup.%')
            AND task_ayuza.audit_acl_snapshot_ok("old"))
    )
);
ALTER TABLE task_ayuza.audit_events ADD CONSTRAINT ck_audit_new_allowlist CHECK (
    "new" IS NULL OR (
        (action LIKE 'organization.%' AND jsonb_typeof("new") = 'object' AND "new" ? 'name'
            AND ("new" - 'name') = '{}'::jsonb AND jsonb_typeof("new"->'name') = 'string'
            AND length("new"->>'name') BETWEEN 1 AND 200)
        OR ((action LIKE 'acl.%' OR action LIKE 'grant.%' OR action LIKE 'setup.%')
            AND task_ayuza.audit_acl_snapshot_ok("new"))
    )
);
ALTER TABLE task_ayuza.audit_events DROP CONSTRAINT ck_audit_acl_actor;
ALTER TABLE task_ayuza.audit_events ADD CONSTRAINT ck_audit_acl_actor CHECK (
    action NOT LIKE 'acl.%' OR (
        actor_kind = 'user' AND session_id IS NOT NULL AND
        ((action IN ('acl.team_created','acl.team_member_added','acl.team_member_changed',
                     'acl.system_role_granted','acl.system_role_revoked')) = (workspace_id IS NULL))
    )
);
ALTER TABLE task_ayuza.audit_events ADD CONSTRAINT ck_audit_m014_actor CHECK (
    (action NOT LIKE 'grant.%' OR (actor_kind = 'user' AND session_id IS NOT NULL AND workspace_id IS NOT NULL))
    AND (action NOT LIKE 'mfa.%' OR (actor_kind = 'user' AND session_id IS NOT NULL AND workspace_id IS NULL
         AND "old" IS NULL AND "new" IS NULL))
    AND (action NOT LIKE 'setup.%' OR (actor_kind = 'system' AND session_id IS NULL AND workspace_id IS NULL))
);
"""


def upgrade():
    op.execute(UPGRADE_SQL)


def downgrade():
    # Retain append-only audit and MFA state: destructive rollback is unsupported.
    raise RuntimeError('M01.4 downgrade is unsupported; discard only the authorized disposable cluster')
