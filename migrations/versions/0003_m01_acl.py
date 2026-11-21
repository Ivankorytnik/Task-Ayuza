"""M01.3 workspaces, teams, memberships, team access, system roles; no HTTP API.

Revision ID: 0003_m01_acl
Revises: 0002_m01_auth

Project/task ACL tables are absent on purpose: no projects/tasks exist yet, so no
placeholder foreign keys are introduced. Administrative grants and MFA are M01.4.
"""
from alembic import op

revision = '0003_m01_acl'
down_revision = '0002_m01_auth'
branch_labels = None
depends_on = None

UPGRADE_SQL = """
CREATE FUNCTION task_ayuza.workspace_timezone_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_timezone_names WHERE name = NEW.timezone) THEN
        RAISE EXCEPTION 'unknown IANA timezone' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION task_ayuza.audit_acl_snapshot_ok(snap jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
    SELECT jsonb_typeof(snap) = 'object'
       AND (snap - ARRAY['name','role','active','capability','timezone','revoked']) = '{}'::jsonb
       AND (NOT (snap ? 'name') OR (jsonb_typeof(snap->'name') = 'string' AND length(snap->>'name') BETWEEN 1 AND 200))
       AND (NOT (snap ? 'timezone') OR (jsonb_typeof(snap->'timezone') = 'string' AND length(snap->>'timezone') BETWEEN 1 AND 64))
       AND (NOT (snap ? 'role') OR (jsonb_typeof(snap->'role') = 'string' AND snap->>'role' IN ('participant','observer','workspace_admin')))
       AND (NOT (snap ? 'capability') OR (jsonb_typeof(snap->'capability') = 'string' AND snap->>'capability' IN ('read','comment','content_edit','link','assign','archive_restore','manage_access','export')))
       AND (NOT (snap ? 'active') OR jsonb_typeof(snap->'active') = 'boolean')
       AND (NOT (snap ? 'revoked') OR jsonb_typeof(snap->'revoked') = 'boolean')
$$;

CREATE TABLE task_ayuza.workspaces (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES task_ayuza.organization(id),
    name varchar(200) NOT NULL,
    timezone varchar(64) NOT NULL,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    archived_at timestamptz,
    CONSTRAINT ck_workspaces_name CHECK (length(name) BETWEEN 1 AND 200 AND btrim(name) <> ''),
    CONSTRAINT ck_workspaces_version CHECK (version >= 1),
    CONSTRAINT ck_workspaces_timezone CHECK (timezone ~ '^[A-Za-z0-9_+/-]{1,64}$')
);
CREATE TRIGGER workspaces_timezone_guard BEFORE INSERT OR UPDATE OF timezone ON task_ayuza.workspaces
    FOR EACH ROW EXECUTE FUNCTION task_ayuza.workspace_timezone_guard();

CREATE TABLE task_ayuza.teams (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES task_ayuza.organization(id),
    name varchar(200) NOT NULL,
    active boolean NOT NULL DEFAULT true,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_teams_name CHECK (length(name) BETWEEN 1 AND 200 AND btrim(name) <> ''),
    CONSTRAINT ck_teams_version CHECK (version >= 1)
);

CREATE TABLE task_ayuza.workspace_members (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES task_ayuza.workspaces(id),
    user_id uuid NOT NULL REFERENCES task_ayuza.users(id),
    role varchar(20) NOT NULL,
    active boolean NOT NULL DEFAULT true,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_workspace_members_pair UNIQUE (workspace_id, user_id),
    CONSTRAINT ck_workspace_members_role CHECK (role IN ('participant','observer','workspace_admin')),
    CONSTRAINT ck_workspace_members_version CHECK (version >= 1)
);
CREATE INDEX ix_workspace_members_user ON task_ayuza.workspace_members(user_id);

CREATE TABLE task_ayuza.team_members (
    id uuid PRIMARY KEY,
    team_id uuid NOT NULL REFERENCES task_ayuza.teams(id),
    user_id uuid NOT NULL REFERENCES task_ayuza.users(id),
    active boolean NOT NULL DEFAULT true,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_team_members_pair UNIQUE (team_id, user_id),
    CONSTRAINT ck_team_members_version CHECK (version >= 1)
);
CREATE INDEX ix_team_members_user ON task_ayuza.team_members(user_id);

CREATE TABLE task_ayuza.workspace_teams (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES task_ayuza.workspaces(id),
    team_id uuid NOT NULL REFERENCES task_ayuza.teams(id),
    active boolean NOT NULL DEFAULT true,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_workspace_teams_pair UNIQUE (workspace_id, team_id),
    CONSTRAINT ck_workspace_teams_version CHECK (version >= 1)
);
CREATE INDEX ix_workspace_teams_team ON task_ayuza.workspace_teams(team_id);

CREATE TABLE task_ayuza.workspace_team_access (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    team_id uuid NOT NULL,
    user_id uuid NOT NULL,
    capability varchar(20) NOT NULL,
    granted_by uuid NOT NULL REFERENCES task_ayuza.users(id),
    reason varchar(500) NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    version bigint NOT NULL DEFAULT 1,
    CONSTRAINT uq_workspace_team_access UNIQUE (workspace_id, team_id, user_id, capability),
    CONSTRAINT fk_wta_workspace_team FOREIGN KEY (workspace_id, team_id)
        REFERENCES task_ayuza.workspace_teams(workspace_id, team_id),
    CONSTRAINT fk_wta_team_member FOREIGN KEY (team_id, user_id)
        REFERENCES task_ayuza.team_members(team_id, user_id),
    CONSTRAINT fk_wta_workspace_member FOREIGN KEY (workspace_id, user_id)
        REFERENCES task_ayuza.workspace_members(workspace_id, user_id),
    CONSTRAINT ck_wta_capability CHECK (capability IN
        ('read','comment','content_edit','link','assign','archive_restore','manage_access','export')),
    CONSTRAINT ck_wta_reason CHECK (length(reason) BETWEEN 1 AND 500 AND btrim(reason) <> ''),
    CONSTRAINT ck_wta_no_self_grant CHECK (granted_by <> user_id),
    CONSTRAINT ck_wta_revoked CHECK (revoked_at IS NULL OR revoked_at >= granted_at),
    CONSTRAINT ck_wta_version CHECK (version >= 1)
);
CREATE INDEX ix_wta_user ON task_ayuza.workspace_team_access(user_id);

CREATE TABLE task_ayuza.system_role_assignments (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES task_ayuza.users(id),
    role_code varchar(20) NOT NULL,
    granted_by uuid REFERENCES task_ayuza.users(id),
    reason varchar(500) NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    version bigint NOT NULL DEFAULT 1,
    CONSTRAINT uq_system_role_user_role UNIQUE (user_id, role_code),
    CONSTRAINT ck_system_role_code CHECK (role_code IN ('system_admin','risk_controller')),
    CONSTRAINT ck_system_role_reason CHECK (length(reason) BETWEEN 1 AND 500 AND btrim(reason) <> ''),
    CONSTRAINT ck_system_role_no_self_grant CHECK (granted_by IS NULL OR granted_by <> user_id),
    CONSTRAINT ck_system_role_revoked CHECK (revoked_at IS NULL OR revoked_at >= granted_at),
    CONSTRAINT ck_system_role_version CHECK (version >= 1)
);

ALTER TABLE task_ayuza.audit_events
    ADD CONSTRAINT fk_audit_events_workspace FOREIGN KEY (workspace_id) REFERENCES task_ayuza.workspaces(id);

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
    (entity_kind = 'workspace_team_access' AND action IN ('acl.team_access_granted','acl.team_access_revoked'))
);
ALTER TABLE task_ayuza.audit_events DROP CONSTRAINT ck_audit_old_allowlist;
ALTER TABLE task_ayuza.audit_events DROP CONSTRAINT ck_audit_new_allowlist;
ALTER TABLE task_ayuza.audit_events ADD CONSTRAINT ck_audit_old_allowlist CHECK (
    "old" IS NULL OR (
        (action LIKE 'organization.%' AND jsonb_typeof("old") = 'object' AND "old" ? 'name'
            AND ("old" - 'name') = '{}'::jsonb AND jsonb_typeof("old"->'name') = 'string'
            AND length("old"->>'name') BETWEEN 1 AND 200)
        OR (action LIKE 'acl.%' AND task_ayuza.audit_acl_snapshot_ok("old"))
    )
);
ALTER TABLE task_ayuza.audit_events ADD CONSTRAINT ck_audit_new_allowlist CHECK (
    "new" IS NULL OR (
        (action LIKE 'organization.%' AND jsonb_typeof("new") = 'object' AND "new" ? 'name'
            AND ("new" - 'name') = '{}'::jsonb AND jsonb_typeof("new"->'name') = 'string'
            AND length("new"->>'name') BETWEEN 1 AND 200)
        OR (action LIKE 'acl.%' AND task_ayuza.audit_acl_snapshot_ok("new"))
    )
);
ALTER TABLE task_ayuza.audit_events ADD CONSTRAINT ck_audit_acl_actor CHECK (
    action NOT LIKE 'acl.%' OR (
        actor_kind = 'user' AND session_id IS NOT NULL AND
        ((action IN ('acl.team_created','acl.team_member_added','acl.team_member_changed')) = (workspace_id IS NULL))
    )
);
"""


def upgrade():
    op.execute(UPGRADE_SQL)


def downgrade():
    # Retain append-only ACL audit: destructive rollback would invalidate history.
    raise RuntimeError('M01.3 downgrade is unsupported; discard only the authorized disposable cluster')
