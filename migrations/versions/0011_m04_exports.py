"""M04.3: releases, export_events

Revision ID: 0011_m04_exports
Revises: 0010_m04_risks
"""
from alembic import op

revision = "0011_m04_exports"
down_revision = "0010_m04_risks"
branch_labels = None
depends_on = None

UPGRADE_SQL = r"""
CREATE TABLE task_ayuza.releases (
    id uuid PRIMARY KEY,
    version varchar(40) NOT NULL,
    commit_sha varchar(40) NOT NULL,
    published_at timestamptz NOT NULL,
    environment varchar(10) NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT uq_releases_version UNIQUE (version, environment),
    CONSTRAINT ck_releases_version CHECK (version ~ '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'),
    CONSTRAINT ck_releases_sha CHECK (commit_sha ~ '^[0-9a-f]{40}$'),
    CONSTRAINT ck_releases_env CHECK (environment IN ('test','staging','production')),
    CONSTRAINT ck_releases_time CHECK (published_at <= recorded_at)
);
CREATE INDEX ix_releases_published ON task_ayuza.releases(published_at, id);

CREATE TABLE task_ayuza.export_events (
    id uuid PRIMARY KEY,
    actor_id uuid NOT NULL REFERENCES task_ayuza.users(id),
    workspace_id uuid NOT NULL REFERENCES task_ayuza.workspaces(id),
    format varchar(4) NOT NULL,
    filters jsonb NOT NULL DEFAULT '{}'::jsonb,
    row_count integer NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    status varchar(10) NOT NULL DEFAULT 'completed',
    request_id uuid NOT NULL,
    CONSTRAINT ck_export_format CHECK (format IN ('csv','json')),
    CONSTRAINT ck_export_rows CHECK (row_count >= 0),
    CONSTRAINT ck_export_status CHECK (status = 'completed'),
    CONSTRAINT ck_export_filters CHECK (jsonb_typeof(filters) = 'object' AND (filters - 'status') = '{}'::jsonb)
);
CREATE INDEX ix_export_workspace ON task_ayuza.export_events(workspace_id, created_at, id);

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
    (entity_kind = 'setup' AND action = 'setup.completed') OR
    (entity_kind = 'project' AND action IN ('project.created','project.updated','project.archived','project.restored')) OR
    (entity_kind = 'project_member' AND action IN ('project.member_added','project.member_changed')) OR
    (entity_kind = 'task' AND action IN ('task.created','task.updated','task.status_changed','task.assigned','task.archived','task.restored','task.stage_set')) OR
    (entity_kind = 'label' AND action = 'label.created') OR
    (entity_kind = 'project' AND action = 'label.project_set') OR
    (entity_kind = 'task' AND action = 'label.task_set') OR
    (entity_kind = 'project_stage' AND action IN ('stage.created','stage.updated','stage.archived','stage.restored')) OR
    (entity_kind = 'checklist_item' AND action IN ('checklist.item_added','checklist.item_changed')) OR
    (entity_kind = 'comment' AND action IN ('comment.added','comment.edited','comment.hidden','comment.restored','comment.deleted')) OR
    (entity_kind = 'task' AND action IN ('task.access_granted','task.access_revoked')) OR
    (entity_kind = 'task_dependency' AND action IN ('dependency.created','dependency.removed','dependency.restored')) OR
    (entity_kind = 'blocker' AND action IN ('blocker.created','blocker.updated','blocker.resolved','blocker.reopened','blocker.archived','blocker.restored')) OR
    (entity_kind = 'risk' AND action IN ('risk.created','risk.updated','risk.archived','risk.restored','risk.check_recorded',
        'risk.task_linked','risk.task_unlinked','risk.blocker_linked','risk.blocker_unlinked')) OR
    (entity_kind = 'export' AND action = 'export.completed')
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
        OR ((action LIKE 'project.%' OR action LIKE 'task.%' OR action LIKE 'label.%' OR action LIKE 'stage.%'
             OR action LIKE 'checklist.%' OR action LIKE 'comment.%'
             OR action LIKE 'dependency.%' OR action LIKE 'blocker.%' OR action LIKE 'risk.%' OR action LIKE 'export.%') AND task_ayuza.audit_work_snapshot_ok("old"))
    )
);
ALTER TABLE task_ayuza.audit_events ADD CONSTRAINT ck_audit_new_allowlist CHECK (
    "new" IS NULL OR (
        (action LIKE 'organization.%' AND jsonb_typeof("new") = 'object' AND "new" ? 'name'
            AND ("new" - 'name') = '{}'::jsonb AND jsonb_typeof("new"->'name') = 'string'
            AND length("new"->>'name') BETWEEN 1 AND 200)
        OR ((action LIKE 'acl.%' OR action LIKE 'grant.%' OR action LIKE 'setup.%')
            AND task_ayuza.audit_acl_snapshot_ok("new"))
        OR ((action LIKE 'project.%' OR action LIKE 'task.%' OR action LIKE 'label.%' OR action LIKE 'stage.%'
             OR action LIKE 'checklist.%' OR action LIKE 'comment.%'
             OR action LIKE 'dependency.%' OR action LIKE 'blocker.%' OR action LIKE 'risk.%' OR action LIKE 'export.%') AND task_ayuza.audit_work_snapshot_ok("new"))
    )
);
"""


def upgrade():
    op.execute(UPGRADE_SQL)


def downgrade():
    raise RuntimeError('M04.3 downgrade is unsupported; discard only the authorized disposable cluster')
