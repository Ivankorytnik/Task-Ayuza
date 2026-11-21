"""M03.1: task_dependencies, blockers, blocker_events

Revision ID: 0008_m03_links
Revises: 0007_m02_events
"""
from alembic import op

revision = "0008_m03_links"
down_revision = "0007_m02_events"
branch_labels = None
depends_on = None

UPGRADE_SQL = r"""
CREATE TABLE task_ayuza.task_dependencies (
    id uuid PRIMARY KEY,
    blocker_task_id uuid NOT NULL REFERENCES task_ayuza.tasks(id),
    dependent_task_id uuid NOT NULL REFERENCES task_ayuza.tasks(id),
    reason varchar(500) NOT NULL DEFAULT '',
    created_by uuid NOT NULL REFERENCES task_ayuza.users(id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    version bigint NOT NULL DEFAULT 1,
    deleted_at timestamptz,
    deleted_by uuid REFERENCES task_ayuza.users(id),
    deletion_reason varchar(500),
    CONSTRAINT ck_dep_distinct CHECK (blocker_task_id <> dependent_task_id),
    CONSTRAINT ck_dep_deleted CHECK ((deleted_at IS NULL) = (deleted_by IS NULL)
        AND (deleted_at IS NULL OR (deletion_reason IS NOT NULL AND btrim(deletion_reason) <> ''))),
    CONSTRAINT ck_dep_version CHECK (version >= 1)
);
CREATE UNIQUE INDEX uq_dep_active_pair ON task_ayuza.task_dependencies(blocker_task_id, dependent_task_id)
    WHERE deleted_at IS NULL;
CREATE INDEX ix_dep_blocker ON task_ayuza.task_dependencies(blocker_task_id);
CREATE INDEX ix_dep_dependent ON task_ayuza.task_dependencies(dependent_task_id);

CREATE TABLE task_ayuza.blockers (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    blocked_task_id uuid NOT NULL,
    blocking_task_id uuid REFERENCES task_ayuza.tasks(id),
    title varchar(200) NOT NULL,
    description varchar(5000) NOT NULL DEFAULT '',
    responsible_team_id uuid REFERENCES task_ayuza.teams(id),
    responsible_user_id uuid REFERENCES task_ayuza.users(id),
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expected_resolution_date date,
    status varchar(10) NOT NULL DEFAULT 'active',
    resolved_at timestamptz,
    created_by uuid NOT NULL REFERENCES task_ayuza.users(id),
    version bigint NOT NULL DEFAULT 1,
    archived_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT fk_blockers_task FOREIGN KEY (workspace_id, blocked_task_id)
        REFERENCES task_ayuza.tasks(workspace_id, id),
    CONSTRAINT ck_blockers_title CHECK (length(title) BETWEEN 1 AND 200 AND btrim(title) <> ''),
    CONSTRAINT ck_blockers_status CHECK (status IN ('active','resolved')),
    CONSTRAINT ck_blockers_resolved CHECK ((status = 'resolved') = (resolved_at IS NOT NULL)),
    CONSTRAINT ck_blockers_responsible CHECK (responsible_team_id IS NOT NULL OR responsible_user_id IS NOT NULL),
    CONSTRAINT ck_blockers_not_self CHECK (blocking_task_id IS NULL OR blocking_task_id <> blocked_task_id),
    CONSTRAINT ck_blockers_version CHECK (version >= 1)
);
CREATE INDEX ix_blockers_task ON task_ayuza.blockers(blocked_task_id, status);
CREATE INDEX ix_blockers_workspace ON task_ayuza.blockers(workspace_id, status, id);
CREATE INDEX ix_blockers_team ON task_ayuza.blockers(responsible_team_id);
CREATE INDEX ix_blockers_user ON task_ayuza.blockers(responsible_user_id);

CREATE TABLE task_ayuza.blocker_events (
    id uuid PRIMARY KEY,
    blocker_id uuid NOT NULL REFERENCES task_ayuza.blockers(id),
    actor_user_id uuid NOT NULL REFERENCES task_ayuza.users(id),
    event_type varchar(12) NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    resulting_version bigint NOT NULL,
    blocking_task_id_snapshot uuid,
    responsible_team_id_snapshot uuid,
    responsible_user_id_snapshot uuid,
    expected_resolution_date_snapshot date,
    CONSTRAINT ck_be_type CHECK (event_type IN ('created','updated','resolved','reopened','archived','restored')),
    CONSTRAINT ck_be_version CHECK (resulting_version >= 1)
);
CREATE INDEX ix_be_blocker ON task_ayuza.blocker_events(blocker_id, occurred_at, id);

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
    (entity_kind = 'blocker' AND action IN ('blocker.created','blocker.updated','blocker.resolved','blocker.reopened','blocker.archived','blocker.restored'))
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
             OR action LIKE 'dependency.%' OR action LIKE 'blocker.%') AND task_ayuza.audit_work_snapshot_ok("old"))
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
             OR action LIKE 'dependency.%' OR action LIKE 'blocker.%') AND task_ayuza.audit_work_snapshot_ok("new"))
    )
);
ALTER TABLE task_ayuza.audit_events DROP CONSTRAINT ck_audit_m02_actor;
ALTER TABLE task_ayuza.audit_events ADD CONSTRAINT ck_audit_m02_actor CHECK (
    (action NOT LIKE 'project.%' AND action NOT LIKE 'task.%' AND action NOT LIKE 'label.%'
     AND action NOT LIKE 'stage.%' AND action NOT LIKE 'checklist.%' AND action NOT LIKE 'comment.%'
     AND action NOT LIKE 'dependency.%' AND action NOT LIKE 'blocker.%')
    OR (actor_kind = 'user' AND session_id IS NOT NULL AND workspace_id IS NOT NULL)
);
"""


def upgrade():
    op.execute(UPGRADE_SQL)


def downgrade():
    raise RuntimeError('M03.1 downgrade is unsupported; discard only the authorized disposable cluster')
