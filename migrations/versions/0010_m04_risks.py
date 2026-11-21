"""M04.2: risk_register, risk_checks, risk_task_links, risk_blocker_links

Revision ID: 0010_m04_risks
Revises: 0009_m04_notifications
"""
from alembic import op

revision = "0010_m04_risks"
down_revision = "0009_m04_notifications"
branch_labels = None
depends_on = None

UPGRADE_SQL = r"""
CREATE TABLE task_ayuza.risk_register (
    id uuid PRIMARY KEY,
    category varchar(20) NOT NULL,
    description varchar(2000) NOT NULL,
    probability integer NOT NULL,
    impact integer NOT NULL,
    severity varchar(8) NOT NULL,
    owner_user_id uuid REFERENCES task_ayuza.users(id),
    owner_team_id uuid REFERENCES task_ayuza.teams(id),
    measures varchar(5000) NOT NULL DEFAULT '',
    due_date date,
    control_status varchar(6) NOT NULL DEFAULT 'gray',
    last_check_id uuid,
    created_by uuid NOT NULL REFERENCES task_ayuza.users(id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    version bigint NOT NULL DEFAULT 1,
    archived_at timestamptz,
    CONSTRAINT ck_risk_category CHECK (category IN ('legal','personal_data','cybersecurity','access','availability',
        'database','backup','quality','release','organizational','other')),
    CONSTRAINT ck_risk_description CHECK (length(description) BETWEEN 1 AND 2000 AND btrim(description) <> ''),
    CONSTRAINT ck_risk_scale CHECK (probability BETWEEN 1 AND 5 AND impact BETWEEN 1 AND 5),
    CONSTRAINT ck_risk_severity CHECK (severity IN ('low','medium','high','critical')),
    CONSTRAINT ck_risk_owner CHECK (owner_user_id IS NOT NULL OR owner_team_id IS NOT NULL),
    CONSTRAINT ck_risk_status CHECK (control_status IN ('gray','green','yellow','red')),
    CONSTRAINT ck_risk_gray CHECK (control_status <> 'green' OR last_check_id IS NOT NULL),
    CONSTRAINT ck_risk_version CHECK (version >= 1)
);
CREATE INDEX ix_risk_register_state ON task_ayuza.risk_register(control_status, severity, id);

CREATE TABLE task_ayuza.risk_checks (
    id uuid PRIMARY KEY,
    risk_id uuid NOT NULL REFERENCES task_ayuza.risk_register(id),
    checker_user_id uuid REFERENCES task_ayuza.users(id),
    system_check_code varchar(40),
    result varchar(8) NOT NULL,
    evidence_reference varchar(500),
    checked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    valid_until timestamptz,
    severity varchar(8) NOT NULL,
    CONSTRAINT ck_rc_checker CHECK ((checker_user_id IS NULL) <> (system_check_code IS NULL)),
    CONSTRAINT ck_rc_code CHECK (system_check_code IS NULL OR system_check_code ~ '^[a-z0-9_.-]{3,40}$'),
    CONSTRAINT ck_rc_result CHECK (result IN ('pass','fail','critical')),
    CONSTRAINT ck_rc_severity CHECK (severity IN ('low','medium','high','critical')),
    CONSTRAINT ck_rc_evidence CHECK (evidence_reference IS NULL OR btrim(evidence_reference) <> ''),
    CONSTRAINT ck_rc_pass CHECK (result <> 'pass' OR (evidence_reference IS NOT NULL AND valid_until IS NOT NULL AND valid_until > checked_at))
);
CREATE INDEX ix_rc_risk ON task_ayuza.risk_checks(risk_id, checked_at, id);
ALTER TABLE task_ayuza.risk_register ADD CONSTRAINT fk_risk_last_check FOREIGN KEY (last_check_id) REFERENCES task_ayuza.risk_checks(id);

CREATE TABLE task_ayuza.risk_task_links (
    id uuid PRIMARY KEY,
    risk_id uuid NOT NULL REFERENCES task_ayuza.risk_register(id),
    task_id uuid NOT NULL REFERENCES task_ayuza.tasks(id),
    created_by uuid NOT NULL REFERENCES task_ayuza.users(id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    removed_at timestamptz
);
CREATE UNIQUE INDEX uq_risk_task_active ON task_ayuza.risk_task_links(risk_id, task_id) WHERE removed_at IS NULL;
CREATE INDEX ix_risk_task_task ON task_ayuza.risk_task_links(task_id);

CREATE TABLE task_ayuza.risk_blocker_links (
    id uuid PRIMARY KEY,
    risk_id uuid NOT NULL REFERENCES task_ayuza.risk_register(id),
    blocker_id uuid NOT NULL REFERENCES task_ayuza.blockers(id),
    created_by uuid NOT NULL REFERENCES task_ayuza.users(id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    removed_at timestamptz
);
CREATE UNIQUE INDEX uq_risk_blocker_active ON task_ayuza.risk_blocker_links(risk_id, blocker_id) WHERE removed_at IS NULL;
CREATE INDEX ix_risk_blocker_blocker ON task_ayuza.risk_blocker_links(blocker_id);

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
        'risk.task_linked','risk.task_unlinked','risk.blocker_linked','risk.blocker_unlinked'))
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
             OR action LIKE 'dependency.%' OR action LIKE 'blocker.%' OR action LIKE 'risk.%') AND task_ayuza.audit_work_snapshot_ok("old"))
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
             OR action LIKE 'dependency.%' OR action LIKE 'blocker.%' OR action LIKE 'risk.%') AND task_ayuza.audit_work_snapshot_ok("new"))
    )
);
"""


def upgrade():
    op.execute(UPGRADE_SQL)


def downgrade():
    raise RuntimeError('M04.2 downgrade is unsupported; discard only the authorized disposable cluster')
