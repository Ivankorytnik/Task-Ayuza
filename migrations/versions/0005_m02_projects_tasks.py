"""M02.1: projects, project_members, tasks and work audit vocabulary

Revision ID: 0005_m02_projects_tasks
Revises: 0004_m01_mfa_grants
"""
from alembic import op

revision = "0005_m02_projects_tasks"
down_revision = "0004_m01_mfa_grants"
branch_labels = None
depends_on = None

UPGRADE_SQL = r"""
CREATE TABLE task_ayuza.projects (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES task_ayuza.workspaces(id),
    owner_user_id uuid NOT NULL,
    title varchar(200) NOT NULL,
    description varchar(10000) NOT NULL DEFAULT '',
    start_date date,
    due_date date,
    version bigint NOT NULL DEFAULT 1,
    archived_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_projects_workspace_id UNIQUE (workspace_id, id),
    CONSTRAINT fk_projects_owner_member FOREIGN KEY (workspace_id, owner_user_id)
        REFERENCES task_ayuza.workspace_members(workspace_id, user_id),
    CONSTRAINT ck_projects_title CHECK (length(title) BETWEEN 1 AND 200 AND btrim(title) <> ''),
    CONSTRAINT ck_projects_dates CHECK (start_date IS NULL OR due_date IS NULL OR start_date <= due_date),
    CONSTRAINT ck_projects_version CHECK (version >= 1)
);
CREATE INDEX ix_projects_workspace ON task_ayuza.projects(workspace_id, id);

CREATE TABLE task_ayuza.project_members (
    id uuid PRIMARY KEY,
    project_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role varchar(20) NOT NULL,
    active boolean NOT NULL DEFAULT true,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_project_members_pair UNIQUE (project_id, user_id),
    CONSTRAINT fk_pm_project FOREIGN KEY (workspace_id, project_id)
        REFERENCES task_ayuza.projects(workspace_id, id),
    CONSTRAINT fk_pm_workspace_member FOREIGN KEY (workspace_id, user_id)
        REFERENCES task_ayuza.workspace_members(workspace_id, user_id),
    CONSTRAINT ck_pm_role CHECK (role IN ('observer','participant','project_manager')),
    CONSTRAINT ck_pm_version CHECK (version >= 1)
);
CREATE INDEX ix_pm_user ON task_ayuza.project_members(user_id, project_id);

CREATE TABLE task_ayuza.tasks (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES task_ayuza.workspaces(id),
    project_id uuid,
    title varchar(300) NOT NULL,
    description varchar(20000) NOT NULL DEFAULT '',
    status varchar(12) NOT NULL DEFAULT 'new',
    priority varchar(10) NOT NULL DEFAULT 'normal',
    created_by_user_id uuid NOT NULL,
    result_owner_user_id uuid NOT NULL,
    executor_team_id uuid NOT NULL,
    assignee_user_id uuid,
    start_date date,
    due_date date,
    closed_at timestamptz,
    version bigint NOT NULL DEFAULT 1,
    archived_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_tasks_workspace_id UNIQUE (workspace_id, id),
    CONSTRAINT fk_tasks_project FOREIGN KEY (workspace_id, project_id)
        REFERENCES task_ayuza.projects(workspace_id, id),
    CONSTRAINT fk_tasks_team FOREIGN KEY (workspace_id, executor_team_id)
        REFERENCES task_ayuza.workspace_teams(workspace_id, team_id),
    CONSTRAINT fk_tasks_author FOREIGN KEY (workspace_id, created_by_user_id)
        REFERENCES task_ayuza.workspace_members(workspace_id, user_id),
    CONSTRAINT fk_tasks_owner FOREIGN KEY (workspace_id, result_owner_user_id)
        REFERENCES task_ayuza.workspace_members(workspace_id, user_id),
    CONSTRAINT fk_tasks_assignee FOREIGN KEY (workspace_id, assignee_user_id)
        REFERENCES task_ayuza.workspace_members(workspace_id, user_id),
    CONSTRAINT ck_tasks_title CHECK (length(title) BETWEEN 1 AND 300 AND btrim(title) <> ''),
    CONSTRAINT ck_tasks_status CHECK (status IN ('new','planned','in_progress','blocked','done','cancelled')),
    CONSTRAINT ck_tasks_priority CHECK (priority IN ('low','normal','high','critical')),
    CONSTRAINT ck_tasks_dates CHECK (start_date IS NULL OR due_date IS NULL OR start_date <= due_date),
    CONSTRAINT ck_tasks_closed CHECK ((status = 'done') = (closed_at IS NOT NULL)),
    CONSTRAINT ck_tasks_version CHECK (version >= 1)
);
CREATE INDEX ix_tasks_status ON task_ayuza.tasks(workspace_id, status, id);
CREATE INDEX ix_tasks_due ON task_ayuza.tasks(workspace_id, due_date, id);
CREATE INDEX ix_tasks_team ON task_ayuza.tasks(workspace_id, executor_team_id, id);
CREATE INDEX ix_tasks_assignee ON task_ayuza.tasks(workspace_id, assignee_user_id, id);
CREATE INDEX ix_tasks_owner ON task_ayuza.tasks(workspace_id, result_owner_user_id, id);
CREATE INDEX ix_tasks_project ON task_ayuza.tasks(workspace_id, project_id, id);

CREATE OR REPLACE FUNCTION task_ayuza.audit_work_snapshot_ok(snap jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
    SELECT jsonb_typeof(snap) = 'object'
       AND (snap - ARRAY['status','priority','role','active','archived','project_id','owner_user_id',
                         'result_owner_user_id','executor_team_id','assignee_user_id','fields']) = '{}'::jsonb
       AND (NOT (snap ? 'status') OR (jsonb_typeof(snap->'status') = 'string'
            AND snap->>'status' IN ('new','planned','in_progress','blocked','done','cancelled')))
       AND (NOT (snap ? 'priority') OR (jsonb_typeof(snap->'priority') = 'string'
            AND snap->>'priority' IN ('low','normal','high','critical')))
       AND (NOT (snap ? 'role') OR (jsonb_typeof(snap->'role') = 'string'
            AND snap->>'role' IN ('observer','participant','project_manager')))
       AND (NOT (snap ? 'active') OR jsonb_typeof(snap->'active') = 'boolean')
       AND (NOT (snap ? 'archived') OR jsonb_typeof(snap->'archived') = 'boolean')
       AND (NOT (snap ? 'project_id') OR snap->'project_id' = 'null'::jsonb
            OR (jsonb_typeof(snap->'project_id') = 'string' AND length(snap->>'project_id') = 36))
       AND (NOT (snap ? 'owner_user_id') OR (jsonb_typeof(snap->'owner_user_id') = 'string' AND length(snap->>'owner_user_id') = 36))
       AND (NOT (snap ? 'result_owner_user_id') OR (jsonb_typeof(snap->'result_owner_user_id') = 'string' AND length(snap->>'result_owner_user_id') = 36))
       AND (NOT (snap ? 'executor_team_id') OR (jsonb_typeof(snap->'executor_team_id') = 'string' AND length(snap->>'executor_team_id') = 36))
       AND (NOT (snap ? 'assignee_user_id') OR snap->'assignee_user_id' = 'null'::jsonb
            OR (jsonb_typeof(snap->'assignee_user_id') = 'string' AND length(snap->>'assignee_user_id') = 36))
       AND (NOT (snap ? 'fields') OR (jsonb_typeof(snap->'fields') = 'array' AND jsonb_array_length(snap->'fields') <= 12))
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
    (entity_kind = 'setup' AND action = 'setup.completed') OR
    (entity_kind = 'project' AND action IN ('project.created','project.updated','project.archived','project.restored')) OR
    (entity_kind = 'project_member' AND action IN ('project.member_added','project.member_changed')) OR
    (entity_kind = 'task' AND action IN ('task.created','task.updated','task.status_changed','task.assigned','task.archived','task.restored'))
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
        OR ((action LIKE 'project.%' OR action LIKE 'task.%') AND task_ayuza.audit_work_snapshot_ok("old"))
    )
);
ALTER TABLE task_ayuza.audit_events ADD CONSTRAINT ck_audit_new_allowlist CHECK (
    "new" IS NULL OR (
        (action LIKE 'organization.%' AND jsonb_typeof("new") = 'object' AND "new" ? 'name'
            AND ("new" - 'name') = '{}'::jsonb AND jsonb_typeof("new"->'name') = 'string'
            AND length("new"->>'name') BETWEEN 1 AND 200)
        OR ((action LIKE 'acl.%' OR action LIKE 'grant.%' OR action LIKE 'setup.%')
            AND task_ayuza.audit_acl_snapshot_ok("new"))
        OR ((action LIKE 'project.%' OR action LIKE 'task.%') AND task_ayuza.audit_work_snapshot_ok("new"))
    )
);
ALTER TABLE task_ayuza.audit_events ADD CONSTRAINT ck_audit_m02_actor CHECK (
    (action NOT LIKE 'project.%' AND action NOT LIKE 'task.%')
    OR (actor_kind = 'user' AND session_id IS NOT NULL AND workspace_id IS NOT NULL)
);
"""


def upgrade():
    op.execute(UPGRADE_SQL)


def downgrade():
    raise RuntimeError('M02.1 downgrade is unsupported; discard only the authorized disposable cluster')
