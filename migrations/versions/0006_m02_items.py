"""M02.2: labels, project stages, subtasks, checklists, comments

Revision ID: 0006_m02_items
Revises: 0005_m02_projects_tasks
"""
from alembic import op

revision = "0006_m02_items"
down_revision = "0005_m02_projects_tasks"
branch_labels = None
depends_on = None

UPGRADE_SQL = r"""
CREATE TABLE task_ayuza.labels (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES task_ayuza.workspaces(id),
    name varchar(60) NOT NULL,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_labels_workspace_id UNIQUE (workspace_id, id),
    CONSTRAINT ck_labels_name CHECK (length(name) BETWEEN 1 AND 60 AND btrim(name) <> ''),
    CONSTRAINT ck_labels_version CHECK (version >= 1)
);
CREATE UNIQUE INDEX uq_labels_workspace_name ON task_ayuza.labels(workspace_id, lower(name));

CREATE TABLE task_ayuza.project_stages (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    project_id uuid NOT NULL,
    title varchar(200) NOT NULL,
    start_date date,
    due_date date,
    sort_order integer NOT NULL DEFAULT 0,
    version bigint NOT NULL DEFAULT 1,
    archived_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT fk_stage_project FOREIGN KEY (workspace_id, project_id)
        REFERENCES task_ayuza.projects(workspace_id, id),
    CONSTRAINT uq_stage_scope UNIQUE (workspace_id, project_id, id),
    CONSTRAINT ck_stage_title CHECK (length(title) BETWEEN 1 AND 200 AND btrim(title) <> ''),
    CONSTRAINT ck_stage_dates CHECK (start_date IS NULL OR due_date IS NULL OR start_date <= due_date),
    CONSTRAINT ck_stage_version CHECK (version >= 1)
);
CREATE INDEX ix_stage_project ON task_ayuza.project_stages(project_id, sort_order, id);

CREATE TABLE task_ayuza.project_labels (
    project_id uuid NOT NULL,
    label_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    active boolean NOT NULL DEFAULT true,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, label_id),
    CONSTRAINT fk_pl_project FOREIGN KEY (workspace_id, project_id) REFERENCES task_ayuza.projects(workspace_id, id),
    CONSTRAINT fk_pl_label FOREIGN KEY (workspace_id, label_id) REFERENCES task_ayuza.labels(workspace_id, id)
);
CREATE INDEX ix_pl_label ON task_ayuza.project_labels(label_id);

CREATE TABLE task_ayuza.task_labels (
    task_id uuid NOT NULL,
    label_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    active boolean NOT NULL DEFAULT true,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (task_id, label_id),
    CONSTRAINT fk_tl_task FOREIGN KEY (workspace_id, task_id) REFERENCES task_ayuza.tasks(workspace_id, id),
    CONSTRAINT fk_tl_label FOREIGN KEY (workspace_id, label_id) REFERENCES task_ayuza.labels(workspace_id, id)
);
CREATE INDEX ix_tl_label ON task_ayuza.task_labels(label_id);

ALTER TABLE task_ayuza.tasks ADD COLUMN parent_task_id uuid;
ALTER TABLE task_ayuza.tasks ADD COLUMN stage_id uuid;
ALTER TABLE task_ayuza.tasks ADD CONSTRAINT fk_tasks_parent FOREIGN KEY (workspace_id, parent_task_id)
    REFERENCES task_ayuza.tasks(workspace_id, id);
ALTER TABLE task_ayuza.tasks ADD CONSTRAINT fk_tasks_stage FOREIGN KEY (workspace_id, project_id, stage_id)
    REFERENCES task_ayuza.project_stages(workspace_id, project_id, id);
ALTER TABLE task_ayuza.tasks ADD CONSTRAINT ck_tasks_stage_project CHECK (stage_id IS NULL OR project_id IS NOT NULL);
CREATE INDEX ix_tasks_parent ON task_ayuza.tasks(parent_task_id);

CREATE FUNCTION task_ayuza.tasks_hierarchy_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE parent record;
BEGIN
    IF NEW.parent_task_id IS NOT NULL THEN
        IF NEW.parent_task_id = NEW.id THEN
            RAISE EXCEPTION 'task cannot be its own parent' USING ERRCODE = '23514';
        END IF;
        SELECT t.workspace_id, t.project_id INTO parent FROM task_ayuza.tasks t WHERE t.id = NEW.parent_task_id;
        IF parent.workspace_id IS DISTINCT FROM NEW.workspace_id OR parent.project_id IS DISTINCT FROM NEW.project_id THEN
            RAISE EXCEPTION 'parent and child must share workspace and project' USING ERRCODE = '23514';
        END IF;
        IF EXISTS (WITH RECURSIVE up(id, parent_id) AS (
                SELECT t.id, t.parent_task_id FROM task_ayuza.tasks t WHERE t.id = NEW.parent_task_id
                UNION ALL
                SELECT t.id, t.parent_task_id FROM task_ayuza.tasks t JOIN up ON t.id = up.parent_id)
            SELECT 1 FROM up WHERE id = NEW.id) THEN
            RAISE EXCEPTION 'task hierarchy cycle' USING ERRCODE = '23514';
        END IF;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.project_id IS DISTINCT FROM OLD.project_id
       AND EXISTS (SELECT 1 FROM task_ayuza.tasks c WHERE c.parent_task_id = NEW.id) THEN
        RAISE EXCEPTION 'cannot move a task that has subtasks to another project' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER tasks_hierarchy_guard BEFORE INSERT OR UPDATE OF parent_task_id, project_id, workspace_id
    ON task_ayuza.tasks FOR EACH ROW EXECUTE FUNCTION task_ayuza.tasks_hierarchy_guard();

CREATE TABLE task_ayuza.checklist_items (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    task_id uuid NOT NULL,
    text varchar(500) NOT NULL,
    position integer NOT NULL,
    is_checked boolean NOT NULL DEFAULT false,
    checked_by uuid REFERENCES task_ayuza.users(id),
    checked_at timestamptz,
    version bigint NOT NULL DEFAULT 1,
    deleted_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT fk_ci_task FOREIGN KEY (workspace_id, task_id) REFERENCES task_ayuza.tasks(workspace_id, id),
    CONSTRAINT uq_ci_position UNIQUE (task_id, position),
    CONSTRAINT ck_ci_text CHECK (length(text) BETWEEN 1 AND 500 AND btrim(text) <> ''),
    CONSTRAINT ck_ci_checked CHECK (is_checked = (checked_at IS NOT NULL) AND is_checked = (checked_by IS NOT NULL)),
    CONSTRAINT ck_ci_version CHECK (version >= 1)
);

CREATE TABLE task_ayuza.comments (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    task_id uuid NOT NULL,
    author_user_id uuid NOT NULL,
    body varchar(10000) NOT NULL,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    edited_at timestamptz,
    hidden_at timestamptz,
    hidden_by uuid REFERENCES task_ayuza.users(id),
    deleted_at timestamptz,
    CONSTRAINT fk_comments_task FOREIGN KEY (workspace_id, task_id) REFERENCES task_ayuza.tasks(workspace_id, id),
    CONSTRAINT fk_comments_author FOREIGN KEY (workspace_id, author_user_id)
        REFERENCES task_ayuza.workspace_members(workspace_id, user_id),
    CONSTRAINT ck_comments_body CHECK (length(body) BETWEEN 1 AND 10000 AND btrim(body) <> ''),
    CONSTRAINT ck_comments_hidden CHECK ((hidden_at IS NULL) = (hidden_by IS NULL)),
    CONSTRAINT ck_comments_version CHECK (version >= 1)
);
CREATE INDEX ix_comments_task ON task_ayuza.comments(task_id, created_at, id);

CREATE TABLE task_ayuza.comment_revisions (
    id uuid PRIMARY KEY,
    comment_id uuid NOT NULL REFERENCES task_ayuza.comments(id),
    body varchar(10000) NOT NULL,
    version bigint NOT NULL,
    replaced_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_comment_revision UNIQUE (comment_id, version)
);

CREATE OR REPLACE FUNCTION task_ayuza.audit_work_snapshot_ok(snap jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
    SELECT jsonb_typeof(snap) = 'object'
       AND (snap - ARRAY['status','priority','role','active','archived','project_id','owner_user_id',
                         'result_owner_user_id','executor_team_id','assignee_user_id','fields',
                         'parent_task_id','stage_id','label_id','checked','deleted','hidden','position']) = '{}'::jsonb
       AND (NOT (snap ? 'status') OR (jsonb_typeof(snap->'status') = 'string'
            AND snap->>'status' IN ('new','planned','in_progress','blocked','done','cancelled')))
       AND (NOT (snap ? 'priority') OR (jsonb_typeof(snap->'priority') = 'string'
            AND snap->>'priority' IN ('low','normal','high','critical')))
       AND (NOT (snap ? 'role') OR (jsonb_typeof(snap->'role') = 'string'
            AND snap->>'role' IN ('observer','participant','project_manager')))
       AND (NOT (snap ? 'active') OR jsonb_typeof(snap->'active') = 'boolean')
       AND (NOT (snap ? 'archived') OR jsonb_typeof(snap->'archived') = 'boolean')
       AND (NOT (snap ? 'checked') OR jsonb_typeof(snap->'checked') = 'boolean')
       AND (NOT (snap ? 'deleted') OR jsonb_typeof(snap->'deleted') = 'boolean')
       AND (NOT (snap ? 'hidden') OR jsonb_typeof(snap->'hidden') = 'boolean')
       AND (NOT (snap ? 'position') OR jsonb_typeof(snap->'position') = 'number')
       AND (NOT (snap ? 'project_id') OR snap->'project_id' = 'null'::jsonb
            OR (jsonb_typeof(snap->'project_id') = 'string' AND length(snap->>'project_id') = 36))
       AND (NOT (snap ? 'parent_task_id') OR snap->'parent_task_id' = 'null'::jsonb
            OR (jsonb_typeof(snap->'parent_task_id') = 'string' AND length(snap->>'parent_task_id') = 36))
       AND (NOT (snap ? 'stage_id') OR snap->'stage_id' = 'null'::jsonb
            OR (jsonb_typeof(snap->'stage_id') = 'string' AND length(snap->>'stage_id') = 36))
       AND (NOT (snap ? 'label_id') OR (jsonb_typeof(snap->'label_id') = 'string' AND length(snap->>'label_id') = 36))
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
    (entity_kind = 'task' AND action IN ('task.created','task.updated','task.status_changed','task.assigned','task.archived','task.restored','task.stage_set')) OR
    (entity_kind = 'label' AND action = 'label.created') OR
    (entity_kind = 'project' AND action = 'label.project_set') OR
    (entity_kind = 'task' AND action = 'label.task_set') OR
    (entity_kind = 'project_stage' AND action IN ('stage.created','stage.updated','stage.archived','stage.restored')) OR
    (entity_kind = 'checklist_item' AND action IN ('checklist.item_added','checklist.item_changed')) OR
    (entity_kind = 'comment' AND action IN ('comment.added','comment.edited','comment.hidden','comment.restored','comment.deleted'))
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
             OR action LIKE 'checklist.%' OR action LIKE 'comment.%') AND task_ayuza.audit_work_snapshot_ok("old"))
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
             OR action LIKE 'checklist.%' OR action LIKE 'comment.%') AND task_ayuza.audit_work_snapshot_ok("new"))
    )
);
ALTER TABLE task_ayuza.audit_events DROP CONSTRAINT ck_audit_m02_actor;
ALTER TABLE task_ayuza.audit_events ADD CONSTRAINT ck_audit_m02_actor CHECK (
    (action NOT LIKE 'project.%' AND action NOT LIKE 'task.%' AND action NOT LIKE 'label.%'
     AND action NOT LIKE 'stage.%' AND action NOT LIKE 'checklist.%' AND action NOT LIKE 'comment.%')
    OR (actor_kind = 'user' AND session_id IS NOT NULL AND workspace_id IS NOT NULL)
);
"""


def upgrade():
    op.execute(UPGRADE_SQL)


def downgrade():
    raise RuntimeError('M02.2 downgrade is unsupported; discard only the authorized disposable cluster')
