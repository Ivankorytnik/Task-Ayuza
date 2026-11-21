"""M02.3: task_events, idempotency_requests, task_access_grants

Revision ID: 0007_m02_events
Revises: 0006_m02_items
"""
from alembic import op

revision = "0007_m02_events"
down_revision = "0006_m02_items"
branch_labels = None
depends_on = None

UPGRADE_SQL = r"""
CREATE TABLE task_ayuza.task_events (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    task_id uuid NOT NULL,
    actor_user_id uuid NOT NULL REFERENCES task_ayuza.users(id),
    event_type varchar(20) NOT NULL,
    from_status varchar(12),
    to_status varchar(12),
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    resulting_version bigint NOT NULL,
    project_id_snapshot uuid,
    team_id_snapshot uuid,
    owner_id_snapshot uuid,
    assignee_id_snapshot uuid,
    project_owner_id_snapshot uuid,
    due_date_snapshot date,
    priority_snapshot varchar(10),
    stage_id_snapshot uuid,
    CONSTRAINT fk_te_task FOREIGN KEY (workspace_id, task_id) REFERENCES task_ayuza.tasks(workspace_id, id),
    CONSTRAINT ck_te_type CHECK (event_type IN ('created','status_changed','completed','cancelled','reopened',
        'assigned','due_changed','priority_changed','stage_changed','archived','restored')),
    CONSTRAINT ck_te_status_values CHECK (
        (from_status IS NULL OR from_status IN ('new','planned','in_progress','blocked','done','cancelled')) AND
        (to_status IS NULL OR to_status IN ('new','planned','in_progress','blocked','done','cancelled'))),
    CONSTRAINT ck_te_transition CHECK (
        (event_type IN ('status_changed','completed','cancelled','reopened')
            AND from_status IS NOT NULL AND to_status IS NOT NULL AND from_status <> to_status)
        OR (event_type NOT IN ('status_changed','completed','cancelled','reopened')
            AND from_status IS NULL AND to_status IS NULL)),
    CONSTRAINT ck_te_semantics CHECK (
        (event_type <> 'completed' OR to_status = 'done') AND
        (event_type <> 'cancelled' OR to_status = 'cancelled') AND
        (event_type <> 'reopened' OR (from_status IN ('done','cancelled') AND to_status NOT IN ('done','cancelled')))),
    CONSTRAINT ck_te_version CHECK (resulting_version >= 1)
);
CREATE INDEX ix_te_task ON task_ayuza.task_events(task_id, occurred_at, id);
CREATE INDEX ix_te_workspace_type ON task_ayuza.task_events(workspace_id, event_type, occurred_at);

CREATE TABLE task_ayuza.idempotency_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL REFERENCES task_ayuza.users(id),
    operation varchar(40) NOT NULL,
    client_key varchar(64) NOT NULL,
    request_hash bytea NOT NULL,
    resource_id uuid NOT NULL,
    state varchar(10) NOT NULL DEFAULT 'done',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CONSTRAINT uq_idempotency UNIQUE (actor_user_id, operation, client_key),
    CONSTRAINT ck_idem_hash CHECK (octet_length(request_hash) = 32),
    CONSTRAINT ck_idem_key CHECK (length(client_key) BETWEEN 8 AND 64),
    CONSTRAINT ck_idem_state CHECK (state IN ('done')),
    CONSTRAINT ck_idem_expiry CHECK (expires_at > created_at)
);
CREATE INDEX ix_idem_expires ON task_ayuza.idempotency_requests(expires_at);

CREATE TABLE task_ayuza.task_access_grants (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    task_id uuid NOT NULL,
    user_id uuid NOT NULL,
    capability varchar(20) NOT NULL,
    granted_by uuid NOT NULL REFERENCES task_ayuza.users(id),
    reason varchar(500) NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz,
    version bigint NOT NULL DEFAULT 1,
    CONSTRAINT fk_tag_task FOREIGN KEY (workspace_id, task_id) REFERENCES task_ayuza.tasks(workspace_id, id),
    CONSTRAINT fk_tag_member FOREIGN KEY (workspace_id, user_id)
        REFERENCES task_ayuza.workspace_members(workspace_id, user_id),
    CONSTRAINT uq_tag_scope UNIQUE (task_id, user_id, capability),
    CONSTRAINT ck_tag_capability CHECK (capability IN ('read','comment','content_edit','link')),
    CONSTRAINT ck_tag_reason CHECK (length(reason) BETWEEN 1 AND 500 AND btrim(reason) <> ''),
    CONSTRAINT ck_tag_no_self CHECK (granted_by <> user_id),
    CONSTRAINT ck_tag_revoked CHECK (revoked_at IS NULL OR revoked_at >= granted_at),
    CONSTRAINT ck_tag_version CHECK (version >= 1)
);
CREATE INDEX ix_tag_user ON task_ayuza.task_access_grants(user_id, task_id);

CREATE OR REPLACE FUNCTION task_ayuza.audit_work_snapshot_ok(snap jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
    SELECT jsonb_typeof(snap) = 'object'
       AND (snap - ARRAY['status','priority','role','active','archived','project_id','owner_user_id',
                         'result_owner_user_id','executor_team_id','assignee_user_id','fields',
                         'parent_task_id','stage_id','label_id','checked','deleted','hidden','position','capability','user_id']) = '{}'::jsonb
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
       AND (NOT (snap ? 'capability') OR (jsonb_typeof(snap->'capability') = 'string' AND snap->>'capability' IN ('read','comment','content_edit','link')))
       AND (NOT (snap ? 'user_id') OR (jsonb_typeof(snap->'user_id') = 'string' AND length(snap->>'user_id') = 36))
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
    (entity_kind = 'comment' AND action IN ('comment.added','comment.edited','comment.hidden','comment.restored','comment.deleted')) OR
    (entity_kind = 'task' AND action IN ('task.access_granted','task.access_revoked'))
);
"""


def upgrade():
    op.execute(UPGRADE_SQL)


def downgrade():
    raise RuntimeError('M02.3 downgrade is unsupported; discard only the authorized disposable cluster')
