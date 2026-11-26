"""WEB-MEMBERS-1: audit action acl.user_created (employee added from the web UI by an administrator).

The action is attributed to the acting administrator and session (ck_audit_acl_actor) and carries
only the allowlisted workspace role; the temporary password never reaches the audit table.

Revision ID: 0013_web_members
Revises: 0012_m08_reminders
"""
from alembic import op

revision = "0013_web_members"
down_revision = "0012_m08_reminders"
branch_labels = None
depends_on = None

UPGRADE_SQL = r"""
ALTER TABLE task_ayuza.audit_events DROP CONSTRAINT ck_audit_scope_m01;
ALTER TABLE task_ayuza.audit_events ADD CONSTRAINT ck_audit_scope_m01 CHECK (
    (entity_kind = 'organization' AND action IN ('organization.created','organization.updated')) OR
    (entity_kind = 'user' AND action IN ('auth.user_created','auth.password_reset','auth.password_changed','auth.deactivated','auth.login_failed','auth.login_limited','auth.login','auth.logout','auth.renewed','acl.user_created')) OR
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
"""


def upgrade():
    op.execute(UPGRADE_SQL)


def downgrade():
    # Retain append-only audit: destructive rollback would invalidate history.
    raise RuntimeError('WEB-MEMBERS-1 downgrade is unsupported; discard only the authorized disposable cluster')
