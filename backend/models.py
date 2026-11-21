"""M01.1 foundation, M01.2 auth, M01.3 ACL and M01.4 MFA/grants metadata. No project/task tables."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

SCHEMA = "task_ayuza"


class Base(DeclarativeBase):
    pass


class Organization(Base):
    __tablename__ = "organization"
    __table_args__ = (
        CheckConstraint("singleton_key IS TRUE", name="ck_organization_singleton"),
        {"schema": SCHEMA},
    )
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    singleton_key: Mapped[bool] = mapped_column(default=True, server_default=text("true"), unique=True, nullable=False)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint(
            "(actor_kind = 'system' AND actor_id IS NULL) OR "
            "(actor_kind = 'user' AND actor_id IS NOT NULL)",
            name="ck_audit_actor_kind",
        ),
        CheckConstraint(
            "(entity_kind = 'organization' AND action IN ('organization.created','organization.updated')) OR "
            "(entity_kind = 'user' AND action IN ('auth.user_created','auth.password_reset','auth.password_changed','auth.deactivated','auth.login_failed','auth.login_limited','auth.login','auth.logout','auth.renewed')) OR "
            "(entity_kind = 'session' AND action IN ('auth.login_failed','auth.login_limited')) OR "
            "(entity_kind = 'workspace' AND action = 'acl.workspace_created') OR "
            "(entity_kind = 'team' AND action = 'acl.team_created') OR "
            "(entity_kind = 'workspace_member' AND action IN ('acl.workspace_member_added','acl.workspace_member_changed')) OR "
            "(entity_kind = 'team_member' AND action IN ('acl.team_member_added','acl.team_member_changed')) OR "
            "(entity_kind = 'workspace_team' AND action IN ('acl.workspace_team_added','acl.workspace_team_changed')) OR "
            "(entity_kind = 'workspace_team_access' AND action IN ('acl.team_access_granted','acl.team_access_revoked'))",
            name="ck_audit_scope_m01",
        ),
        CheckConstraint(
            '"old" IS NULL OR (jsonb_typeof("old") = \'object\' AND '
            '"old" ? \'name\' AND '
            '("old" - \'name\') = \'{}\'::jsonb AND '
            'jsonb_typeof("old"->\'name\') = \'string\' AND '
            'length("old"->>\'name\') BETWEEN 1 AND 200)',
            name="ck_audit_old_allowlist",
        ),
        CheckConstraint(
            '"new" IS NULL OR (jsonb_typeof("new") = \'object\' AND '
            '"new" ? \'name\' AND '
            '("new" - \'name\') = \'{}\'::jsonb AND '
            'jsonb_typeof("new"->\'name\') = \'string\' AND '
            'length("new"->>\'name\') BETWEEN 1 AND 200)',
            name="ck_audit_new_allowlist",
        ),
        CheckConstraint("action NOT LIKE 'auth.%' OR (\"old\" IS NULL AND \"new\" IS NULL AND workspace_id IS NULL)", name="ck_audit_auth_snapshot"),
        Index("ix_audit_occurred", "occurred_at", "id"),
        {"schema": SCHEMA},
    )
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor_kind: Mapped[str] = mapped_column(String(10), nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    session_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    workspace_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey(f"{SCHEMA}.workspaces.id", name="fk_audit_events_workspace"))
    entity_kind: Mapped[str] = mapped_column(String(40), nullable=False)
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    action: Mapped[str] = mapped_column(String(60), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"), nullable=False)
    request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    old: Mapped[dict | None] = mapped_column("old", JSONB(none_as_null=True))
    new: Mapped[dict | None] = mapped_column("new", JSONB(none_as_null=True))



# Core tables used by the auth service. Explicit metadata, never create_all on startup.
from sqlalchemy import Table, Column, BigInteger, Boolean, ForeignKeyConstraint, Integer, LargeBinary, Text, UniqueConstraint, Date

Users = Table('users', Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('organization_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.organization.id'),nullable=False),
    Column('login',String(64),nullable=False),
    Column('login_normalized',String(64,collation='C'),nullable=False),
    Column('display_name',String(200),nullable=False),
    Column('password_hash',Text,nullable=False),
    Column('active',Boolean,nullable=False,server_default=text('true')),
    Column('must_change_password',Boolean,nullable=False,server_default=text('true')),
    Column('temporary_expires_at',DateTime(timezone=True)),
    Column('auth_version',BigInteger,nullable=False,server_default=text('1')),
    UniqueConstraint('organization_id','login_normalized',name='uq_users_login'),
    CheckConstraint('auth_version > 0',name='users_auth_version_check'),
    CheckConstraint("login = login_normalized AND login_normalized ~ '^[a-z0-9._-]{3,64}$'",name='ck_users_login'),
    CheckConstraint('must_change_password = (temporary_expires_at IS NOT NULL)',name='ck_users_temporary'),
    CheckConstraint('length(display_name) BETWEEN 1 AND 200',name='ck_users_display'),schema=SCHEMA)
Sessions = Table('sessions',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('user_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id')),
    Column('token_hash',LargeBinary,nullable=False,unique=True),
    Column('csrf_hash',LargeBinary,nullable=False),
    Column('kind',String(12),nullable=False),
    Column('created_at',DateTime(timezone=True),nullable=False),
    Column('expires_at',DateTime(timezone=True),nullable=False),
    Column('absolute_expires_at',DateTime(timezone=True),nullable=False),
    Column('revoked_at',DateTime(timezone=True)),
    Column('auth_version',BigInteger),
    Column('mfa_verified_at',DateTime(timezone=True)),
    CheckConstraint('octet_length(token_hash)=32'),CheckConstraint('octet_length(csrf_hash)=32'),
    CheckConstraint("kind IN ('prelogin','password','normal')"),
    CheckConstraint("(kind='prelogin' AND user_id IS NULL AND auth_version IS NULL) OR (kind<>'prelogin' AND user_id IS NOT NULL AND auth_version IS NOT NULL AND auth_version>0)",name='ck_sessions_scope'),
    CheckConstraint('created_at < expires_at AND expires_at <= absolute_expires_at',name='ck_sessions_expiry'),
    Index('ix_sessions_user','user_id'),Index('ix_sessions_expiry','absolute_expires_at'),schema=SCHEMA)
PreloginLimits = Table('prelogin_limits',Base.metadata,
    Column('ip_key',LargeBinary,primary_key=True),
    Column('window_start',DateTime(timezone=True),nullable=False),
    Column('issued_count',BigInteger,nullable=False),
    Column('updated_at',DateTime(timezone=True),nullable=False),
    CheckConstraint('octet_length(ip_key)=32'),CheckConstraint('issued_count BETWEEN 1 AND 30'),
    Index('ix_prelogin_limits_updated','updated_at'),schema=SCHEMA)
AuthLimitEvents = Table('auth_limit_events',Base.metadata,
    Column('key_kind',String(8),primary_key=True),
    Column('key_hash',LargeBinary,primary_key=True),
    Column('last_event_at',DateTime(timezone=True),nullable=False),
    CheckConstraint("key_kind IN ('login','ip')"),
    CheckConstraint('octet_length(key_hash)=32'),
    Index('ix_auth_limit_events_time','last_event_at'),schema=SCHEMA)
LoginAttempts = Table('login_attempts',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('login_key',LargeBinary,nullable=False),Column('ip_key',LargeBinary,nullable=False),
    Column('attempted_at',DateTime(timezone=True),nullable=False),
    CheckConstraint('octet_length(login_key)=32'),CheckConstraint('octet_length(ip_key)=32'),
    Index('ix_attempts_login','login_key','attempted_at'),Index('ix_attempts_ip','ip_key','attempted_at'),
    Index('ix_attempts_time','attempted_at'),schema=SCHEMA)


# M01.3 ACL tables. CHECK/trigger details live in migration 0003_m01_acl.
def _stamp():
    return [Column('version',BigInteger,nullable=False,server_default=text('1')),
            Column('created_at',DateTime(timezone=True),nullable=False,server_default=text('now()')),
            Column('updated_at',DateTime(timezone=True),nullable=False,server_default=text('now()'))]

Workspaces = Table('workspaces',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('organization_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.organization.id'),nullable=False),
    Column('name',String(200),nullable=False),
    Column('timezone',String(64),nullable=False),
    *_stamp(),
    Column('archived_at',DateTime(timezone=True)),
    CheckConstraint('length(name) BETWEEN 1 AND 200 AND btrim(name) <> \'\'',name='ck_workspaces_name'),
    CheckConstraint('version >= 1',name='ck_workspaces_version'),schema=SCHEMA)
Teams = Table('teams',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('organization_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.organization.id'),nullable=False),
    Column('name',String(200),nullable=False),
    Column('active',Boolean,nullable=False,server_default=text('true')),
    *_stamp(),
    CheckConstraint('length(name) BETWEEN 1 AND 200 AND btrim(name) <> \'\'',name='ck_teams_name'),
    CheckConstraint('version >= 1',name='ck_teams_version'),schema=SCHEMA)
WorkspaceMembers = Table('workspace_members',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('workspace_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.workspaces.id'),nullable=False),
    Column('user_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id'),nullable=False),
    Column('role',String(20),nullable=False),
    Column('active',Boolean,nullable=False,server_default=text('true')),
    *_stamp(),
    UniqueConstraint('workspace_id','user_id',name='uq_workspace_members_pair'),
    CheckConstraint("role IN ('participant','observer','workspace_admin')",name='ck_workspace_members_role'),
    CheckConstraint('version >= 1',name='ck_workspace_members_version'),
    Index('ix_workspace_members_user','user_id'),schema=SCHEMA)
TeamMembers = Table('team_members',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('team_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.teams.id'),nullable=False),
    Column('user_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id'),nullable=False),
    Column('active',Boolean,nullable=False,server_default=text('true')),
    *_stamp(),
    UniqueConstraint('team_id','user_id',name='uq_team_members_pair'),
    CheckConstraint('version >= 1',name='ck_team_members_version'),
    Index('ix_team_members_user','user_id'),schema=SCHEMA)
WorkspaceTeams = Table('workspace_teams',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('workspace_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.workspaces.id'),nullable=False),
    Column('team_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.teams.id'),nullable=False),
    Column('active',Boolean,nullable=False,server_default=text('true')),
    *_stamp(),
    UniqueConstraint('workspace_id','team_id',name='uq_workspace_teams_pair'),
    CheckConstraint('version >= 1',name='ck_workspace_teams_version'),
    Index('ix_workspace_teams_team','team_id'),schema=SCHEMA)
WorkspaceTeamAccess = Table('workspace_team_access',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('workspace_id',UUID(as_uuid=True),nullable=False),
    Column('team_id',UUID(as_uuid=True),nullable=False),
    Column('user_id',UUID(as_uuid=True),nullable=False),
    Column('capability',String(20),nullable=False),
    Column('granted_by',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id'),nullable=False),
    Column('reason',String(500),nullable=False),
    Column('granted_at',DateTime(timezone=True),nullable=False,server_default=text('now()')),
    Column('revoked_at',DateTime(timezone=True)),
    Column('version',BigInteger,nullable=False,server_default=text('1')),
    UniqueConstraint('workspace_id','team_id','user_id','capability',name='uq_workspace_team_access'),
    ForeignKeyConstraint(['workspace_id','team_id'],[f'{SCHEMA}.workspace_teams.workspace_id',f'{SCHEMA}.workspace_teams.team_id'],name='fk_wta_workspace_team'),
    ForeignKeyConstraint(['team_id','user_id'],[f'{SCHEMA}.team_members.team_id',f'{SCHEMA}.team_members.user_id'],name='fk_wta_team_member'),
    ForeignKeyConstraint(['workspace_id','user_id'],[f'{SCHEMA}.workspace_members.workspace_id',f'{SCHEMA}.workspace_members.user_id'],name='fk_wta_workspace_member'),
    CheckConstraint('granted_by <> user_id',name='ck_wta_no_self_grant'),
    CheckConstraint('version >= 1',name='ck_wta_version'),
    Index('ix_wta_user','user_id'),schema=SCHEMA)
SystemRoleAssignments = Table('system_role_assignments',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('user_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id'),nullable=False),
    Column('role_code',String(20),nullable=False),
    Column('granted_by',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id')),
    Column('reason',String(500),nullable=False),
    Column('granted_at',DateTime(timezone=True),nullable=False,server_default=text('now()')),
    Column('revoked_at',DateTime(timezone=True)),
    Column('version',BigInteger,nullable=False,server_default=text('1')),
    UniqueConstraint('user_id','role_code',name='uq_system_role_user_role'),
    CheckConstraint("role_code IN ('system_admin','risk_controller')",name='ck_system_role_code'),
    CheckConstraint('granted_by IS NULL OR granted_by <> user_id',name='ck_system_role_no_self_grant'),
    CheckConstraint('version >= 1',name='ck_system_role_version'),schema=SCHEMA)


# M01.4 MFA, administrative grants (workspace scope only), one-time setup marker.
UserMfa = Table('user_mfa',Base.metadata,
    Column('user_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id'),primary_key=True),
    Column('encrypted_secret',LargeBinary,nullable=False),
    Column('enabled_at',DateTime(timezone=True)),
    Column('last_used_step',BigInteger),
    Column('failed_count',Integer,nullable=False,server_default=text('0')),
    Column('locked_until',DateTime(timezone=True)),
    Column('version',BigInteger,nullable=False,server_default=text('1')),
    Column('created_at',DateTime(timezone=True),nullable=False,server_default=text('now()')),
    Column('updated_at',DateTime(timezone=True),nullable=False,server_default=text('now()')),
    CheckConstraint('octet_length(encrypted_secret) = 48',name='ck_user_mfa_secret'),
    CheckConstraint('version >= 1',name='ck_user_mfa_version'),schema=SCHEMA)
MfaBackupCodes = Table('mfa_backup_codes',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('user_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id'),nullable=False),
    Column('code_hash',LargeBinary,nullable=False),
    Column('used_at',DateTime(timezone=True)),
    Column('created_at',DateTime(timezone=True),nullable=False,server_default=text('now()')),
    UniqueConstraint('user_id','code_hash',name='uq_mfa_backup_user_hash'),
    CheckConstraint('octet_length(code_hash) = 32',name='ck_mfa_backup_hash'),
    Index('ix_mfa_backup_user','user_id'),schema=SCHEMA)
AdministrativeGrants = Table('administrative_grants',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('grantee_user_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id'),nullable=False),
    Column('workspace_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.workspaces.id'),nullable=False),
    Column('capability',String(20),nullable=False),
    Column('kind',String(10),nullable=False),
    Column('approver_user_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id'),nullable=False),
    Column('reason',String(500),nullable=False),
    Column('valid_from',DateTime(timezone=True),nullable=False),
    Column('expires_at',DateTime(timezone=True),nullable=False),
    Column('revoked_at',DateTime(timezone=True)),
    Column('revoked_by',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id')),
    Column('version',BigInteger,nullable=False,server_default=text('1')),
    Column('created_at',DateTime(timezone=True),nullable=False,server_default=text('now()')),
    CheckConstraint('approver_user_id <> grantee_user_id',name='ck_ag_no_self_approval'),
    CheckConstraint('version >= 1',name='ck_ag_version'),
    Index('ix_ag_grantee_workspace','grantee_user_id','workspace_id'),
    Index('ix_ag_workspace','workspace_id'),schema=SCHEMA)
SetupState = Table('setup_state',Base.metadata,
    Column('singleton',Boolean,primary_key=True,server_default=text('true')),
    Column('completed_at',DateTime(timezone=True),nullable=False,server_default=text('now()')),
    Column('owner_user_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id'),nullable=False),
    CheckConstraint('singleton IS TRUE',name='ck_setup_singleton'),schema=SCHEMA)

# ---- M02.1 ----
def _ts(name, **kw):
    return Column(name, DateTime(timezone=True), nullable=False, server_default=text('now()'), **kw)

Projects = Table('projects',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('workspace_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.workspaces.id'),nullable=False),
    Column('owner_user_id',UUID(as_uuid=True),nullable=False),
    Column('title',String(200),nullable=False),
    Column('description',String(10000),nullable=False,server_default=text("''")),
    Column('start_date',Date),Column('due_date',Date),
    Column('version',BigInteger,nullable=False,server_default=text('1')),
    Column('archived_at',DateTime(timezone=True)),
    _ts('created_at'),_ts('updated_at'),
    UniqueConstraint('workspace_id','id',name='uq_projects_workspace_id'),
    ForeignKeyConstraint(['workspace_id','owner_user_id'],[f'{SCHEMA}.workspace_members.workspace_id',f'{SCHEMA}.workspace_members.user_id'],name='fk_projects_owner_member'),
    CheckConstraint('version >= 1',name='ck_projects_version'),
    Index('ix_projects_workspace','workspace_id','id'),schema=SCHEMA)
ProjectMembers = Table('project_members',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('project_id',UUID(as_uuid=True),nullable=False),
    Column('workspace_id',UUID(as_uuid=True),nullable=False),
    Column('user_id',UUID(as_uuid=True),nullable=False),
    Column('role',String(20),nullable=False),
    Column('active',Boolean,nullable=False,server_default=text('true')),
    Column('version',BigInteger,nullable=False,server_default=text('1')),
    _ts('created_at'),_ts('updated_at'),
    UniqueConstraint('project_id','user_id',name='uq_project_members_pair'),
    ForeignKeyConstraint(['workspace_id','project_id'],[f'{SCHEMA}.projects.workspace_id',f'{SCHEMA}.projects.id'],name='fk_pm_project'),
    ForeignKeyConstraint(['workspace_id','user_id'],[f'{SCHEMA}.workspace_members.workspace_id',f'{SCHEMA}.workspace_members.user_id'],name='fk_pm_workspace_member'),
    CheckConstraint('version >= 1',name='ck_pm_version'),
    Index('ix_pm_user','user_id','project_id'),schema=SCHEMA)
Tasks = Table('tasks',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('workspace_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.workspaces.id'),nullable=False),
    Column('project_id',UUID(as_uuid=True)),
    Column('title',String(300),nullable=False),
    Column('description',String(20000),nullable=False,server_default=text("''")),
    Column('status',String(12),nullable=False,server_default=text("'new'")),
    Column('priority',String(10),nullable=False,server_default=text("'normal'")),
    Column('created_by_user_id',UUID(as_uuid=True),nullable=False),
    Column('result_owner_user_id',UUID(as_uuid=True),nullable=False),
    Column('executor_team_id',UUID(as_uuid=True),nullable=False),
    Column('assignee_user_id',UUID(as_uuid=True)),
    Column('start_date',Date),Column('due_date',Date),
    Column('closed_at',DateTime(timezone=True)),
    Column('version',BigInteger,nullable=False,server_default=text('1')),
    Column('archived_at',DateTime(timezone=True)),
    Column('parent_task_id',UUID(as_uuid=True)),
    Column('stage_id',UUID(as_uuid=True)),
    _ts('created_at'),_ts('updated_at'),
    UniqueConstraint('workspace_id','id',name='uq_tasks_workspace_id'),
    ForeignKeyConstraint(['workspace_id','parent_task_id'],[f'{SCHEMA}.tasks.workspace_id',f'{SCHEMA}.tasks.id'],name='fk_tasks_parent'),
    ForeignKeyConstraint(['workspace_id','project_id','stage_id'],[f'{SCHEMA}.project_stages.workspace_id',f'{SCHEMA}.project_stages.project_id',f'{SCHEMA}.project_stages.id'],name='fk_tasks_stage'),
    Index('ix_tasks_parent','parent_task_id'),
    ForeignKeyConstraint(['workspace_id','project_id'],[f'{SCHEMA}.projects.workspace_id',f'{SCHEMA}.projects.id'],name='fk_tasks_project'),
    ForeignKeyConstraint(['workspace_id','executor_team_id'],[f'{SCHEMA}.workspace_teams.workspace_id',f'{SCHEMA}.workspace_teams.team_id'],name='fk_tasks_team'),
    ForeignKeyConstraint(['workspace_id','created_by_user_id'],[f'{SCHEMA}.workspace_members.workspace_id',f'{SCHEMA}.workspace_members.user_id'],name='fk_tasks_author'),
    ForeignKeyConstraint(['workspace_id','result_owner_user_id'],[f'{SCHEMA}.workspace_members.workspace_id',f'{SCHEMA}.workspace_members.user_id'],name='fk_tasks_owner'),
    ForeignKeyConstraint(['workspace_id','assignee_user_id'],[f'{SCHEMA}.workspace_members.workspace_id',f'{SCHEMA}.workspace_members.user_id'],name='fk_tasks_assignee'),
    CheckConstraint('version >= 1',name='ck_tasks_version'),
    Index('ix_tasks_status','workspace_id','status','id'),
    Index('ix_tasks_due','workspace_id','due_date','id'),
    Index('ix_tasks_team','workspace_id','executor_team_id','id'),
    Index('ix_tasks_assignee','workspace_id','assignee_user_id','id'),
    Index('ix_tasks_owner','workspace_id','result_owner_user_id','id'),
    Index('ix_tasks_project','workspace_id','project_id','id'),schema=SCHEMA)

# ---- M02.2 ----
Labels = Table('labels',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('workspace_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.workspaces.id'),nullable=False),
    Column('name',String(60),nullable=False),
    Column('version',BigInteger,nullable=False,server_default=text('1')),
    _ts('created_at'),
    UniqueConstraint('workspace_id','id',name='uq_labels_workspace_id'),
    Index('uq_labels_workspace_name','workspace_id',text('lower(name)'),unique=True),schema=SCHEMA)
ProjectStages = Table('project_stages',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('workspace_id',UUID(as_uuid=True),nullable=False),
    Column('project_id',UUID(as_uuid=True),nullable=False),
    Column('title',String(200),nullable=False),
    Column('start_date',Date),Column('due_date',Date),
    Column('sort_order',Integer,nullable=False,server_default=text('0')),
    Column('version',BigInteger,nullable=False,server_default=text('1')),
    Column('archived_at',DateTime(timezone=True)),
    _ts('created_at'),_ts('updated_at'),
    ForeignKeyConstraint(['workspace_id','project_id'],[f'{SCHEMA}.projects.workspace_id',f'{SCHEMA}.projects.id'],name='fk_stage_project'),
    UniqueConstraint('workspace_id','project_id','id',name='uq_stage_scope'),
    Index('ix_stage_project','project_id','sort_order','id'),schema=SCHEMA)
ProjectLabels = Table('project_labels',Base.metadata,
    Column('project_id',UUID(as_uuid=True),primary_key=True),
    Column('label_id',UUID(as_uuid=True),primary_key=True),
    Column('workspace_id',UUID(as_uuid=True),nullable=False),
    Column('active',Boolean,nullable=False,server_default=text('true')),
    Column('version',BigInteger,nullable=False,server_default=text('1')),
    _ts('created_at'),
    ForeignKeyConstraint(['workspace_id','project_id'],[f'{SCHEMA}.projects.workspace_id',f'{SCHEMA}.projects.id'],name='fk_pl_project'),
    ForeignKeyConstraint(['workspace_id','label_id'],[f'{SCHEMA}.labels.workspace_id',f'{SCHEMA}.labels.id'],name='fk_pl_label'),
    Index('ix_pl_label','label_id'),schema=SCHEMA)
TaskLabels = Table('task_labels',Base.metadata,
    Column('task_id',UUID(as_uuid=True),primary_key=True),
    Column('label_id',UUID(as_uuid=True),primary_key=True),
    Column('workspace_id',UUID(as_uuid=True),nullable=False),
    Column('active',Boolean,nullable=False,server_default=text('true')),
    Column('version',BigInteger,nullable=False,server_default=text('1')),
    _ts('created_at'),
    ForeignKeyConstraint(['workspace_id','task_id'],[f'{SCHEMA}.tasks.workspace_id',f'{SCHEMA}.tasks.id'],name='fk_tl_task'),
    ForeignKeyConstraint(['workspace_id','label_id'],[f'{SCHEMA}.labels.workspace_id',f'{SCHEMA}.labels.id'],name='fk_tl_label'),
    Index('ix_tl_label','label_id'),schema=SCHEMA)
ChecklistItems = Table('checklist_items',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('workspace_id',UUID(as_uuid=True),nullable=False),
    Column('task_id',UUID(as_uuid=True),nullable=False),
    Column('text',String(500),nullable=False),
    Column('position',Integer,nullable=False),
    Column('is_checked',Boolean,nullable=False,server_default=text('false')),
    Column('checked_by',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id')),
    Column('checked_at',DateTime(timezone=True)),
    Column('version',BigInteger,nullable=False,server_default=text('1')),
    Column('deleted_at',DateTime(timezone=True)),
    _ts('created_at'),_ts('updated_at'),
    ForeignKeyConstraint(['workspace_id','task_id'],[f'{SCHEMA}.tasks.workspace_id',f'{SCHEMA}.tasks.id'],name='fk_ci_task'),
    UniqueConstraint('task_id','position',name='uq_ci_position'),schema=SCHEMA)
Comments = Table('comments',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('workspace_id',UUID(as_uuid=True),nullable=False),
    Column('task_id',UUID(as_uuid=True),nullable=False),
    Column('author_user_id',UUID(as_uuid=True),nullable=False),
    Column('body',String(10000),nullable=False),
    Column('version',BigInteger,nullable=False,server_default=text('1')),
    _ts('created_at'),
    Column('edited_at',DateTime(timezone=True)),
    Column('hidden_at',DateTime(timezone=True)),
    Column('hidden_by',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id')),
    Column('deleted_at',DateTime(timezone=True)),
    ForeignKeyConstraint(['workspace_id','task_id'],[f'{SCHEMA}.tasks.workspace_id',f'{SCHEMA}.tasks.id'],name='fk_comments_task'),
    ForeignKeyConstraint(['workspace_id','author_user_id'],[f'{SCHEMA}.workspace_members.workspace_id',f'{SCHEMA}.workspace_members.user_id'],name='fk_comments_author'),
    Index('ix_comments_task','task_id','created_at','id'),schema=SCHEMA)
CommentRevisions = Table('comment_revisions',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('comment_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.comments.id'),nullable=False),
    Column('body',String(10000),nullable=False),
    Column('version',BigInteger,nullable=False),
    _ts('replaced_at'),
    UniqueConstraint('comment_id','version',name='uq_comment_revision'),schema=SCHEMA)

# ---- M02.3 ----
TaskEvents = Table('task_events',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('workspace_id',UUID(as_uuid=True),nullable=False),
    Column('task_id',UUID(as_uuid=True),nullable=False),
    Column('actor_user_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id'),nullable=False),
    Column('event_type',String(20),nullable=False),
    Column('from_status',String(12)),Column('to_status',String(12)),
    Column('occurred_at',DateTime(timezone=True),nullable=False,server_default=text('clock_timestamp()')),
    Column('resulting_version',BigInteger,nullable=False),
    Column('project_id_snapshot',UUID(as_uuid=True)),Column('team_id_snapshot',UUID(as_uuid=True)),
    Column('owner_id_snapshot',UUID(as_uuid=True)),Column('assignee_id_snapshot',UUID(as_uuid=True)),
    Column('project_owner_id_snapshot',UUID(as_uuid=True)),
    Column('due_date_snapshot',Date),Column('priority_snapshot',String(10)),
    Column('stage_id_snapshot',UUID(as_uuid=True)),
    ForeignKeyConstraint(['workspace_id','task_id'],[f'{SCHEMA}.tasks.workspace_id',f'{SCHEMA}.tasks.id'],name='fk_te_task'),
    Index('ix_te_task','task_id','occurred_at','id'),
    Index('ix_te_workspace_type','workspace_id','event_type','occurred_at'),schema=SCHEMA)
IdempotencyRequests = Table('idempotency_requests',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('actor_user_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id'),nullable=False),
    Column('operation',String(40),nullable=False),
    Column('client_key',String(64),nullable=False),
    Column('request_hash',LargeBinary,nullable=False),
    Column('resource_id',UUID(as_uuid=True),nullable=False),
    Column('state',String(10),nullable=False,server_default=text("'done'")),
    Column('created_at',DateTime(timezone=True),nullable=False,server_default=text('clock_timestamp()')),
    Column('expires_at',DateTime(timezone=True),nullable=False),
    UniqueConstraint('actor_user_id','operation','client_key',name='uq_idempotency'),
    Index('ix_idem_expires','expires_at'),schema=SCHEMA)
TaskAccessGrants = Table('task_access_grants',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('workspace_id',UUID(as_uuid=True),nullable=False),
    Column('task_id',UUID(as_uuid=True),nullable=False),
    Column('user_id',UUID(as_uuid=True),nullable=False),
    Column('capability',String(20),nullable=False),
    Column('granted_by',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id'),nullable=False),
    Column('reason',String(500),nullable=False),
    Column('granted_at',DateTime(timezone=True),nullable=False,server_default=text('clock_timestamp()')),
    Column('revoked_at',DateTime(timezone=True)),
    Column('version',BigInteger,nullable=False,server_default=text('1')),
    ForeignKeyConstraint(['workspace_id','task_id'],[f'{SCHEMA}.tasks.workspace_id',f'{SCHEMA}.tasks.id'],name='fk_tag_task'),
    ForeignKeyConstraint(['workspace_id','user_id'],[f'{SCHEMA}.workspace_members.workspace_id',f'{SCHEMA}.workspace_members.user_id'],name='fk_tag_member'),
    UniqueConstraint('task_id','user_id','capability',name='uq_tag_scope'),
    Index('ix_tag_user','user_id','task_id'),schema=SCHEMA)

# ---- M03.1 ----
TaskDependencies = Table('task_dependencies',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('blocker_task_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.tasks.id'),nullable=False),
    Column('dependent_task_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.tasks.id'),nullable=False),
    Column('reason',String(500),nullable=False,server_default=text("''")),
    Column('created_by',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id'),nullable=False),
    Column('created_at',DateTime(timezone=True),nullable=False,server_default=text('clock_timestamp()')),
    Column('version',BigInteger,nullable=False,server_default=text('1')),
    Column('deleted_at',DateTime(timezone=True)),
    Column('deleted_by',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id')),
    Column('deletion_reason',String(500)),
    Index('uq_dep_active_pair','blocker_task_id','dependent_task_id',unique=True,postgresql_where=text('deleted_at IS NULL')),
    Index('ix_dep_blocker','blocker_task_id'),
    Index('ix_dep_dependent','dependent_task_id'),schema=SCHEMA)
Blockers = Table('blockers',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('workspace_id',UUID(as_uuid=True),nullable=False),
    Column('blocked_task_id',UUID(as_uuid=True),nullable=False),
    Column('blocking_task_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.tasks.id')),
    Column('title',String(200),nullable=False),
    Column('description',String(5000),nullable=False,server_default=text("''")),
    Column('responsible_team_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.teams.id')),
    Column('responsible_user_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id')),
    Column('occurred_at',DateTime(timezone=True),nullable=False,server_default=text('clock_timestamp()')),
    Column('expected_resolution_date',Date),
    Column('status',String(10),nullable=False,server_default=text("'active'")),
    Column('resolved_at',DateTime(timezone=True)),
    Column('created_by',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id'),nullable=False),
    Column('version',BigInteger,nullable=False,server_default=text('1')),
    Column('archived_at',DateTime(timezone=True)),
    Column('created_at',DateTime(timezone=True),nullable=False,server_default=text('clock_timestamp()')),
    Column('updated_at',DateTime(timezone=True),nullable=False,server_default=text('clock_timestamp()')),
    ForeignKeyConstraint(['workspace_id','blocked_task_id'],[f'{SCHEMA}.tasks.workspace_id',f'{SCHEMA}.tasks.id'],name='fk_blockers_task'),
    Index('ix_blockers_task','blocked_task_id','status'),
    Index('ix_blockers_workspace','workspace_id','status','id'),
    Index('ix_blockers_team','responsible_team_id'),
    Index('ix_blockers_user','responsible_user_id'),schema=SCHEMA)
BlockerEvents = Table('blocker_events',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('blocker_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.blockers.id'),nullable=False),
    Column('actor_user_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id'),nullable=False),
    Column('event_type',String(12),nullable=False),
    Column('occurred_at',DateTime(timezone=True),nullable=False,server_default=text('clock_timestamp()')),
    Column('resulting_version',BigInteger,nullable=False),
    Column('blocking_task_id_snapshot',UUID(as_uuid=True)),
    Column('responsible_team_id_snapshot',UUID(as_uuid=True)),
    Column('responsible_user_id_snapshot',UUID(as_uuid=True)),
    Column('expected_resolution_date_snapshot',Date),
    Index('ix_be_blocker','blocker_id','occurred_at','id'),schema=SCHEMA)
OutboxEvents = Table('outbox_events',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('workspace_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.workspaces.id'),nullable=False),
    Column('task_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.tasks.id'),nullable=False),
    Column('event_type',String(24),nullable=False),
    Column('recipient_user_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id'),nullable=False),
    Column('actor_user_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id'),nullable=False),
    Column('source_id',UUID(as_uuid=True),nullable=False),
    Column('dedupe_key',String(200),nullable=False),
    Column('state',String(8),nullable=False,server_default=text("'pending'")),
    Column('attempts',Integer,nullable=False,server_default=text('0')),
    Column('created_at',DateTime(timezone=True),nullable=False,server_default=text('clock_timestamp()')),
    Column('processed_at',DateTime(timezone=True)),
    UniqueConstraint('dedupe_key',name='uq_outbox_dedupe'),
    Index('ix_outbox_pending','created_at','id',postgresql_where=text("state = 'pending'")),schema=SCHEMA)
Notifications = Table('notifications',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('workspace_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.workspaces.id'),nullable=False),
    Column('task_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.tasks.id'),nullable=False),
    Column('recipient_user_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id'),nullable=False),
    Column('event_type',String(24),nullable=False),
    Column('outbox_event_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.outbox_events.id'),nullable=False),
    Column('dedupe_key',String(200),nullable=False),
    Column('created_at',DateTime(timezone=True),nullable=False,server_default=text('clock_timestamp()')),
    Column('read_at',DateTime(timezone=True)),
    UniqueConstraint('dedupe_key',name='uq_notifications_dedupe'),
    UniqueConstraint('outbox_event_id',name='uq_notifications_outbox'),
    Index('ix_notifications_recipient','recipient_user_id','read_at','created_at'),schema=SCHEMA)
RiskRegister = Table('risk_register',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('category',String(20),nullable=False),
    Column('description',String(2000),nullable=False),
    Column('probability',Integer,nullable=False),
    Column('impact',Integer,nullable=False),
    Column('severity',String(8),nullable=False),
    Column('owner_user_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id')),
    Column('owner_team_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.teams.id')),
    Column('measures',String(5000),nullable=False,server_default=text("''")),
    Column('due_date',Date),
    Column('control_status',String(6),nullable=False,server_default=text("'gray'")),
    Column('last_check_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.risk_checks.id',use_alter=True,name='fk_risk_last_check')),
    Column('created_by',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id'),nullable=False),
    Column('created_at',DateTime(timezone=True),nullable=False,server_default=text('clock_timestamp()')),
    Column('updated_at',DateTime(timezone=True),nullable=False,server_default=text('clock_timestamp()')),
    Column('version',BigInteger,nullable=False,server_default=text('1')),
    Column('archived_at',DateTime(timezone=True)),
    Index('ix_risk_register_state','control_status','severity','id'),schema=SCHEMA)
RiskChecks = Table('risk_checks',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('risk_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.risk_register.id'),nullable=False),
    Column('checker_user_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id')),
    Column('system_check_code',String(40)),
    Column('result',String(8),nullable=False),
    Column('evidence_reference',String(500)),
    Column('checked_at',DateTime(timezone=True),nullable=False,server_default=text('clock_timestamp()')),
    Column('valid_until',DateTime(timezone=True)),
    Column('severity',String(8),nullable=False),
    Index('ix_rc_risk','risk_id','checked_at','id'),schema=SCHEMA)
RiskTaskLinks = Table('risk_task_links',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('risk_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.risk_register.id'),nullable=False),
    Column('task_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.tasks.id'),nullable=False),
    Column('created_by',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id'),nullable=False),
    Column('created_at',DateTime(timezone=True),nullable=False,server_default=text('clock_timestamp()')),
    Column('removed_at',DateTime(timezone=True)),
    Index('uq_risk_task_active','risk_id','task_id',unique=True,postgresql_where=text('removed_at IS NULL')),
    Index('ix_risk_task_task','task_id'),schema=SCHEMA)
RiskBlockerLinks = Table('risk_blocker_links',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('risk_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.risk_register.id'),nullable=False),
    Column('blocker_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.blockers.id'),nullable=False),
    Column('created_by',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id'),nullable=False),
    Column('created_at',DateTime(timezone=True),nullable=False,server_default=text('clock_timestamp()')),
    Column('removed_at',DateTime(timezone=True)),
    Index('uq_risk_blocker_active','risk_id','blocker_id',unique=True,postgresql_where=text('removed_at IS NULL')),
    Index('ix_risk_blocker_blocker','blocker_id'),schema=SCHEMA)
Releases = Table('releases',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('version',String(40),nullable=False),
    Column('commit_sha',String(40),nullable=False),
    Column('published_at',DateTime(timezone=True),nullable=False),
    Column('environment',String(10),nullable=False),
    Column('recorded_at',DateTime(timezone=True),nullable=False,server_default=text('clock_timestamp()')),
    UniqueConstraint('version','environment',name='uq_releases_version'),
    Index('ix_releases_published','published_at','id'),schema=SCHEMA)
ExportEvents = Table('export_events',Base.metadata,
    Column('id',UUID(as_uuid=True),primary_key=True),
    Column('actor_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.users.id'),nullable=False),
    Column('workspace_id',UUID(as_uuid=True),ForeignKey(f'{SCHEMA}.workspaces.id'),nullable=False),
    Column('format',String(4),nullable=False),
    Column('filters',JSONB,nullable=False,server_default=text("'{}'::jsonb")),
    Column('row_count',Integer,nullable=False),
    Column('created_at',DateTime(timezone=True),nullable=False,server_default=text('clock_timestamp()')),
    Column('status',String(10),nullable=False,server_default=text("'completed'")),
    Column('request_id',UUID(as_uuid=True),nullable=False),
    Index('ix_export_workspace','workspace_id','created_at','id'),schema=SCHEMA)
