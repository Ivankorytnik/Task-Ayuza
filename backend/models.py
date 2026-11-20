"""M01.1 foundation and M01.2 auth metadata. No ACL/project/task tables."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Index, String, text
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
            "(entity_kind = 'session' AND action IN ('auth.login_failed','auth.login_limited'))",
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
    workspace_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    entity_kind: Mapped[str] = mapped_column(String(40), nullable=False)
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    action: Mapped[str] = mapped_column(String(60), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"), nullable=False)
    request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    old: Mapped[dict | None] = mapped_column("old", JSONB(none_as_null=True))
    new: Mapped[dict | None] = mapped_column("new", JSONB(none_as_null=True))



# Core tables used by the auth service. Explicit metadata, never create_all on startup.
from sqlalchemy import Table, Column, ForeignKey, BigInteger, Boolean, LargeBinary, Text, UniqueConstraint

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
