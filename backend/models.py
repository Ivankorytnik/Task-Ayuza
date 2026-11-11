"""Minimal M01.1 metadata. No users, ACL, project or task tables."""
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
            "entity_kind = 'organization' AND "
            "action IN ('organization.created', 'organization.updated')",
            name="ck_audit_scope_m01",
        ),
        CheckConstraint(
            '"old" IS NULL OR (jsonb_typeof("old") = \'object\' AND '
            '("old" - \'name\') = \'{}\'::jsonb AND '
            'jsonb_typeof("old"->\'name\') = \'string\' AND '
            'length("old"->>\'name\') BETWEEN 1 AND 200)',
            name="ck_audit_old_allowlist",
        ),
        CheckConstraint(
            '"new" IS NULL OR (jsonb_typeof("new") = \'object\' AND '
            '("new" - \'name\') = \'{}\'::jsonb AND '
            'jsonb_typeof("new"->\'name\') = \'string\' AND '
            'length("new"->>\'name\') BETWEEN 1 AND 200)',
            name="ck_audit_new_allowlist",
        ),
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
    old: Mapped[dict | None] = mapped_column("old", JSONB)
    new: Mapped[dict | None] = mapped_column("new", JSONB)
