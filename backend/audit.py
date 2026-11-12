"""Server-side allowlisting. No generic audit CRUD or unsafe arbitrary snapshots."""
from __future__ import annotations

import uuid
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.models import AuditEvent, Organization

ALLOWED_SNAPSHOT_FIELDS = frozenset({"name"})


class OrganizationAlreadyExistsError(Exception):
    """Safe service conflict; caller must roll back the transaction."""


def _safe_snapshot(values: dict | None) -> dict | None:
    if values is None:
        return None
    if set(values) - ALLOWED_SNAPSHOT_FIELDS:
        raise ValueError("Disallowed audit snapshot fields")
    if set(values) != {"name"} or not isinstance(values["name"], str):
        raise ValueError("Invalid audit snapshot")
    name = values["name"]
    if not name.strip() or len(name) > 200:
        raise ValueError("Invalid audit snapshot")
    return {"name": name}


def record_organization_event(
    session: Session,
    *,
    organization_id: uuid.UUID,
    action: str,
    request_id: uuid.UUID,
    old: dict | None,
    new: dict | None,
) -> None:
    if action not in {"organization.created", "organization.updated"}:
        raise ValueError("Unsupported audit action")
    session.add(AuditEvent(
        actor_kind="system", actor_id=None, entity_kind="organization",
        entity_id=organization_id, action=action, request_id=request_id,
        old=_safe_snapshot(old), new=_safe_snapshot(new),
    ))


def create_organization(session: Session, *, name: str, request_id: uuid.UUID) -> Organization:
    """Explicit privileged service operation. Caller commits; event and change are atomic.

    Startup never calls this function. Database singleton constraint serializes races.
    """
    if not isinstance(name, str) or not name.strip() or len(name) > 200:
        raise ValueError("Invalid organization name")
    organization = Organization(name=name)
    session.add(organization)
    try:
        session.flush()
    except IntegrityError as error:
        diagnostic = getattr(error.orig, "diag", None)
        if (getattr(error.orig, "sqlstate", None) == "23505"
                and getattr(diagnostic, "schema_name", None) == "task_ayuza"
                and getattr(diagnostic, "table_name", None) == "organization"
                and getattr(diagnostic, "constraint_name", None) == "organization_singleton_key_key"):
            raise OrganizationAlreadyExistsError("Organization already exists") from None
        raise
    record_organization_event(
        session, organization_id=organization.id, action="organization.created",
        request_id=request_id, old=None, new={"name": name},
    )
    session.flush()
    return organization

