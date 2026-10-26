"""Identity administration audit events (SECURITY_PROGRAM F-C13, ADR-0004).

Writes go through the audit module's ``AuditService`` so the ADR-0004
``<module>.<resource>.<verb>`` naming rule is validated on every event. Events
are written in the same transaction as the change they describe: if the audit
write fails, the change fails too (security-critical events must not fail
silently). Never pass passwords, password hashes or tokens here.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.modules.audit.application.dto import RecordAuditEventCommand
from app.modules.audit.application.service import AuditService
from app.modules.audit.infrastructure.repositories import SqlAlchemyAuditLogRepository
from app.modules.identity.api.authorization.context import AuthorizationContext


def record_identity_event(
    db: Session,
    *,
    actor_id: UUID | None,
    session_id: UUID | None,
    action: str,
    resource_type: str,
    resource_id: UUID | str | None,
    organization_id: UUID | None = None,
    old_values: dict[str, Any] | None = None,
    new_values: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    AuditService(SqlAlchemyAuditLogRepository(db)).record(
        RecordAuditEventCommand(
            action=action,
            resource_type=resource_type,
            organization_id=organization_id,
            user_id=actor_id,
            session_id=session_id,
            resource_id=None if resource_id is None else str(resource_id),
            old_values=old_values,
            new_values=new_values,
            metadata=metadata,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    )


def record_context_event(
    db: Session,
    context: AuthorizationContext,
    *,
    action: str,
    resource_type: str,
    resource_id: UUID | str | None,
    organization_id: UUID | None = None,
    old_values: dict[str, Any] | None = None,
    new_values: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    record_identity_event(
        db,
        actor_id=context.user_id,
        session_id=context.session_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        organization_id=context.organization_id if organization_id is None else organization_id,
        old_values=old_values,
        new_values=new_values,
        metadata=metadata,
    )
