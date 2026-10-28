import uuid

import pytest

from app.modules.audit.application.dto import RecordAuditEventCommand
from app.modules.audit.application.service import AuditService
from app.modules.audit.domain.entities import AuditLog
from app.modules.audit.domain.exceptions import InvalidAuditEventError


class InMemoryAuditLogRepository:
    def __init__(self) -> None:
        self.records: list[AuditLog] = []

    def append(self, audit_log: AuditLog) -> AuditLog:
        self.records.append(audit_log)
        return audit_log


def test_audit_service_records_event_through_repository() -> None:
    repository = InMemoryAuditLogRepository()
    service = AuditService(repository)
    user_id = uuid.uuid4()
    org_id = uuid.uuid4()
    session_id = uuid.uuid4()

    result = service.record(
        RecordAuditEventCommand(
            organization_id=org_id,
            user_id=user_id,
            session_id=session_id,
            action="identity.user.login",
            resource_type="user",
            resource_id=str(user_id),
            new_values={"status": "authenticated"},
            metadata={"outcome": "success"},
            ip_address="127.0.0.1",
            user_agent="pytest",
        )
    )

    assert len(repository.records) == 1
    assert result.action == "identity.user.login"
    assert result.organization_id == org_id
    assert result.user_id == user_id
    assert result.session_id == session_id
    assert result.metadata == {"outcome": "success"}


def test_audit_service_rejects_empty_action() -> None:
    service = AuditService(InMemoryAuditLogRepository())

    with pytest.raises(InvalidAuditEventError, match="action is required"):
        service.record(
            RecordAuditEventCommand(action="  ", resource_type="user"),
        )


def test_audit_service_rejects_invalid_action_format() -> None:
    service = AuditService(InMemoryAuditLogRepository())

    with pytest.raises(InvalidAuditEventError, match="module.resource.action"):
        service.record(
            RecordAuditEventCommand(action="invalid_action", resource_type="user"),
        )


def test_audit_service_rejects_non_json_serializable_metadata() -> None:
    service = AuditService(InMemoryAuditLogRepository())

    class NotSerializable:
        pass

    with pytest.raises(InvalidAuditEventError, match="metadata must be JSON-serializable"):
        service.record(
            RecordAuditEventCommand(
                action="identity.user.login",
                resource_type="user",
                metadata={"bad": NotSerializable()},  # type: ignore[dict-item]
            ),
        )


def test_audit_service_accepts_product_prefixed_action_without_product_dependency() -> None:
    repository = InMemoryAuditLogRepository()
    service = AuditService(repository)

    result = service.record(
        RecordAuditEventCommand(
            action="fair_crm.company.created",
            resource_type="company",
            resource_id="company-123",
        )
    )

    assert result.action == "fair_crm.company.created"
    assert len(repository.records) == 1
