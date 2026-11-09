from fastapi import Depends
from sqlalchemy.orm import Session as DbSession

from app.db.session import get_db
from app.modules.audit.application.list_organization_audit_logs import ListOrganizationAuditLogsUseCase
from app.modules.audit.application.minimize_terminal_organization_audit import (
    MinimizeTerminalOrganizationAuditUseCase,
)
from app.modules.audit.application.purge_retained_organization_audit import (
    PurgeRetainedOrganizationAuditUseCase,
)
from app.modules.audit.application.record_organization_audit_event import (
    RecordOrganizationAuditEventUseCase,
)
from app.modules.audit.application.service import AuditService
from app.modules.audit.domain.query.audit_log_query_repository import AuditLogQueryRepository
from app.modules.audit.infrastructure.query_repository import SqlAlchemyAuditLogQueryRepository
from app.modules.audit.infrastructure.repositories import SqlAlchemyAuditLogRepository
from app.modules.identity.api.authentication.dependencies import get_clock
from app.modules.identity.api.organization.dependencies import get_organization_repository
from app.modules.identity.domain.authentication.ports.clock import Clock
from app.modules.identity.domain.organization.ports.organization_repository import OrganizationRepository


def get_audit_log_query_repository(
    db: DbSession = Depends(get_db, scope="function"),
) -> AuditLogQueryRepository:
    return SqlAlchemyAuditLogQueryRepository(db)


def get_list_organization_audit_logs_use_case(
    query_repository: AuditLogQueryRepository = Depends(get_audit_log_query_repository),
) -> ListOrganizationAuditLogsUseCase:
    return ListOrganizationAuditLogsUseCase(query_repository=query_repository)


def get_audit_service(db: DbSession = Depends(get_db, scope="function")) -> AuditService:
    return AuditService(audit_log_repository=SqlAlchemyAuditLogRepository(db))


def get_record_organization_audit_event_use_case(
    audit_service: AuditService = Depends(get_audit_service),
) -> RecordOrganizationAuditEventUseCase:
    return RecordOrganizationAuditEventUseCase(audit_service=audit_service)


def get_minimize_terminal_organization_audit_use_case(
    db: DbSession = Depends(get_db, scope="function"),
) -> MinimizeTerminalOrganizationAuditUseCase:
    return MinimizeTerminalOrganizationAuditUseCase(
        audit_log_repository=SqlAlchemyAuditLogRepository(db)
    )


def get_purge_retained_organization_audit_use_case(
    db: DbSession = Depends(get_db, scope="function"),
    organization_repository: OrganizationRepository = Depends(get_organization_repository),
    clock: Clock = Depends(get_clock),
) -> PurgeRetainedOrganizationAuditUseCase:
    return PurgeRetainedOrganizationAuditUseCase(
        audit_log_repository=SqlAlchemyAuditLogRepository(db),
        organization_repository=organization_repository,
        clock=clock,
    )
