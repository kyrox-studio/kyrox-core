from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status

from app.modules.audit.api.dependencies import (
    get_list_organization_audit_logs_use_case,
    get_purge_retained_organization_audit_use_case,
    get_record_organization_audit_event_use_case,
)
from app.modules.audit.api.error_mapping import map_audit_query_error, map_audit_record_error
from app.modules.audit.api.mappers import (
    audit_log_list_params_to_command,
    audit_log_list_result_to_response,
    audit_log_to_response,
    record_audit_event_request_to_command,
)
from app.modules.audit.api.schemas import (
    AuditLogListQueryParams,
    AuditLogListResponse,
    AuditLogResponse,
    ErrorResponse,
    PurgeRetainedOrganizationAuditResponse,
    RecordAuditEventRequest,
)
from app.modules.audit.application.list_organization_audit_logs import ListOrganizationAuditLogsUseCase
from app.modules.audit.application.purge_retained_organization_audit import (
    PurgeRetainedOrganizationAuditUseCase,
)
from app.modules.audit.application.record_organization_audit_event import (
    RecordOrganizationAuditEventUseCase,
)
from app.modules.audit.domain.exceptions import (
    AuditRetentionOrganizationNotFoundError,
    AuditRetentionPreconditionError,
    InvalidAuditEventError,
)
from app.modules.audit.domain.query_exceptions import InvalidAuditQueryError
from app.modules.audit.domain.retention_policy import (
    is_reserved_core_lifecycle_action,
    is_terminal_retention_action,
)
from app.modules.identity.api.authorization.context import (
    AuthenticatedOrganizationContext,
    AuthorizationContext,
)
from app.modules.identity.api.authorization.guards import require_organization_access, require_permission
from app.modules.identity.api.authorization.scope import assert_organization_scope
from app.modules.identity.api.organization.dependencies import get_organization_repository
from app.modules.identity.api.organization.product_lifecycle_routes import (
    require_product_lifecycle_credential,
)
from app.modules.identity.domain.organization.ports.organization_repository import OrganizationRepository
from app.modules.identity.domain.organization.value_objects.identity.organization_id import OrganizationId

router = APIRouter(tags=["audit"])


def get_audit_log_list_query_params(
    action: str | None = None,
    action_prefix: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    user_id: UUID | None = None,
    session_id: UUID | None = None,
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
    limit: int = 50,
    cursor: str | None = None,
) -> AuditLogListQueryParams:
    return AuditLogListQueryParams(
        action=action,
        action_prefix=action_prefix,
        resource_type=resource_type,
        resource_id=resource_id,
        user_id=user_id,
        session_id=session_id,
        from_=from_,
        to=to,
        limit=limit,
        cursor=cursor,
    )


def _terminal_safe_body(
    organization_id: UUID,
    body: RecordAuditEventRequest,
) -> RecordAuditEventRequest:
    action = body.action.strip()
    if not is_terminal_retention_action(action):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Deleted organizations accept only minimal retained control audit events",
        )

    if is_reserved_core_lifecycle_action(action):
        resource_type = "organization"
        resource_id = str(organization_id)
    else:
        if body.resource_type != "organization_closure_execution" or body.resource_id is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Retained closure audit requires an explicit closure execution identity",
            )
        try:
            resource_id = str(UUID(body.resource_id))
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Retained closure audit requires a valid closure execution identity",
            ) from exc
        resource_type = "organization_closure_execution"

    return body.model_copy(
        update={
            "resource_type": resource_type,
            "resource_id": resource_id,
            "old_values": None,
            "new_values": None,
            "metadata": None,
            "ip_address": None,
            "user_agent": None,
        }
    )


@router.get(
    "/organizations/{organization_id}/audit-logs",
    response_model=AuditLogListResponse,
    responses={
        400: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
)
def list_organization_audit_logs(
    organization_id: UUID,
    params: AuditLogListQueryParams = Depends(get_audit_log_list_query_params),
    context: AuthorizationContext = Depends(require_permission("audit.logs.read")),
    use_case: ListOrganizationAuditLogsUseCase = Depends(get_list_organization_audit_logs_use_case),
) -> AuditLogListResponse:
    assert_organization_scope(organization_id, context)
    try:
        result = use_case.execute(audit_log_list_params_to_command(organization_id, params))
    except InvalidAuditQueryError as exc:
        raise map_audit_query_error(exc) from exc

    return audit_log_list_result_to_response(result)


@router.post(
    "/organizations/{organization_id}/audit-events",
    response_model=AuditLogResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
)
def record_organization_audit_event(
    organization_id: UUID,
    body: RecordAuditEventRequest,
    context: AuthenticatedOrganizationContext = Depends(require_organization_access()),
    organization_repository: OrganizationRepository = Depends(get_organization_repository),
    use_case: RecordOrganizationAuditEventUseCase = Depends(get_record_organization_audit_event_use_case),
) -> AuditLogResponse:
    assert_organization_scope(organization_id, context)
    organization = organization_repository.get_by_id_including_deleted(OrganizationId(organization_id))
    if organization is not None and organization.is_deleted():
        body = _terminal_safe_body(organization_id, body)
    elif is_reserved_core_lifecycle_action(body.action):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Core lifecycle audit action namespace is reserved",
        )

    try:
        audit_log = use_case.execute(
            record_audit_event_request_to_command(organization_id, context, body)
        )
    except InvalidAuditEventError as exc:
        raise map_audit_record_error(exc) from exc

    return audit_log_to_response(audit_log)


@router.post(
    "/organizations/{organization_id}/retained-audit-evidence/purge",
    response_model=PurgeRetainedOrganizationAuditResponse,
    dependencies=[Depends(require_product_lifecycle_credential)],
    responses={
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
)
def purge_retained_organization_audit_evidence(
    organization_id: UUID,
    expected_policy_version: str | None = Header(
        default=None,
        alias="X-Kyrox-Retention-Policy-Version",
    ),
    require_already_purged: bool = Header(
        default=False,
        alias="X-Kyrox-Retention-Require-Already-Purged",
    ),
    use_case: PurgeRetainedOrganizationAuditUseCase = Depends(
        get_purge_retained_organization_audit_use_case
    ),
) -> PurgeRetainedOrganizationAuditResponse:
    try:
        result = use_case.execute(
            organization_id,
            expected_policy_version=expected_policy_version,
            require_already_purged=require_already_purged,
        )
    except AuditRetentionOrganizationNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except AuditRetentionPreconditionError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    return PurgeRetainedOrganizationAuditResponse(
        organization_id=result.organization_id,
        policy_version=result.policy_version,
        terminal_deleted_at=result.terminal_deleted_at,
        retention_deadline=result.retention_deadline,
        purged_count=result.purged_count,
        already_purged_verified=result.already_purged_verified,
    )
