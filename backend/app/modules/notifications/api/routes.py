from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response, status
from fastapi.responses import JSONResponse

from app.modules.identity.api.authorization.context import AuthorizationContext
from app.modules.identity.api.authorization.dependencies import get_platform_user_reader
from app.modules.identity.api.authorization.guards import get_access_token_claims, require_permission, require_super_admin
from app.modules.identity.domain.authorization.ports.platform_user_reader import PlatformUserReader
from app.modules.identity.domain.authorization.value_objects.identity.user_id import UserId
from app.modules.notifications.application.inbox import InboxReadState, InboxService
from app.modules.identity.domain.authentication.value_objects.security.access_token import AccessTokenClaims
from app.modules.identity.api.authorization.scope import assert_organization_scope
from app.modules.notifications.api.dependencies import (
    NotificationWorkerScheduler,
    get_inbox_service,
    get_get_notification_use_case,
    get_notification_worker_scheduler,
    get_send_notification_use_case,
    get_list_system_in_app_notifications_use_case,
    require_product_notification_credential,
)
from app.modules.notifications.api.error_mapping import map_notification_error
from app.modules.notifications.api.mappers import (
    get_notification_command,
    get_result_to_response,
    send_request_to_command,
    send_result_to_response,
)
from app.modules.notifications.api.schemas import (
    AnnouncementRequest,
    AnnouncementResponse,
    AnnouncementHistoryItem,
    AnnouncementHistoryResponse,
    ErrorResponse,
    InboxMessageResponse,
    InboxResponse,
    NotificationResponse,
    SendNotificationRequest,
    SendNotificationResponse,
)
from app.modules.notifications.application.get_notification import GetNotificationUseCase
from app.modules.notifications.application.send_notification import SendNotificationUseCase
from app.modules.notifications.application.list_in_app_notifications import ListSystemInAppNotificationsUseCase
from app.modules.notifications.application.commands import SendNotificationCommand
from app.modules.notifications.api.schemas import InAppNotificationResponse, SystemInAppNotificationRequest
from app.modules.notifications.domain.exceptions import NotificationError
from app.modules.notifications.domain.value_objects.notification_status import NotificationStatus

router = APIRouter(tags=["notifications"])


@router.post("/system/notifications/in-app", response_model=SendNotificationResponse)
def send_system_in_app_notification(
    body: SystemInAppNotificationRequest,
    _: AccessTokenClaims = Depends(require_super_admin),
    use_case: SendNotificationUseCase = Depends(get_send_notification_use_case),
) -> SendNotificationResponse:
    result = _handle_notification_errors(lambda: use_case.execute(SendNotificationCommand(
        organization_id=None, channel="in_app", recipient=body.recipient,
        subject=body.subject, body=body.body, variables=body.variables,
        template_key=None, idempotency_key=body.idempotency_key,
    )))
    return send_result_to_response(result)


@router.get("/system/notifications/in-app", response_model=list[InAppNotificationResponse])
def list_system_in_app_notifications(
    limit: int = Query(default=50, ge=1, le=100),
    claims: AccessTokenClaims = Depends(require_super_admin),
    use_case: ListSystemInAppNotificationsUseCase = Depends(get_list_system_in_app_notifications_use_case),
) -> list[InAppNotificationResponse]:
    return [InAppNotificationResponse(
        id=item.id, subject=item.subject, body=item.body,
        variables=item.variables, created_at=item.created_at,
    ) for item in use_case.execute(claims.sub.value, limit=limit)]


@router.post("/internal/notifications/in-app", response_model=SendNotificationResponse,
             dependencies=[Depends(require_product_notification_credential)])
def deliver_worker_in_app_notification(
    body: SystemInAppNotificationRequest,
    use_case: SendNotificationUseCase = Depends(get_send_notification_use_case),
) -> SendNotificationResponse:
    result = _handle_notification_errors(lambda: use_case.execute(SendNotificationCommand(
        organization_id=None, channel="in_app", recipient=body.recipient,
        subject=body.subject, body=body.body, variables=body.variables,
        template_key=None, idempotency_key=body.idempotency_key,
    )))
    return send_result_to_response(result)


def _handle_notification_errors(use_case_call):
    try:
        return use_case_call()
    except NotificationError as exc:
        raise map_notification_error(exc) from exc


@router.post(
    "/organizations/{organization_id}/notifications/send",
    response_model=SendNotificationResponse,
    responses={
        400: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
)
def send_organization_notification(
    organization_id: UUID,
    body: SendNotificationRequest,
    background_tasks: BackgroundTasks,
    context: AuthorizationContext = Depends(require_permission("notifications.platform.execute")),
    use_case: SendNotificationUseCase = Depends(get_send_notification_use_case),
    worker_scheduler: NotificationWorkerScheduler = Depends(get_notification_worker_scheduler),
) -> JSONResponse:
    assert_organization_scope(organization_id, context)
    result = _handle_notification_errors(
        lambda: use_case.execute(send_request_to_command(organization_id, body))
    )
    if result.status == NotificationStatus.QUEUED:
        worker_scheduler.schedule(background_tasks)
    response = send_result_to_response(result)
    status_code = (
        status.HTTP_200_OK
        if result.idempotent_replay
        else status.HTTP_202_ACCEPTED
    )
    return JSONResponse(
        status_code=status_code,
        content=response.model_dump(mode="json"),
    )


def require_active_inbox_user(
    claims: AccessTokenClaims = Depends(get_access_token_claims),
    reader: PlatformUserReader = Depends(get_platform_user_reader),
) -> UUID:
    snapshot = reader.get_snapshot(UserId(claims.sub.value))
    if snapshot is None or not snapshot.can_be_authorized():
        raise HTTPException(403, "Active account required")
    return claims.sub.value


@router.get("/notifications/inbox", response_model=InboxResponse)
def list_my_inbox(
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    read_state: InboxReadState = "all",
    user_id: UUID = Depends(require_active_inbox_user),
    inbox: InboxService = Depends(get_inbox_service),
) -> InboxResponse:
    messages, total = inbox.store.list_messages(user_id, limit, offset, read_state)
    return InboxResponse(
        items=[InboxMessageResponse.model_validate(item, from_attributes=True) for item in messages],
        total=total,
        unread_count=total if read_state == "unread" else inbox.store.count_unread(user_id),
    )


@router.put("/notifications/inbox/{message_id}/read", status_code=204)
def mark_my_inbox_message_read(
    message_id: UUID,
    user_id: UUID = Depends(require_active_inbox_user),
    inbox: InboxService = Depends(get_inbox_service),
) -> Response:
    if not inbox.store.mark_read(user_id, message_id):
        raise HTTPException(404, "Notification not found")
    return Response(status_code=204)


@router.get("/system/notifications/announcements", response_model=AnnouncementHistoryResponse)
def list_announcements(
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    _claims: AccessTokenClaims = Depends(require_super_admin),
    inbox: InboxService = Depends(get_inbox_service),
) -> AnnouncementHistoryResponse:
    items, total = inbox.store.list_announcements(limit, offset)
    return AnnouncementHistoryResponse(
        items=[AnnouncementHistoryItem.model_validate(item, from_attributes=True) for item in items],
        total=total,
    )


@router.post("/system/notifications/announcements", response_model=AnnouncementResponse)
def send_announcement(
    body: AnnouncementRequest,
    claims: AccessTokenClaims = Depends(require_super_admin),
    inbox: InboxService = Depends(get_inbox_service),
) -> AnnouncementResponse:
    result = _handle_notification_errors(lambda: inbox.announce(
        claims.sub.value, claims.sid.value, body.idempotency_key, body.subject, body.body,
    ))
    return AnnouncementResponse.model_validate(result, from_attributes=True)


@router.get(
    "/notifications/{notification_id}",
    response_model=NotificationResponse,
    responses={
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
)
def get_notification_status(
    notification_id: UUID,
    context: AuthorizationContext = Depends(require_permission("notifications.platform.read")),
    use_case: GetNotificationUseCase = Depends(get_get_notification_use_case),
) -> NotificationResponse:
    result = _handle_notification_errors(
        lambda: use_case.execute(
            get_notification_command(
                notification_id,
                None if context.is_super_admin else context.organization_id,
            )
        )
    )
    return get_result_to_response(result)
