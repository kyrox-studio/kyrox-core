from collections.abc import Callable
from uuid import UUID

from sqlalchemy.orm import Session as DbSession

from app.modules.jobs.domain.entities import Job
from app.modules.jobs.domain.ports import JobHandler, JobHandlerResult
from app.modules.notifications.application.commands import DispatchNotificationCommand
from app.modules.notifications.application.dispatch_notification import DispatchNotificationUseCase
from app.modules.notifications.application.policy import NotificationPolicy
from app.modules.notifications.application.ports.content_renderer import NotificationContentRenderer
from app.modules.notifications.domain.ports import NotificationChannelRegistry
from app.modules.notifications.infrastructure.jobs.handler_context import get_notification_handler_session
from app.modules.notifications.infrastructure.repositories import SqlAlchemyNotificationRepository
from app.modules.notifications.infrastructure.settings_reader import (
    NotificationSettingsReaderAdapter,
    SettingRepositoryOrganizationSettingReader,
)
from app.modules.settings.infrastructure.repositories import SqlAlchemySettingRepository


def build_dispatch_notification_use_case(
    session: DbSession,
    channel_registry: NotificationChannelRegistry,
    content_renderer: NotificationContentRenderer | None = None,
) -> DispatchNotificationUseCase:
    setting_reader = SettingRepositoryOrganizationSettingReader(
        SqlAlchemySettingRepository(session)
    )
    return DispatchNotificationUseCase(
        notification_repository=SqlAlchemyNotificationRepository(session),
        channel_registry=channel_registry,
        settings_reader=NotificationSettingsReaderAdapter(setting_reader),
        notification_policy=NotificationPolicy(),
        content_renderer=content_renderer,
    )


class NotificationDispatchJobHandler(JobHandler):
    def __init__(
        self,
        *,
        session_factory: Callable[[], DbSession],
        channel_registry: NotificationChannelRegistry,
        content_renderer_factory: Callable[[DbSession], NotificationContentRenderer] | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._channel_registry = channel_registry
        self._content_renderer_factory = content_renderer_factory

    def handle(self, job: Job) -> JobHandlerResult:
        raw_notification_id = job.payload.get("notification_id")
        if raw_notification_id is None:
            raise ValueError("Missing notification_id in job payload")
        notification_id = UUID(str(raw_notification_id))

        shared_session = get_notification_handler_session()
        session = shared_session if shared_session is not None else self._session_factory()
        owns_session = shared_session is None
        try:
            content_renderer = (
                self._content_renderer_factory(session)
                if self._content_renderer_factory is not None
                else None
            )
            use_case = build_dispatch_notification_use_case(
                session,
                self._channel_registry,
                content_renderer,
            )
            result = use_case.execute(
                DispatchNotificationCommand(notification_id=notification_id)
            )
            if owns_session:
                session.commit()
            return JobHandlerResult(
                result={
                    "notification_id": str(result.notification_id),
                    "status": result.status.value,
                    "idempotent_noop": result.idempotent_noop,
                },
                retryable=False,
            )
        except Exception:
            if owns_session:
                session.rollback()
            raise
        finally:
            if owns_session:
                session.close()
