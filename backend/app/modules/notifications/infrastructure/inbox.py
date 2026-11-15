from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.modules.audit.application.dto import RecordAuditEventCommand
from app.modules.audit.application.service import AuditService
from app.modules.notifications.application.inbox import Announcement, AnnouncementResult, InboxMessage, InboxReadState
from app.modules.notifications.domain.exceptions import DuplicateIdempotencyConflictError
from app.modules.notifications.infrastructure.persistence.models import PlatformNotificationModel

ANNOUNCEMENT = "platform-announcement"


class SqlAlchemyInboxStore:
    def __init__(self, session: Session, active_recipients: Callable[[], list[UUID]], audit: AuditService) -> None:
        self._session = session
        self._active_recipients = active_recipients
        self._audit = audit

    @staticmethod
    def _personal(user_id: UUID):
        model = PlatformNotificationModel
        return (
            model.organization_id.is_(None), model.channel == "in_app",
            model.status == "sent", model.recipient == str(user_id),
        )

    def list_messages(
        self, user_id: UUID, limit: int, offset: int, read_state: InboxReadState,
    ) -> tuple[list[InboxMessage], int]:
        model = PlatformNotificationModel
        criteria = list(self._personal(user_id))
        if read_state == "unread":
            criteria.append(model.read_at.is_(None))
        elif read_state == "read":
            criteria.append(model.read_at.is_not(None))
        rows = self._session.scalars(
            select(model).where(*criteria)
            .order_by(model.created_at.desc(), model.id.desc()).limit(limit).offset(offset)
        )
        items = [InboxMessage(
            row.id, row.subject, row.body, row.created_at, row.read_at,
            row.template_key == ANNOUNCEMENT,
        ) for row in rows]
        total = self._session.scalar(select(func.count()).select_from(model).where(*criteria)) or 0
        return items, total

    def count_unread(self, user_id: UUID) -> int:
        model = PlatformNotificationModel
        return self._session.scalar(
            select(func.count()).select_from(model).where(*self._personal(user_id), model.read_at.is_(None))
        ) or 0

    def mark_read(self, user_id: UUID, message_id: UUID) -> bool:
        model = PlatformNotificationModel
        return self._session.execute(
            update(model).where(*self._personal(user_id), model.id == message_id)
            .values(read_at=func.coalesce(model.read_at, datetime.now(UTC)))
        ).rowcount == 1

    def list_announcements(self, limit: int, offset: int) -> tuple[list[Announcement], int]:
        model = PlatformNotificationModel
        criteria = (
            model.organization_id.is_(None), model.channel == "in_app",
            model.status == "sent", model.recipient == ANNOUNCEMENT,
            model.idempotency_key.startswith("announcement:"),
        )
        rows = self._session.scalars(
            select(model).where(*criteria)
            .order_by(model.created_at.desc(), model.id.desc()).limit(limit).offset(offset)
        )
        items = [
            Announcement(row.id, row.subject, row.body, row.created_at, int(row.variables["recipient_count"]))
            for row in rows
        ]
        total = self._session.scalar(select(func.count()).select_from(model).where(*criteria)) or 0
        return items, total

    def announce(
        self, actor_id: UUID, session_id: UUID, key: UUID, subject: str, body: str,
    ) -> AnnouncementResult:
        model = PlatformNotificationModel
        request_key = f"announcement:{actor_id}:{key}"
        lookup = select(model).where(model.organization_id.is_(None), model.idempotency_key == request_key)
        existing = self._session.scalar(lookup)
        if existing is not None:
            return self._replay(existing, subject, body)

        recipients = self._active_recipients()
        now = datetime.now(UTC)
        announcement = model(
            id=uuid4(), channel="in_app", recipient=ANNOUNCEMENT,
            subject=subject, body=body, status="sent", sent_at=now, created_at=now,
            idempotency_key=request_key, variables={"recipient_count": len(recipients)},
        )
        try:
            with self._session.begin_nested():
                self._session.add(announcement)
                self._session.flush()
                if recipients:
                    self._session.execute(model.__table__.insert(), [
                        dict(id=uuid4(), channel="in_app", recipient=str(user_id), subject=subject, body=body,
                             status="sent", sent_at=now, created_at=now, template_key=ANNOUNCEMENT)
                        for user_id in recipients
                    ])
                self._audit.record(RecordAuditEventCommand(
                    action="notifications.announcement.sent", resource_type="platform_notification",
                    resource_id=str(announcement.id), user_id=actor_id, session_id=session_id,
                    metadata={"recipient_count": len(recipients)},
                ))
        except IntegrityError:
            existing = self._session.scalar(lookup)
            if existing is None:
                raise
            return self._replay(existing, subject, body)

        return AnnouncementResult(announcement.id, len(recipients), True)

    @staticmethod
    def _replay(row: PlatformNotificationModel, subject: str, body: str) -> AnnouncementResult:
        if row.recipient != ANNOUNCEMENT or row.subject != subject or row.body != body:
            raise DuplicateIdempotencyConflictError("Announcement key already used with a different payload")
        return AnnouncementResult(row.id, int(row.variables["recipient_count"]), False)
