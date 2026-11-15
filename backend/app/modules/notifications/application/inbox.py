from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol
from uuid import UUID

from app.modules.notifications.application.policy import NotificationPolicy

InboxReadState = Literal["all", "unread", "read"]


@dataclass(frozen=True)
class InboxMessage:
    id: UUID
    subject: str
    body: str
    created_at: datetime
    read_at: datetime | None
    is_announcement: bool


@dataclass(frozen=True)
class Announcement:
    id: UUID
    subject: str
    body: str
    created_at: datetime
    recipient_count: int


@dataclass(frozen=True)
class AnnouncementResult:
    id: UUID
    recipient_count: int
    created: bool


class InboxStore(Protocol):
    def list_announcements(self, limit: int, offset: int) -> tuple[list[Announcement], int]: ...
    def list_messages(
        self, user_id: UUID, limit: int, offset: int, read_state: InboxReadState,
    ) -> tuple[list[InboxMessage], int]: ...
    def count_unread(self, user_id: UUID) -> int: ...
    def mark_read(self, user_id: UUID, message_id: UUID) -> bool: ...
    def announce(
        self, actor_id: UUID, session_id: UUID, key: UUID, subject: str, body: str,
    ) -> AnnouncementResult: ...


class InboxService:
    def __init__(self, store: InboxStore, policy: NotificationPolicy) -> None:
        self.store = store
        self._policy = policy

    def announce(
        self, actor_id: UUID, session_id: UUID, key: UUID, subject: str, body: str,
    ) -> AnnouncementResult:
        return self.store.announce(
            actor_id, session_id, key,
            self._policy.normalize_subject(subject), self._policy.normalize_body(body),
        )
