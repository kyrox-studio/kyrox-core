from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class SendNotificationRequest(BaseModel):
    channel: str
    recipient: str
    subject: str
    body: str
    template_key: str | None = None
    variables: dict[str, Any] | None = None
    idempotency_key: str | None = Field(default=None, max_length=128)


class NotificationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID | None
    channel: str
    recipient: str
    subject: str
    status: str
    template_key: str | None
    job_id: UUID | None
    failure_reason: str | None
    failure_code: str | None
    created_at: datetime
    queued_at: datetime | None
    sent_at: datetime | None
    failed_at: datetime | None
    suppressed_at: datetime | None


class SendNotificationResponse(BaseModel):
    notification: NotificationResponse
    created: bool


class ErrorResponse(BaseModel):
    detail: str


class InAppNotificationResponse(BaseModel):
    id: UUID
    subject: str
    body: str
    variables: dict[str, Any] | None
    created_at: datetime


class SystemInAppNotificationRequest(BaseModel):
    recipient: str = "super_admin"
    subject: str
    body: str
    variables: dict[str, Any] | None = None
    idempotency_key: str = Field(min_length=1, max_length=128)


class InboxMessageResponse(BaseModel):
    id: UUID
    subject: str
    body: str
    created_at: datetime
    read_at: datetime | None
    is_announcement: bool


class InboxResponse(BaseModel):
    items: list[InboxMessageResponse]
    total: int
    unread_count: int


class AnnouncementHistoryItem(BaseModel):
    id: UUID
    subject: str
    body: str
    created_at: datetime
    recipient_count: int


class AnnouncementHistoryResponse(BaseModel):
    items: list[AnnouncementHistoryItem]
    total: int


class AnnouncementRequest(BaseModel):
    subject: str = Field(min_length=1, max_length=998)
    body: str = Field(min_length=1, max_length=10000)
    idempotency_key: UUID


class AnnouncementResponse(BaseModel):
    id: UUID
    recipient_count: int
    created: bool
