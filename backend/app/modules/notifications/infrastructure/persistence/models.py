from datetime import datetime
from typing import Any
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy import CheckConstraint, Index, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import UTCDateTime, UUIDPrimaryKey
from app.db.utils import generate_uuid


class PlatformNotificationModel(Base):
    __tablename__ = "platform_notifications"
    __table_args__ = (
        CheckConstraint("channel IN ('email', 'in_app')", name="ck_platform_notifications_channel"),
        CheckConstraint(
            "status IN ('pending', 'queued', 'sending', 'sent', 'failed', 'suppressed')",
            name="ck_platform_notifications_status",
        ),
        Index("ix_platform_notifications_organization_id", "organization_id"),
        Index("ix_platform_notifications_status_created", "status", "created_at"),
        Index("ix_platform_notifications_job_id", "job_id"),
        Index("ix_platform_notifications_inbox", "recipient", "channel", "status", "created_at"),
        Index(
            "uq_platform_notifications_org_idempotency",
            "organization_id",
            "idempotency_key",
            unique=True,
            postgresql_where=sa.text("idempotency_key IS NOT NULL"),
            sqlite_where=sa.text("idempotency_key IS NOT NULL"),
        ),
        Index(
            "uq_platform_notifications_platform_idempotency",
            "idempotency_key",
            unique=True,
            postgresql_where=sa.text(
                "organization_id IS NULL AND idempotency_key IS NOT NULL"
            ),
            sqlite_where=sa.text(
                "organization_id IS NULL AND idempotency_key IS NOT NULL"
            ),
        ),
    )

    id: Mapped[UUID] = mapped_column(
        UUIDPrimaryKey,
        primary_key=True,
        default=generate_uuid,
    )
    organization_id: Mapped[UUID | None] = mapped_column(UUIDPrimaryKey, nullable=True)
    channel: Mapped[str] = mapped_column(String(32), nullable=False)
    recipient: Mapped[str] = mapped_column(String(320), nullable=False)
    subject: Mapped[str] = mapped_column(String(998), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    template_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    variables: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    job_id: Mapped[UUID | None] = mapped_column(UUIDPrimaryKey, nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    failure_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        nullable=False,
        server_default=func.now(),
    )
    read_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    queued_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    failed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    suppressed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
