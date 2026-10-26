from datetime import UTC, datetime

from app.modules.identity.domain.authentication.entities.session import (
    DEFAULT_SESSION_LIFETIME,
    Session,
)
from app.modules.identity.domain.authentication.value_objects.client.client_fingerprint import (
    ClientFingerprint,
)
from app.modules.identity.domain.authentication.value_objects.client.device_name import DeviceName
from app.modules.identity.domain.authentication.value_objects.client.ip_address import IpAddress
from app.modules.identity.domain.authentication.value_objects.client.user_agent import UserAgent
from app.modules.identity.domain.authentication.value_objects.identity.session_id import SessionId
from app.modules.identity.domain.authentication.value_objects.identity.user_id import UserId
from app.modules.identity.infrastructure.authentication.persistence.models.session import SessionModel


def _as_utc(value: datetime | None) -> datetime | None:
    # SQLite drops the offset of timezone-aware columns; stored values are UTC.
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


class SessionMapper:
    @staticmethod
    def _optional_vo(raw: str | None, factory: type) -> object | None:
        if raw is None:
            return None
        try:
            return factory.create(raw)
        except ValueError:
            return None

    @staticmethod
    def to_domain(model: SessionModel) -> Session:
        return Session(
            id=SessionId(model.id),
            user_id=UserId(model.user_id),
            created_at=model.created_at,
            updated_at=model.updated_at,
            last_activity_at=model.last_activity_at,
            revoked_at=model.revoked_at,
            expires_at=_as_utc(model.expires_at),
            ip_address=SessionMapper._optional_vo(model.ip_address, IpAddress),
            user_agent=SessionMapper._optional_vo(model.user_agent, UserAgent),
            device_name=SessionMapper._optional_vo(model.device_name, DeviceName),
            client_fingerprint=SessionMapper._optional_vo(
                model.client_fingerprint,
                ClientFingerprint,
            ),
        )

    @staticmethod
    def to_model(entity: Session) -> SessionModel:
        return SessionModel(
            id=entity.id.value,
            user_id=entity.user_id.value,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
            last_activity_at=entity.last_activity_at,
            revoked_at=entity.revoked_at,
            expires_at=(
                entity.expires_at
                if entity.expires_at is not None
                else entity.created_at + DEFAULT_SESSION_LIFETIME
            ),
            ip_address=entity.ip_address.value if entity.ip_address else None,
            user_agent=entity.user_agent.value if entity.user_agent else None,
            device_name=entity.device_name.value if entity.device_name else None,
            client_fingerprint=(
                entity.client_fingerprint.value if entity.client_fingerprint else None
            ),
        )

    @staticmethod
    def apply_to_model(entity: Session, model: SessionModel) -> None:
        model.updated_at = entity.updated_at
        model.last_activity_at = entity.last_activity_at
        model.revoked_at = entity.revoked_at
        model.ip_address = entity.ip_address.value if entity.ip_address else None
        model.user_agent = entity.user_agent.value if entity.user_agent else None
        model.device_name = entity.device_name.value if entity.device_name else None
        model.client_fingerprint = (
            entity.client_fingerprint.value if entity.client_fingerprint else None
        )
