from dataclasses import dataclass
from datetime import datetime, timedelta

from app.modules.identity.domain.authentication.exceptions import AuthenticationError
from app.modules.identity.domain.authentication.value_objects.client.client_fingerprint import (
    ClientFingerprint,
)
from app.modules.identity.domain.authentication.value_objects.client.device_name import DeviceName
from app.modules.identity.domain.authentication.value_objects.client.ip_address import IpAddress
from app.modules.identity.domain.authentication.value_objects.client.user_agent import UserAgent
from app.modules.identity.domain.authentication.value_objects.identity.session_id import SessionId
from app.modules.identity.domain.authentication.value_objects.identity.user_id import UserId

# Absolute session lifetime used when a caller does not set ``expires_at``
# (ADR-0003 refresh lifetime). Login always sets it from the token policy.
DEFAULT_SESSION_LIFETIME = timedelta(days=30)


@dataclass
class Session:
    id: SessionId
    user_id: UserId
    created_at: datetime
    updated_at: datetime
    last_activity_at: datetime | None = None
    revoked_at: datetime | None = None
    ip_address: IpAddress | None = None
    user_agent: UserAgent | None = None
    device_name: DeviceName | None = None
    client_fingerprint: ClientFingerprint | None = None
    # Absolute end of the session (SECURITY_PROGRAM F-C8). Refresh rotation never
    # extends it; after it the session's access and refresh tokens are rejected.
    expires_at: datetime | None = None

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None

    def is_expired(self, at: datetime) -> bool:
        return self.expires_at is not None and at >= self.expires_at

    def is_usable_at(self, at: datetime) -> bool:
        return self.is_active and not self.is_expired(at)

    def revoke(self, at: datetime) -> None:
        self.revoked_at = at
        self.updated_at = at

    def record_activity(self, at: datetime) -> None:
        self.last_activity_at = at
        self.updated_at = at

    def assert_active(self, at: datetime | None = None) -> None:
        if not self.is_active:
            raise AuthenticationError("Session is no longer active")
        if at is not None and self.is_expired(at):
            raise AuthenticationError("Session has expired")
