import uuid
from datetime import UTC, datetime

import pytest

from app.modules.identity.domain.authentication.entities import RefreshToken, Session, User
from app.modules.identity.domain.authentication.enums import RefreshTokenRevokeReason, UserStatus
from app.modules.identity.domain.authentication.exceptions import (
    AuthenticationError,
    ExpiredRefreshTokenError,
    InactiveUserError,
    LockedUserError,
    RevokedRefreshTokenError,
)
from app.modules.identity.domain.authentication.value_objects.client import (
    ClientFingerprint,
    DeviceName,
    IpAddress,
    UserAgent,
)
from app.modules.identity.domain.authentication.value_objects.identity import (
    FamilyId,
    RefreshTokenId,
    SessionId,
    UserId,
)
from app.modules.identity.domain.authentication.value_objects.security import (
    Email,
    PasswordHash,
    TokenHash,
)


def _now() -> datetime:
    return datetime.now(tz=UTC)



def test_user_assert_can_authenticate_raises_for_locked_user() -> None:
    user = User(
        id=UserId(uuid.uuid4()),
        email=Email.create("user@example.com"),
        password_hash=PasswordHash("hash"),
        status=UserStatus.LOCKED,
        created_at=_now(),
        updated_at=_now(),
    )

    with pytest.raises(LockedUserError):
        user.assert_can_authenticate()


def test_user_assert_can_authenticate_raises_for_inactive_user() -> None:
    user = User(
        id=UserId(uuid.uuid4()),
        email=Email.create("user@example.com"),
        password_hash=PasswordHash("hash"),
        status=UserStatus.INACTIVE,
        created_at=_now(),
        updated_at=_now(),
    )

    with pytest.raises(InactiveUserError):
        user.assert_can_authenticate()


def test_session_is_active_derived_from_revoked_at() -> None:
    session = Session(
        id=SessionId(uuid.uuid4()),
        user_id=UserId(uuid.uuid4()),
        created_at=_now(),
        updated_at=_now(),
        client_fingerprint=ClientFingerprint.create("fp"),
    )
    assert session.is_active is True

    at = _now()
    session.revoke(at)
    assert session.is_active is False
    assert session.revoked_at == at


def test_session_assert_active_raises_when_revoked() -> None:
    session = Session(
        id=SessionId(uuid.uuid4()),
        user_id=UserId(uuid.uuid4()),
        created_at=_now(),
        updated_at=_now(),
        ip_address=IpAddress.create("10.0.0.1"),
        user_agent=UserAgent.create("agent"),
        device_name=DeviceName.create("iphone"),
    )
    session.revoke(_now())

    with pytest.raises(AuthenticationError, match="Session is no longer active"):
        session.assert_active()


def test_refresh_token_assert_usable_detects_expired_token() -> None:
    token = RefreshToken(
        id=RefreshTokenId(uuid.uuid4()),
        session_id=SessionId(uuid.uuid4()),
        token_hash=TokenHash("abc"),
        family_id=FamilyId(uuid.uuid4()),
        expires_at=datetime(2020, 1, 1, tzinfo=UTC),
        created_at=_now(),
    )

    with pytest.raises(ExpiredRefreshTokenError):
        token.assert_usable(_now())


def test_refresh_token_mark_reuse_detected_revokes_with_reason() -> None:
    token = RefreshToken(
        id=RefreshTokenId(uuid.uuid4()),
        session_id=SessionId(uuid.uuid4()),
        token_hash=TokenHash("abc"),
        family_id=FamilyId(uuid.uuid4()),
        expires_at=_now(),
        created_at=_now(),
    )
    at = _now()
    token.mark_reuse_detected(at)

    assert token.reuse_detected_at == at
    assert token.revoked_reason is RefreshTokenRevokeReason.REUSE_DETECTED
    assert token.is_revoked() is True


def test_refresh_token_assert_usable_detects_revoked_token() -> None:
    token = RefreshToken(
        id=RefreshTokenId(uuid.uuid4()),
        session_id=SessionId(uuid.uuid4()),
        token_hash=TokenHash("abc"),
        family_id=FamilyId(uuid.uuid4()),
        expires_at=_now(),
        created_at=_now(),
    )
    token.revoke(_now(), RefreshTokenRevokeReason.LOGOUT)

    with pytest.raises(RevokedRefreshTokenError):
        token.assert_usable(_now())
