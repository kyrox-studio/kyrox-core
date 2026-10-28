import uuid

import pytest

from app.modules.identity.domain.authentication.enums import RefreshTokenRevokeReason, UserStatus
from app.modules.identity.domain.authentication.exceptions import (
    ExpiredRefreshTokenError,
    InactiveUserError,
    InvalidRefreshTokenError,
    LockedUserError,
    RevokedRefreshTokenError,
)
from app.modules.identity.domain.authentication.value_objects.client import (
    ClientFingerprint,
    DeviceName,
    IpAddress,
    UserAgent,
)
from app.modules.identity.domain.authentication.value_objects.identity import UserId
from app.modules.identity.domain.authentication.value_objects.security import (
    AccessToken,
    Email,
    PasswordHash,
    RefreshToken,
    TokenHash,
)


def test_email_create_normalizes_value() -> None:
    email = Email.create("  User@Example.COM  ")
    assert email.value == "user@example.com"


def test_email_create_rejects_invalid_value() -> None:
    with pytest.raises(ValueError, match="Invalid email"):
        Email.create("not-an-email")


def test_access_token_create_rejects_empty_value() -> None:
    with pytest.raises(ValueError, match="Access token cannot be empty"):
        AccessToken.create("   ")


def test_refresh_token_value_object_rejects_empty_value() -> None:
    with pytest.raises(ValueError, match="Refresh token cannot be empty"):
        RefreshToken.create("")


def test_typed_identifiers_require_uuid() -> None:
    user_id = UserId(uuid.uuid4())
    assert isinstance(user_id.value, uuid.UUID)

    with pytest.raises(TypeError):
        UserId("not-a-uuid")  # type: ignore[arg-type]


def test_client_value_objects_enforce_length() -> None:
    IpAddress.create("127.0.0.1")
    UserAgent.create("pytest")
    DeviceName.create("workstation")
    ClientFingerprint.create("fp-123")

    with pytest.raises(ValueError):
        IpAddress.create("x" * 46)


def test_password_hash_and_token_hash_reject_empty_values() -> None:
    with pytest.raises(ValueError):
        PasswordHash("")

    with pytest.raises(ValueError):
        TokenHash("")


def test_refresh_token_revoke_reason_values() -> None:
    assert RefreshTokenRevokeReason.REUSE_DETECTED.value == "reuse_detected"


def test_user_status_includes_locked() -> None:
    assert UserStatus.LOCKED.value == "locked"


def test_authentication_exception_hierarchy() -> None:
    assert issubclass(ExpiredRefreshTokenError, InvalidRefreshTokenError)
    assert issubclass(RevokedRefreshTokenError, InvalidRefreshTokenError)
    assert issubclass(InvalidRefreshTokenError, Exception)
    assert issubclass(InactiveUserError, Exception)
    assert issubclass(LockedUserError, Exception)
