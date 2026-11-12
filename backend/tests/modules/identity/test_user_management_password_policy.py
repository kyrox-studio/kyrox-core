import pytest

from app.core.exceptions import AppException
from app.modules.identity.infrastructure.user_management.service import hash_password as _hash_password
from app.modules.identity.domain.authentication.value_objects.security.password_hash import (
    PasswordHash,
)
from app.modules.identity.infrastructure.authentication.security import Argon2idPasswordHasher


def test_manual_user_password_hash_uses_shared_policy() -> None:
    raw_password = "correct horse battery staple"

    password_hash = _hash_password(raw_password)

    assert Argon2idPasswordHasher().verify(raw_password, PasswordHash(password_hash)) is True


def test_manual_user_password_hash_rejects_short_password_without_echoing_secret() -> None:
    raw_password = "secret"

    with pytest.raises(AppException) as exc_info:
        _hash_password(raw_password)

    assert exc_info.value.status_code == 422
    assert "at least 12 characters" in exc_info.value.message
    assert raw_password not in exc_info.value.message


def test_manual_user_password_hash_rejects_oversized_password() -> None:
    with pytest.raises(AppException) as exc_info:
        _hash_password("a" * 256)

    assert exc_info.value.status_code == 422
    assert "at most 255 characters" in exc_info.value.message
