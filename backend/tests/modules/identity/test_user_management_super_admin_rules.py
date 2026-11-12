import uuid
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.core.exceptions import AppException
from app.modules.identity.api.authorization.context import AuthorizationContext
from app.modules.identity.infrastructure.user_management.service import (
    actor_is_super_admin as _actor_is_super_admin,
    assert_super_admin_change_allowed as _assert_super_admin_change_allowed,
)


def _context() -> AuthorizationContext:
    return AuthorizationContext(
        user_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        email="actor@example.com",
    )


@pytest.mark.parametrize(
    ("status", "deleted_at", "is_super_admin", "expected"),
    [
        ("active", None, True, True),
        ("suspended", None, True, False),
        ("active", object(), True, False),
        ("active", None, False, False),
    ],
)
def test_only_active_non_deleted_super_admin_can_change_the_flag(
    status: str,
    deleted_at: object | None,
    is_super_admin: bool,
    expected: bool,
) -> None:
    db = Mock()
    db.get.return_value = SimpleNamespace(
        status=status,
        deleted_at=deleted_at,
        is_super_admin=is_super_admin,
    )

    assert _actor_is_super_admin(db, uuid.uuid4()) is expected


def test_non_super_admin_cannot_grant_or_revoke_super_admin() -> None:
    db = Mock()
    db.get.return_value = SimpleNamespace(
        status="active",
        deleted_at=None,
        is_super_admin=False,
    )

    for requested in (True, False):
        with pytest.raises(AppException) as exc_info:
            _assert_super_admin_change_allowed(db, _context(), requested)

        assert exc_info.value.status_code == 403


def test_active_super_admin_can_grant_or_revoke_super_admin() -> None:
    db = Mock()
    db.get.return_value = SimpleNamespace(
        status="active",
        deleted_at=None,
        is_super_admin=True,
    )

    for requested in (True, False):
        assert _assert_super_admin_change_allowed(db, _context(), requested) is True
