import uuid
from datetime import UTC, datetime

import pytest

from app.modules.identity.domain.authorization.entities import (
    PermissionGroup,
    Role,
    RolePermission,
    UserRole,
)
from app.modules.identity.domain.authorization.enums import AssignmentStatus, RoleScope
from app.modules.identity.domain.authorization.exceptions import InvalidPermissionError, InvalidRoleError
from app.modules.identity.domain.authorization.value_objects.identity import (
    OrganizationId,
    PermissionGroupId,
    PermissionId,
    RoleId,
    UserId,
    UserRoleId,
)
from app.modules.identity.domain.authorization.value_objects.rbac import (
    PermissionGroupCode,
    PermissionModule,
    RoleSlug,
)


def _now() -> datetime:
    return datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)


def test_permission_group_assert_modifiable_blocks_system_group() -> None:
    group = PermissionGroup(
        id=PermissionGroupId(uuid.uuid4()),
        code=PermissionGroupCode.create("identity.users"),
        name="Users",
        module=PermissionModule.create("identity"),
        description="User permissions",
        sort_order=1,
        is_system=True,
        created_at=_now(),
        updated_at=_now(),
    )

    with pytest.raises(InvalidPermissionError):
        group.assert_modifiable()



def test_role_assert_active() -> None:
    role = Role(
        id=RoleId(uuid.uuid4()),
        name="Owner",
        slug=RoleSlug.create("owner"),
        scope=RoleScope.PLATFORM,
        is_system=True,
        created_at=_now(),
        updated_at=_now(),
        deleted_at=_now(),
    )

    with pytest.raises(InvalidRoleError):
        role.assert_active()


def test_user_role_revoke_marks_assignment_ineffective() -> None:
    user_role = UserRole(
        id=UserRoleId(uuid.uuid4()),
        user_id=UserId(uuid.uuid4()),
        organization_id=OrganizationId(uuid.uuid4()),
        role_id=RoleId(uuid.uuid4()),
        status=AssignmentStatus.ACTIVE,
        assigned_at=_now(),
    )

    assert user_role.is_effective() is True
    user_role.revoke(_now())
    assert user_role.is_effective() is False
    assert user_role.status is AssignmentStatus.INACTIVE


def test_role_permission_is_frozen() -> None:
    role_permission = RolePermission(
        role_id=RoleId(uuid.uuid4()),
        permission_id=PermissionId(uuid.uuid4()),
    )

    with pytest.raises(Exception):
        role_permission.role_id = RoleId(uuid.uuid4())  # type: ignore[misc]
