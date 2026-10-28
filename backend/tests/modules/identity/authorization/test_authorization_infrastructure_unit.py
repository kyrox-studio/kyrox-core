import uuid
from datetime import UTC, datetime


from app.modules.identity.domain.authorization.entities import (
    Permission,
    PermissionGroup,
    Role,
    UserRole,
)
from app.modules.identity.domain.authorization.enums import AssignmentStatus, RoleScope
from app.modules.identity.domain.authorization.value_objects.identity import (
    OrganizationId,
    PermissionGroupId,
    PermissionId,
    RoleId,
    UserId,
    UserRoleId,
)
from app.modules.identity.domain.authorization.value_objects.rbac import (
    PermissionCode,
    PermissionGroupCode,
    PermissionModule,
    RoleSlug,
)
from app.modules.identity.infrastructure.authorization.persistence.mappers.permission_group_mapper import (
    PermissionGroupMapper,
)
from app.modules.identity.infrastructure.authorization.persistence.mappers.permission_mapper import (
    PermissionMapper,
)
from app.modules.identity.infrastructure.authorization.persistence.mappers.role_mapper import RoleMapper
from app.modules.identity.infrastructure.authorization.persistence.mappers.user_role_mapper import (
    UserRoleMapper,
)
from app.modules.identity.infrastructure.authorization.persistence.models.permission import PermissionModel
from app.modules.identity.infrastructure.authorization.persistence.models.permission_group import (
    PermissionGroupModel,
)
from app.modules.identity.infrastructure.authorization.persistence.models.role import RoleModel
from app.modules.identity.infrastructure.authorization.persistence.models.user_role import UserRoleModel


def _now() -> datetime:
    return datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)


def test_role_mapper_roundtrip() -> None:
    role = Role(
        id=RoleId(uuid.uuid4()),
        name="Owner",
        slug=RoleSlug.create("owner"),
        scope=RoleScope.ORGANIZATION,
        is_system=True,
        created_at=_now(),
        updated_at=_now(),
    )
    model = RoleMapper.to_model(role)
    assert isinstance(model, RoleModel)
    restored = RoleMapper.to_domain(model)
    assert restored.id.value == role.id.value
    assert restored.slug.value == role.slug.value


def test_permission_group_mapper_roundtrip() -> None:
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
    model = PermissionGroupMapper.to_model(group)
    assert isinstance(model, PermissionGroupModel)
    restored = PermissionGroupMapper.to_domain(model)
    assert restored.code.value == group.code.value


def test_permission_mapper_roundtrip() -> None:
    permission = Permission(
        id=PermissionId(uuid.uuid4()),
        group_id=PermissionGroupId(uuid.uuid4()),
        code=PermissionCode.create("core.user.read"),
        description="Read users",
        is_system=True,
        created_at=_now(),
        updated_at=_now(),
    )
    model = PermissionMapper.to_model(permission)
    assert isinstance(model, PermissionModel)
    restored = PermissionMapper.to_domain(model)
    assert restored.code.value == permission.code.value


def test_user_role_mapper_roundtrip() -> None:
    user_role = UserRole(
        id=UserRoleId(uuid.uuid4()),
        user_id=UserId(uuid.uuid4()),
        organization_id=OrganizationId(uuid.uuid4()),
        role_id=RoleId(uuid.uuid4()),
        status=AssignmentStatus.ACTIVE,
        assigned_at=_now(),
        assigned_by=UserId(uuid.uuid4()),
    )
    model = UserRoleMapper.to_model(user_role)
    assert isinstance(model, UserRoleModel)
    restored = UserRoleMapper.to_domain(model)
    assert restored.assigned_by is not None
    assert restored.assigned_by.value == user_role.assigned_by.value
