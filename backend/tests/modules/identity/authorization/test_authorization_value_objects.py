import uuid

import pytest

from app.modules.identity.domain.authorization.enums import AssignmentStatus, OrganizationStatus, RoleScope
from app.modules.identity.domain.authorization.exceptions import (
    AuthorizationError,
    InvalidPermissionError,
    InvalidRoleError,
    PermissionDeniedError,
)
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
    PlatformUserSnapshot,
    RoleSlug,
)


def test_permission_code_create_normalizes_value() -> None:
    code = PermissionCode.create("  Core.User.Read  ")
    assert code.value == "core.user.read"


@pytest.mark.parametrize(
    "raw",
    (
        "fair_crm.customers.read",
        "fair_crm.scraper.download",
        "fair_crm.admin.backups.read",
        "fair_crm.admin.data_operations.run",
        "fair_crm.dashboard.read",
        "fair_crm.todos.outcomes.deactivate",
    ),
)
def test_permission_code_create_accepts_valid_codes(raw: str) -> None:
    assert PermissionCode.create(raw).value == raw


@pytest.mark.parametrize(
    "raw",
    (
        "fair_crm",
        "fair_crm.",
        "fair_crm..read",
        "fair_crm.admin.backups.",
        ".fair_crm.customers.read",
        "fair_crm.customers.read.",
        "invalid",
    ),
)
def test_permission_code_create_rejects_invalid_value(raw: str) -> None:
    with pytest.raises(ValueError, match="Invalid permission code"):
        PermissionCode.create(raw)


def test_permission_group_code_create_normalizes_value() -> None:
    code = PermissionGroupCode.create(" Identity.Users ")
    assert code.value == "identity.users"


def test_permission_module_accepts_product_namespace() -> None:
    module = PermissionModule.create("fair_crm")
    assert module.value == "fair_crm"



def test_permission_module_rejects_invalid_format() -> None:
    with pytest.raises(ValueError, match="Invalid permission module"):
        PermissionModule.create("crm-module")

    with pytest.raises(ValueError, match="Invalid permission module"):
        PermissionModule.create("")


def test_role_slug_create_normalizes_value() -> None:
    slug = RoleSlug.create(" Owner ")
    assert slug.value == "owner"


def test_typed_identifiers_require_uuid() -> None:
    role_id = RoleId(uuid.uuid4())
    assert isinstance(role_id.value, uuid.UUID)

    with pytest.raises(TypeError):
        RoleId("not-a-uuid")  # type: ignore[arg-type]


def test_platform_user_snapshot_can_be_authorized() -> None:
    snapshot = PlatformUserSnapshot(
        user_id=UserId(uuid.uuid4()),
        is_active=True,
        is_super_admin=False,
        is_deleted=False,
    )
    assert snapshot.can_be_authorized() is True

    inactive = PlatformUserSnapshot(
        user_id=snapshot.user_id,
        is_active=False,
        is_super_admin=False,
        is_deleted=False,
    )
    assert inactive.can_be_authorized() is False


def test_authorization_exception_hierarchy() -> None:
    assert issubclass(PermissionDeniedError, AuthorizationError)
    assert issubclass(InvalidRoleError, AuthorizationError)
    assert issubclass(InvalidPermissionError, AuthorizationError)


def test_role_scope_and_assignment_status_values() -> None:
    assert RoleScope.PLATFORM.value == "platform"
    assert AssignmentStatus.ACTIVE.value == "active"
    assert OrganizationStatus.SUSPENDED.value == "suspended"


def test_all_identity_value_objects_construct_with_uuid() -> None:
    value = uuid.uuid4()
    assert PermissionId(value).value == value
    assert PermissionGroupId(value).value == value
    assert UserRoleId(value).value == value
    assert OrganizationId(value).value == value
    assert UserId(value).value == value
