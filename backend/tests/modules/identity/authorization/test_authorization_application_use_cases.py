import uuid

import pytest

from app.modules.identity.application.authorization import (
    AuthorizationService,
    CheckPermissionCommand,
    PermissionPolicy,
)
from app.modules.identity.domain.authorization.exceptions import (
    InvalidPermissionError,
    PermissionDeniedError,
)
from app.modules.identity.domain.authorization.value_objects.identity.organization_id import (
    OrganizationId,
)
from app.modules.identity.domain.authorization.value_objects.identity.user_id import UserId
from app.modules.identity.domain.authorization.value_objects.rbac.permission_code import (
    PermissionCode,
)
from app.modules.identity.domain.authorization.value_objects.rbac.platform_user_snapshot import (
    PlatformUserSnapshot,
)


class FakePlatformUserReader:
    def __init__(self, snapshots: dict[UserId, PlatformUserSnapshot]) -> None:
        self._snapshots = snapshots

    def get_snapshot(self, user_id: UserId) -> PlatformUserSnapshot | None:
        return self._snapshots.get(user_id)


class FakePermissionChecker:
    def __init__(self, allowed_codes: set[str]) -> None:
        self._allowed_codes = allowed_codes
        self.calls: list[tuple[UserId, OrganizationId, PermissionCode]] = []

    def has_permission(
        self,
        user_id: UserId,
        organization_id: OrganizationId,
        permission_code: PermissionCode,
    ) -> bool:
        self.calls.append((user_id, organization_id, permission_code))
        return permission_code.value in self._allowed_codes


def _command(
    user_id: uuid.UUID | None = None,
    organization_id: uuid.UUID | None = None,
    permission_code: str = "core.user.read",
) -> CheckPermissionCommand:
    return CheckPermissionCommand(
        user_id=UserId(user_id or uuid.uuid4()),
        organization_id=OrganizationId(organization_id or uuid.uuid4()),
        permission_code=permission_code,
    )


def test_check_permission_allows_matching_rbac_permission() -> None:
    user_id = UserId(uuid.uuid4())
    org_id = OrganizationId(uuid.uuid4())
    reader = FakePlatformUserReader(
        {
            user_id: PlatformUserSnapshot(
                user_id=user_id,
                is_active=True,
                is_super_admin=False,
                is_deleted=False,
            )
        }
    )
    checker = FakePermissionChecker({"core.user.read"})
    service = AuthorizationService(
        platform_user_reader=reader,
        permission_checker=checker,
    )

    decision = service.check_permission(
        CheckPermissionCommand(
            user_id=user_id,
            organization_id=org_id,
            permission_code="core.user.read",
        )
    )

    assert decision.allowed is True
    assert decision.bypassed_by_super_admin is False
    assert decision.permission_code.value == "core.user.read"
    assert len(checker.calls) == 1


def test_check_permission_denies_missing_rbac_permission() -> None:
    user_id = UserId(uuid.uuid4())
    reader = FakePlatformUserReader(
        {
            user_id: PlatformUserSnapshot(
                user_id=user_id,
                is_active=True,
                is_super_admin=False,
                is_deleted=False,
            )
        }
    )
    checker = FakePermissionChecker(set())
    service = AuthorizationService(
        platform_user_reader=reader,
        permission_checker=checker,
    )

    decision = service.check_permission(_command(user_id=user_id.value))

    assert decision.allowed is False
    assert decision.denial_reason == "permission_denied"


def test_check_permission_denies_inactive_user_without_calling_checker() -> None:
    user_id = UserId(uuid.uuid4())
    reader = FakePlatformUserReader(
        {
            user_id: PlatformUserSnapshot(
                user_id=user_id,
                is_active=False,
                is_super_admin=False,
                is_deleted=False,
            )
        }
    )
    checker = FakePermissionChecker({"core.user.read"})
    service = AuthorizationService(
        platform_user_reader=reader,
        permission_checker=checker,
    )

    decision = service.check_permission(_command(user_id=user_id.value))

    assert decision.allowed is False
    assert decision.denial_reason == "user_not_authorizable"
    assert checker.calls == []


def test_super_admin_bypasses_rbac_for_core_permissions() -> None:
    user_id = UserId(uuid.uuid4())
    reader = FakePlatformUserReader(
        {
            user_id: PlatformUserSnapshot(
                user_id=user_id,
                is_active=True,
                is_super_admin=True,
                is_deleted=False,
            )
        }
    )
    checker = FakePermissionChecker(set())
    service = AuthorizationService(
        platform_user_reader=reader,
        permission_checker=checker,
    )

    decision = service.check_permission(
        _command(user_id=user_id.value, permission_code="core.user.read")
    )

    assert decision.allowed is True
    assert decision.bypassed_by_super_admin is True
    assert checker.calls == []


def test_super_admin_bypasses_non_core_permissions_without_rbac_lookup() -> None:
    user_id = UserId(uuid.uuid4())
    reader = FakePlatformUserReader(
        {
            user_id: PlatformUserSnapshot(
                user_id=user_id,
                is_active=True,
                is_super_admin=True,
                is_deleted=False,
            )
        }
    )
    checker = FakePermissionChecker({"identity.roles.read"})
    service = AuthorizationService(
        platform_user_reader=reader,
        permission_checker=checker,
    )

    decision = service.check_permission(
        _command(user_id=user_id.value, permission_code="identity.roles.read")
    )

    assert decision.allowed is True
    assert decision.bypassed_by_super_admin is True
    assert checker.calls == []


def test_super_admin_bypasses_account_authorization_state() -> None:
    user_id = UserId(uuid.uuid4())
    reader = FakePlatformUserReader(
        {
            user_id: PlatformUserSnapshot(
                user_id=user_id,
                is_active=True,
                is_super_admin=True,
                is_deleted=True,
            )
        }
    )
    checker = FakePermissionChecker({"core.user.read"})
    service = AuthorizationService(
        platform_user_reader=reader,
        permission_checker=checker,
    )

    decision = service.check_permission(
        _command(user_id=user_id.value, permission_code="core.user.read")
    )

    assert decision.allowed is True
    assert decision.bypassed_by_super_admin is True
    assert checker.calls == []


def test_permission_policy_validate_rejects_invalid_code() -> None:
    policy = PermissionPolicy()

    with pytest.raises(InvalidPermissionError):
        policy.validate("invalid")


def test_permission_policy_normalize_lowercases_code() -> None:
    policy = PermissionPolicy()
    assert policy.normalize(" Core.User.Read ").value == "core.user.read"


def test_permission_policy_normalize_accepts_nested_admin_codes() -> None:
    policy = PermissionPolicy()
    assert policy.normalize("fair_crm.admin.backups.read").value == "fair_crm.admin.backups.read"



def test_has_permission_returns_boolean() -> None:
    user_id = UserId(uuid.uuid4())
    reader = FakePlatformUserReader(
        {
            user_id: PlatformUserSnapshot(
                user_id=user_id,
                is_active=True,
                is_super_admin=False,
                is_deleted=False,
            )
        }
    )
    checker = FakePermissionChecker({"core.user.read"})
    service = AuthorizationService(
        platform_user_reader=reader,
        permission_checker=checker,
    )

    assert service.has_permission(_command(user_id=user_id.value)) is True


def test_require_permission_raises_on_denial() -> None:
    user_id = UserId(uuid.uuid4())
    reader = FakePlatformUserReader(
        {
            user_id: PlatformUserSnapshot(
                user_id=user_id,
                is_active=True,
                is_super_admin=False,
                is_deleted=False,
            )
        }
    )
    checker = FakePermissionChecker(set())
    service = AuthorizationService(
        platform_user_reader=reader,
        permission_checker=checker,
    )

    with pytest.raises(PermissionDeniedError):
        service.require_permission(_command(user_id=user_id.value))


def test_authorization_decision_is_immutable() -> None:
    decision = AuthorizationService(
        platform_user_reader=FakePlatformUserReader({}),
        permission_checker=FakePermissionChecker(set()),
    ).check_permission(_command())

    with pytest.raises(Exception):
        decision.allowed = True  # type: ignore[misc]
