from app.modules.identity.application.authorization.commands import CheckPermissionCommand
from app.modules.identity.application.authorization.policy import PermissionPolicy
from app.modules.identity.application.authorization.results import AuthorizationDecision
from app.modules.identity.domain.authorization.exceptions import PermissionDeniedError
from app.modules.identity.domain.authorization.ports.permission_checker import PermissionChecker
from app.modules.identity.domain.authorization.ports.platform_user_reader import PlatformUserReader
from app.modules.identity.domain.authorization.value_objects.rbac.permission_code import PermissionCode


class AuthorizationService:
    def __init__(
        self,
        platform_user_reader: PlatformUserReader,
        permission_checker: PermissionChecker,
        permission_policy: PermissionPolicy | None = None,
    ) -> None:
        self._platform_user_reader = platform_user_reader
        self._permission_checker = permission_checker
        self._permission_policy = permission_policy or PermissionPolicy()

    def check_permission(self, command: CheckPermissionCommand) -> AuthorizationDecision:
        snapshot = self._platform_user_reader.get_snapshot(command.user_id)

        # The DB-backed Super Admin flag is the first authorization rule.
        # It bypasses account authorization state, permission normalization,
        # RBAC lookup, CRUD grants, memberships and organization-scoped roles.
        if snapshot is not None and snapshot.is_super_admin:
            raw_permission = command.permission_code.strip().lower()
            return AuthorizationDecision(
                allowed=True,
                permission_code=PermissionCode(value=raw_permission or "super_admin.bypass.allowed"),
                bypassed_by_super_admin=True,
            )

        permission_code = self._permission_policy.normalize(command.permission_code)
        if snapshot is None or not snapshot.can_be_authorized():
            return AuthorizationDecision(
                allowed=False,
                permission_code=permission_code,
                denial_reason="user_not_authorizable",
            )

        allowed = self._permission_checker.has_permission(
            command.user_id,
            command.organization_id,
            permission_code,
        )
        if allowed:
            return AuthorizationDecision(
                allowed=True,
                permission_code=permission_code,
            )

        return AuthorizationDecision(
            allowed=False,
            permission_code=permission_code,
            denial_reason="permission_denied",
        )

    def has_permission(self, command: CheckPermissionCommand) -> bool:
        return self.check_permission(command).allowed

    def require_permission(self, command: CheckPermissionCommand) -> None:
        decision = self.check_permission(command)
        if decision.is_denied:
            raise PermissionDeniedError(
                f"Permission denied: {decision.permission_code.value} "
                f"for organization {command.organization_id.value}"
            )
