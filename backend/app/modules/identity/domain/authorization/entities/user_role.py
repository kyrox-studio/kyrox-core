from dataclasses import dataclass
from datetime import datetime

from app.modules.identity.domain.authorization.enums.assignment_status import AssignmentStatus
from app.modules.identity.domain.authorization.value_objects.identity.organization_id import (
    OrganizationId,
)
from app.modules.identity.domain.authorization.value_objects.identity.role_id import RoleId
from app.modules.identity.domain.authorization.value_objects.identity.user_id import UserId
from app.modules.identity.domain.authorization.value_objects.identity.user_role_id import UserRoleId


@dataclass
class UserRole:
    id: UserRoleId
    user_id: UserId
    organization_id: OrganizationId
    role_id: RoleId
    status: AssignmentStatus
    assigned_at: datetime
    revoked_at: datetime | None = None
    assigned_by: UserId | None = None

    def is_effective(self) -> bool:
        return self.status is AssignmentStatus.ACTIVE and self.revoked_at is None


    def revoke(self, at: datetime) -> None:
        self.revoked_at = at
        self.status = AssignmentStatus.INACTIVE
