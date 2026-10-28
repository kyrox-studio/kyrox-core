from dataclasses import dataclass
from datetime import datetime

from app.modules.identity.domain.authorization.exceptions import InvalidPermissionError
from app.modules.identity.domain.authorization.value_objects.identity.permission_group_id import (
    PermissionGroupId,
)
from app.modules.identity.domain.authorization.value_objects.identity.permission_id import PermissionId
from app.modules.identity.domain.authorization.value_objects.rbac.permission_code import PermissionCode


@dataclass
class Permission:
    id: PermissionId
    group_id: PermissionGroupId
    code: PermissionCode
    description: str
    is_system: bool
    created_at: datetime
    updated_at: datetime

    def assert_modifiable(self) -> None:
        if self.is_system:
            raise InvalidPermissionError("System permissions cannot be modified")

