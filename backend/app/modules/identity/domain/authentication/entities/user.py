from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from app.modules.identity.domain.authentication.enums.user_status import UserStatus
from app.modules.identity.domain.authentication.exceptions import (
    InactiveUserError,
    LockedUserError,
)
from app.modules.identity.domain.authentication.value_objects.identity.user_id import UserId
from app.modules.identity.domain.authentication.value_objects.security.email import Email
from app.modules.identity.domain.authentication.value_objects.security.password_hash import (
    PasswordHash,
)


@dataclass
class User:
    id: UserId
    email: Email
    password_hash: PasswordHash | None
    status: UserStatus
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None = None
    organization_id: UUID | None = None
    is_super_admin: bool = False

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None


    def is_locked(self) -> bool:
        return self.status is UserStatus.LOCKED

    def assert_can_authenticate(self) -> None:
        if self.is_deleted or self.status is UserStatus.INACTIVE:
            raise InactiveUserError("User account is not active")
        if self.is_locked() or self.status is UserStatus.SUSPENDED:
            raise LockedUserError("User account is locked")
