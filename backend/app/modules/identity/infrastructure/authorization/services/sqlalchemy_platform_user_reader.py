from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session as DbSession

from app.modules.identity.domain.authentication.enums.user_status import UserStatus
from app.modules.identity.domain.authorization.value_objects.identity.user_id import UserId
from app.modules.identity.domain.authorization.value_objects.rbac.platform_user_snapshot import (
    PlatformUserSnapshot,
)
from app.modules.identity.infrastructure.persistence.models import OrganizationModel, UserModel


class SqlAlchemyPlatformUserReader:
    def __init__(self, session: DbSession) -> None:
        self._session = session

    def get_snapshot(self, user_id: UserId) -> PlatformUserSnapshot | None:
        model = self._session.get(UserModel, user_id.value)
        if model is None:
            return None

        return PlatformUserSnapshot(
            user_id=user_id,
            is_active=UserStatus(model.status) is UserStatus.ACTIVE,
            is_super_admin=model.is_super_admin,
            is_deleted=model.deleted_at is not None,
            organization_id=model.organization_id,
        )

    def list_active_notification_recipients(self) -> list[UUID]:
        return list(self._session.scalars(
            select(UserModel.id)
            .outerjoin(OrganizationModel, UserModel.organization_id == OrganizationModel.id)
            .where(
                UserModel.status == UserStatus.ACTIVE.value,
                UserModel.deleted_at.is_(None),
                or_(
                    UserModel.is_super_admin.is_(True),
                    (OrganizationModel.status == "active") & OrganizationModel.deleted_at.is_(None),
                ),
            )
        ))
