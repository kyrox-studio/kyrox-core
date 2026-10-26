from uuid import UUID

from sqlalchemy import Boolean, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, BaseModelMixin
from app.db.types import UUIDPrimaryKey


class UserModel(BaseModelMixin, Base):
    __tablename__ = "identity_users"

    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    is_super_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    organization_id: Mapped[UUID | None] = mapped_column(
        UUIDPrimaryKey,
        ForeignKey(
            "identity_organizations.id",
            ondelete="CASCADE",
            onupdate="CASCADE",
        ),
        nullable=True,
        index=True,
    )


from app.modules.identity.infrastructure.authentication.persistence.models.identity_action_token import (
    IdentityActionTokenModel,
)
from app.modules.identity.infrastructure.authentication.persistence.models.login_throttle import (
    LoginThrottleModel,
)
from app.modules.identity.infrastructure.authentication.persistence.models.refresh_token import (
    RefreshTokenModel,
)
from app.modules.identity.infrastructure.authentication.persistence.models.session import SessionModel
from app.modules.identity.infrastructure.authorization.persistence.models import (
    PermissionGroupModel,
    PermissionModel,
    RoleModel,
    RolePermissionModel,
    UserRoleModel,
)
from app.modules.identity.infrastructure.organization.persistence.models.organization import OrganizationModel
