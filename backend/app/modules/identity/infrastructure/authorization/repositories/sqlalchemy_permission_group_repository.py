from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.modules.identity.domain.authorization.entities.permission_group import PermissionGroup
from app.modules.identity.domain.authorization.value_objects.identity.permission_group_id import (
    PermissionGroupId,
)
from app.modules.identity.domain.authorization.value_objects.rbac.permission_group_code import (
    PermissionGroupCode,
)
from app.modules.identity.infrastructure.authorization.persistence.mappers.permission_group_mapper import (
    PermissionGroupMapper,
)
from app.modules.identity.infrastructure.authorization.persistence.models.permission_group import (
    PermissionGroupModel,
)


class SqlAlchemyPermissionGroupRepository:
    def __init__(self, session: DbSession) -> None:
        self._session = session

    def add(self, group: PermissionGroup) -> PermissionGroup:
        model = PermissionGroupMapper.to_model(group)
        self._session.add(model)
        self._session.flush()
        self._session.refresh(model)
        return PermissionGroupMapper.to_domain(model)

    def update(self, group: PermissionGroup) -> PermissionGroup:
        model = self._session.get(PermissionGroupModel, group.id.value)
        if model is None:
            raise ValueError(f"Permission group not found: {group.id.value}")

        PermissionGroupMapper.apply_to_model(group, model)
        self._session.flush()
        self._session.refresh(model)
        return PermissionGroupMapper.to_domain(model)

    def remove(self, group_id: PermissionGroupId) -> None:
        model = self._session.get(PermissionGroupModel, group_id.value)
        if model is None:
            raise ValueError(f"Permission group not found: {group_id.value}")

        self._session.delete(model)
        self._session.flush()

    def get_by_id(self, group_id: PermissionGroupId) -> PermissionGroup | None:
        model = self._session.get(PermissionGroupModel, group_id.value)
        if model is None:
            return None
        return PermissionGroupMapper.to_domain(model)

    def get_by_code(self, code: PermissionGroupCode) -> PermissionGroup | None:
        stmt = select(PermissionGroupModel).where(PermissionGroupModel.code == code.value)
        model = self._session.scalars(stmt).first()
        if model is None:
            return None
        return PermissionGroupMapper.to_domain(model)

