
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.modules.identity.domain.authentication.entities.user import User
from app.modules.identity.domain.authentication.ports.clock import Clock
from app.modules.identity.domain.authentication.value_objects.identity.user_id import UserId
from app.modules.identity.domain.authentication.value_objects.security.email import Email
from app.modules.identity.infrastructure.authentication.persistence.mappers.user_mapper import UserMapper
from app.modules.identity.infrastructure.persistence.models import UserModel


class SqlAlchemyUserRepository:
    def __init__(self, session: DbSession, clock: Clock) -> None:
        self._session = session
        self._clock = clock

    def add(self, user: User) -> User:
        model = UserMapper.to_model(user)
        self._session.add(model)
        self._session.flush()
        self._session.refresh(model)
        return UserMapper.to_domain(model)

    def update(self, user: User) -> User:
        model = self._session.get(UserModel, user.id.value)
        if model is None:
            raise ValueError(f"User not found: {user.id.value}")

        UserMapper.apply_to_model(user, model)
        self._session.flush()
        self._session.refresh(model)
        return UserMapper.to_domain(model)

    def remove(self, user_id: UserId) -> None:
        model = self._session.get(UserModel, user_id.value)
        if model is None:
            raise ValueError(f"User not found: {user_id.value}")

        if model.deleted_at is not None:
            return

        model.deleted_at = self._clock.now()
        self._session.flush()

    def get_by_id(self, user_id: UserId) -> User | None:
        model = self._session.get(UserModel, user_id.value)
        if model is None or model.deleted_at is not None:
            return None
        return UserMapper.to_domain(model)

    def get_by_email(self, email: Email) -> User | None:
        stmt = select(UserModel).where(
            UserModel.email == email.value,
            UserModel.deleted_at.is_(None),
        )
        model = self._session.scalars(stmt).first()
        if model is None:
            return None
        return UserMapper.to_domain(model)
