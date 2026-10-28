import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db.base import Base
from app.modules.identity.domain.authentication.entities.refresh_token import RefreshToken
from app.modules.identity.domain.authentication.entities.session import Session as AuthSession
from app.modules.identity.domain.authentication.entities.user import User
from app.modules.identity.domain.authentication.enums.refresh_token_revoke_reason import (
    RefreshTokenRevokeReason,
)
from app.modules.identity.domain.authentication.enums.user_status import UserStatus
from app.modules.identity.domain.authentication.value_objects.identity.family_id import FamilyId
from app.modules.identity.domain.authentication.value_objects.identity.refresh_token_id import (
    RefreshTokenId,
)
from app.modules.identity.domain.authentication.value_objects.identity.session_id import SessionId
from app.modules.identity.domain.authentication.value_objects.identity.user_id import UserId
from app.modules.identity.domain.authentication.value_objects.security.email import Email
from app.modules.identity.domain.authentication.value_objects.security.password_hash import (
    PasswordHash,
)
from app.modules.identity.domain.authentication.value_objects.security.token_hash import TokenHash
from app.modules.identity.infrastructure.authentication.repositories.sqlalchemy_refresh_token_repository import (
    SqlAlchemyRefreshTokenRepository,
)
from app.modules.identity.infrastructure.authentication.repositories.sqlalchemy_session_repository import (
    SqlAlchemySessionRepository,
)
from app.modules.identity.infrastructure.authentication.repositories.sqlalchemy_user_repository import (
    SqlAlchemyUserRepository,
)
from app.modules.identity.infrastructure.persistence import models as identity_models  # noqa: F401


class FixedClock:
    def __init__(self, now: datetime) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now


@pytest.fixture
def db_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _now() -> datetime:
    return datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)


def test_sqlalchemy_user_repository_add_update_remove(db_session: Session) -> None:
    clock = FixedClock(_now())
    repo = SqlAlchemyUserRepository(db_session, clock)
    user = User(
        id=UserId(uuid.uuid4()),
        email=Email.create("user@example.com"),
        password_hash=PasswordHash("hash"),
        status=UserStatus.ACTIVE,
        created_at=_now(),
        updated_at=_now(),
    )

    created = repo.add(user)
    db_session.commit()
    assert repo.get_by_email(Email.create("user@example.com")) is not None

    created.status = UserStatus.INACTIVE
    created.updated_at = _now()
    updated = repo.update(created)
    db_session.commit()
    assert updated.status is UserStatus.INACTIVE

    repo.remove(created.id)
    db_session.commit()
    assert repo.get_by_id(created.id) is None


def test_sqlalchemy_session_repository_add_update_remove(db_session: Session) -> None:
    clock = FixedClock(_now())
    user_repo = SqlAlchemyUserRepository(db_session, clock)
    session_repo = SqlAlchemySessionRepository(db_session)

    user = user_repo.add(
        User(
            id=UserId(uuid.uuid4()),
            email=Email.create("session-user@example.com"),
            password_hash=PasswordHash("hash"),
            status=UserStatus.ACTIVE,
            created_at=_now(),
            updated_at=_now(),
        )
    )
    db_session.flush()

    auth_session = AuthSession(
        id=SessionId(uuid.uuid4()),
        user_id=user.id,
        created_at=_now(),
        updated_at=_now(),
    )
    created = session_repo.add(auth_session)
    db_session.commit()

    loaded = session_repo.get_by_id(created.id)
    assert loaded is not None
    assert loaded.user_id.value == user.id.value

    loaded.revoke(_now())
    session_repo.update(loaded)
    db_session.commit()
    assert session_repo.get_by_id(created.id).revoked_at is not None

    session_repo.remove(created.id)
    db_session.commit()
    assert session_repo.get_by_id(created.id) is None


def test_sqlalchemy_refresh_token_repository_queries(db_session: Session) -> None:
    now = _now()
    clock = FixedClock(now)
    user_repo = SqlAlchemyUserRepository(db_session, clock)
    session_repo = SqlAlchemySessionRepository(db_session)
    refresh_repo = SqlAlchemyRefreshTokenRepository(db_session, clock)

    user = user_repo.add(
        User(
            id=UserId(uuid.uuid4()),
            email=Email.create("refresh-user@example.com"),
            password_hash=PasswordHash("hash"),
            status=UserStatus.ACTIVE,
            created_at=now,
            updated_at=now,
        )
    )
    db_session.flush()

    auth_session = session_repo.add(
        AuthSession(
            id=SessionId(uuid.uuid4()),
            user_id=user.id,
            created_at=now,
            updated_at=now,
        )
    )
    db_session.flush()

    active_token = RefreshToken(
        id=RefreshTokenId(uuid.uuid4()),
        session_id=auth_session.id,
        token_hash=TokenHash("active-hash"),
        family_id=FamilyId(uuid.uuid4()),
        expires_at=now + timedelta(days=1),
        created_at=now,
    )
    refresh_repo.add(active_token)
    db_session.commit()

    loaded = refresh_repo.get_by_token_hash(TokenHash("active-hash"))
    assert loaded is not None
    assert refresh_repo.get_active_by_session_id(auth_session.id) is not None

    loaded.revoke(now, RefreshTokenRevokeReason.LOGOUT)
    refresh_repo.update(loaded)
    db_session.commit()
    assert refresh_repo.get_active_by_session_id(auth_session.id) is None
