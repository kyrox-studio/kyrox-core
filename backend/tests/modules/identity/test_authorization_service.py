import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db.base import Base
from app.modules.identity.application.authorization import CheckPermissionCommand
from app.modules.identity.domain.authorization.exceptions import PermissionDeniedError
from app.modules.identity.domain.authorization.value_objects.identity.organization_id import (
    OrganizationId,
)
from app.modules.identity.domain.authorization.value_objects.identity.user_id import UserId
from app.modules.identity.domain.entities import Organization, User
from app.modules.identity.domain.enums import UserStatus
from app.modules.identity.infrastructure.persistence import models as identity_models  # noqa: F401
from authorization_test_helpers import build_authorization_service, seed_user_role_with_permission


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


def _command(user: User, org: Organization, permission_code: str) -> CheckPermissionCommand:
    return CheckPermissionCommand(
        user_id=UserId(user.id),
        organization_id=OrganizationId(org.id),
        permission_code=permission_code,
    )


def test_authorization_service_has_permission(db_session: Session) -> None:
    seed = seed_user_role_with_permission(db_session)
    service = build_authorization_service(db_session)

    assert service.has_permission(_command(seed.user, seed.org, seed.permission_code)) is True
    assert service.has_permission(_command(seed.user, seed.org, "core.user.create")) is False


def test_authorization_service_require_permission(db_session: Session) -> None:
    seed = seed_user_role_with_permission(db_session)
    service = build_authorization_service(db_session)

    service.require_permission(_command(seed.user, seed.org, seed.permission_code))

    with pytest.raises(PermissionDeniedError):
        service.require_permission(_command(seed.user, seed.org, "core.user.create"))


def test_authorization_service_rejects_inactive_user(db_session: Session) -> None:
    seed = seed_user_role_with_permission(db_session)
    inactive_user = seed.user_repo.get_by_id(seed.user.id)
    assert inactive_user is not None
    inactive_user.status = UserStatus.SUSPENDED
    inactive_user.updated_at = seed.user.created_at
    seed.user_repo.update(inactive_user)
    db_session.commit()

    service = build_authorization_service(db_session)
    assert service.has_permission(_command(seed.user, seed.org, seed.permission_code)) is False
