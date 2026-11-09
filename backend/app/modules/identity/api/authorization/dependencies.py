from fastapi import Depends
from sqlalchemy.orm import Session as DbSession

from app.db.session import get_db
from app.modules.identity.application.authorization import AuthorizationService
from app.modules.identity.domain.authorization.ports.permission_checker import PermissionChecker
from app.modules.identity.domain.authorization.ports.platform_user_reader import PlatformUserReader
from app.modules.identity.infrastructure.authorization.services import (
    SqlAlchemyPermissionChecker,
    SqlAlchemyPlatformUserReader,
)


def get_platform_user_reader(db: DbSession = Depends(get_db, scope="function")) -> PlatformUserReader:
    return SqlAlchemyPlatformUserReader(db)


def get_permission_checker(db: DbSession = Depends(get_db, scope="function")) -> PermissionChecker:
    return SqlAlchemyPermissionChecker(db)


def get_authorization_service(
    platform_user_reader: PlatformUserReader = Depends(get_platform_user_reader),
    permission_checker: PermissionChecker = Depends(get_permission_checker),
) -> AuthorizationService:
    return AuthorizationService(
        platform_user_reader=platform_user_reader,
        permission_checker=permission_checker,
    )
