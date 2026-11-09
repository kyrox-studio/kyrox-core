from fastapi import Depends
from sqlalchemy.orm import Session as DbSession

from app.db.session import get_db
from app.modules.identity.api.authentication.dependencies import (
    get_clock,
    get_id_generator,
    get_refresh_token_repository,
    get_session_repository,
    get_user_repository,
)
from app.modules.identity.application.authentication.id_generator import IdGenerator
from app.modules.identity.application.authentication.revoke_organization_sessions import (
    RevokeOrganizationSessionsUseCase,
)
from app.modules.identity.application.organization.create_organization import CreateOrganizationUseCase
from app.modules.identity.application.organization.delete_organization import DeleteOrganizationUseCase
from app.modules.identity.application.organization.get_organization import GetOrganizationUseCase
from app.modules.identity.application.organization.list_organizations import ListOrganizationsUseCase
from app.modules.identity.application.organization.reactivate_organization import ReactivateOrganizationUseCase
from app.modules.identity.application.organization.suspend_organization import SuspendOrganizationUseCase
from app.modules.identity.application.organization.update_organization import UpdateOrganizationUseCase
from app.modules.identity.domain.authentication.ports.clock import Clock
from app.modules.identity.domain.authentication.ports.refresh_token_repository import (
    RefreshTokenRepository,
)
from app.modules.identity.domain.authentication.ports.session_repository import SessionRepository
from app.modules.identity.domain.authentication.ports.user_repository import UserRepository
from app.modules.identity.domain.authorization.ports.role_repository import RoleRepository
from app.modules.identity.domain.organization.ports.organization_repository import OrganizationRepository
from app.modules.identity.domain.organization.ports.user_organization_reader import UserOrganizationReader
from app.modules.identity.infrastructure.authorization.repositories.sqlalchemy_role_repository import (
    SqlAlchemyRoleRepository,
)
from app.modules.identity.infrastructure.organization.repositories.sqlalchemy_organization_repository import (
    SqlAlchemyOrganizationRepository,
)
from app.modules.identity.infrastructure.organization.repositories.sqlalchemy_user_organization_reader import (
    SqlAlchemyUserOrganizationReader,
)


def get_organization_repository(
    db: DbSession = Depends(get_db, scope="function"),
    clock: Clock = Depends(get_clock),
) -> OrganizationRepository:
    return SqlAlchemyOrganizationRepository(db, clock)


def get_role_repository(db: DbSession = Depends(get_db, scope="function")) -> RoleRepository:
    return SqlAlchemyRoleRepository(db)


def get_user_organization_reader(
    db: DbSession = Depends(get_db, scope="function"),
) -> UserOrganizationReader:
    return SqlAlchemyUserOrganizationReader(db)


def get_create_organization_use_case(
    organization_repository: OrganizationRepository = Depends(get_organization_repository),
    user_repository: UserRepository = Depends(get_user_repository),
    role_repository: RoleRepository = Depends(get_role_repository),
    clock: Clock = Depends(get_clock),
    id_generator: IdGenerator = Depends(get_id_generator),
) -> CreateOrganizationUseCase:
    return CreateOrganizationUseCase(
        organization_repository=organization_repository,
        user_repository=user_repository,
        role_repository=role_repository,
        clock=clock,
        id_generator=id_generator,
    )


def get_list_organizations_use_case(
    organization_repository: OrganizationRepository = Depends(get_organization_repository),
    user_organization_reader: UserOrganizationReader = Depends(get_user_organization_reader),
) -> ListOrganizationsUseCase:
    return ListOrganizationsUseCase(
        organization_repository=organization_repository,
        user_organization_reader=user_organization_reader,
    )


def get_get_organization_use_case(
    organization_repository: OrganizationRepository = Depends(get_organization_repository),
) -> GetOrganizationUseCase:
    return GetOrganizationUseCase(organization_repository=organization_repository)


def get_update_organization_use_case(
    organization_repository: OrganizationRepository = Depends(get_organization_repository),
    clock: Clock = Depends(get_clock),
) -> UpdateOrganizationUseCase:
    return UpdateOrganizationUseCase(
        organization_repository=organization_repository,
        clock=clock,
    )


def get_delete_organization_use_case(
    organization_repository: OrganizationRepository = Depends(get_organization_repository),
) -> DeleteOrganizationUseCase:
    return DeleteOrganizationUseCase(organization_repository=organization_repository)


def get_suspend_organization_use_case(
    organization_repository: OrganizationRepository = Depends(get_organization_repository),
    session_repository: SessionRepository = Depends(get_session_repository),
    refresh_token_repository: RefreshTokenRepository = Depends(get_refresh_token_repository),
    clock: Clock = Depends(get_clock),
) -> SuspendOrganizationUseCase:
    return SuspendOrganizationUseCase(
        organization_repository=organization_repository,
        revoke_organization_sessions=RevokeOrganizationSessionsUseCase(
            session_repository=session_repository,
            refresh_token_repository=refresh_token_repository,
            clock=clock,
        ),
        clock=clock,
    )


def get_reactivate_organization_use_case(
    organization_repository: OrganizationRepository = Depends(get_organization_repository),
    clock: Clock = Depends(get_clock),
) -> ReactivateOrganizationUseCase:
    return ReactivateOrganizationUseCase(
        organization_repository=organization_repository,
        clock=clock,
    )
