from fastapi import Depends
from sqlalchemy.orm import Session as DbSession

from app.db.session import get_db
from app.modules.identity.api.authentication.dependencies import (
    build_login_attempt_limiter,
    build_login_audit_port,
    get_clock,
    get_id_generator,
    get_password_hasher,
    get_refresh_token_repository,
    get_refresh_token_service,
    get_session_repository,
    get_token_pair_issuer,
    get_user_repository,
)
from app.modules.identity.application.authentication.id_generator import IdGenerator
from app.modules.identity.application.authentication.login import LoginUseCase
from app.modules.identity.application.authentication.refresh_session import RefreshSessionUseCase
from app.modules.identity.application.authentication.revoke_all_user_sessions import (
    RevokeAllUserSessionsUseCase,
)
from app.modules.identity.application.authentication.token_pair_issuer import TokenPairIssuer
from app.modules.identity.domain.authentication.ports.clock import Clock
from app.modules.identity.domain.authentication.ports.password_hasher import PasswordHasher
from app.modules.identity.domain.authentication.ports.refresh_token_repository import (
    RefreshTokenRepository,
)
from app.modules.identity.domain.authentication.ports.refresh_token_service import RefreshTokenService
from app.modules.identity.domain.authentication.ports.session_repository import SessionRepository
from app.modules.identity.domain.authentication.ports.user_repository import UserRepository
from app.modules.identity.infrastructure.organization.repositories.sqlalchemy_organization_repository import (
    SqlAlchemyOrganizationRepository,
)


def get_lifecycle_aware_login_use_case(
    db: DbSession = Depends(get_db),
    user_repository: UserRepository = Depends(get_user_repository),
    session_repository: SessionRepository = Depends(get_session_repository),
    refresh_token_repository: RefreshTokenRepository = Depends(get_refresh_token_repository),
    password_hasher: PasswordHasher = Depends(get_password_hasher),
    token_pair_issuer: TokenPairIssuer = Depends(get_token_pair_issuer),
    clock: Clock = Depends(get_clock),
    id_generator: IdGenerator = Depends(get_id_generator),
) -> LoginUseCase:
    return LoginUseCase(
        user_repository=user_repository,
        session_repository=session_repository,
        password_hasher=password_hasher,
        token_pair_issuer=token_pair_issuer,
        clock=clock,
        id_generator=id_generator,
        revoke_all_user_sessions=RevokeAllUserSessionsUseCase(
            session_repository=session_repository,
            refresh_token_repository=refresh_token_repository,
            clock=clock,
        ),
        organization_repository=SqlAlchemyOrganizationRepository(db, clock),
        attempt_limiter=build_login_attempt_limiter(db),
        audit_port=build_login_audit_port(db),
        persist_failure=db.commit,
    )


def get_lifecycle_aware_refresh_session_use_case(
    db: DbSession = Depends(get_db),
    user_repository: UserRepository = Depends(get_user_repository),
    session_repository: SessionRepository = Depends(get_session_repository),
    refresh_token_repository: RefreshTokenRepository = Depends(get_refresh_token_repository),
    refresh_token_service: RefreshTokenService = Depends(get_refresh_token_service),
    token_pair_issuer: TokenPairIssuer = Depends(get_token_pair_issuer),
    clock: Clock = Depends(get_clock),
) -> RefreshSessionUseCase:
    return RefreshSessionUseCase(
        user_repository=user_repository,
        session_repository=session_repository,
        refresh_token_repository=refresh_token_repository,
        refresh_token_service=refresh_token_service,
        token_pair_issuer=token_pair_issuer,
        clock=clock,
        organization_repository=SqlAlchemyOrganizationRepository(db, clock),
        persist_revocation=db.commit,
    )
