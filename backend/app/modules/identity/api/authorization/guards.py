from collections.abc import Callable
from typing import Annotated
from uuid import UUID

import jwt
from fastapi import Depends, Header, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.exceptions import AppException
from app.modules.identity.api.authentication.dependencies import (
    get_session_repository,
    get_token_service,
)
from app.modules.identity.api.authorization.context import (
    AuthenticatedOrganizationContext,
    AuthorizationContext,
)
from app.modules.identity.api.authorization.dependencies import (
    get_authorization_service,
    get_platform_user_reader,
)
from app.modules.identity.api.authorization.error_mapping import map_authorization_error
from app.modules.identity.application.authorization import AuthorizationService, CheckPermissionCommand
from app.modules.identity.domain.authentication.ports.session_repository import SessionRepository
from app.modules.identity.domain.authentication.ports.token_service import TokenService
from app.modules.identity.domain.authentication.value_objects.security.access_token import (
    AccessToken,
    AccessTokenClaims,
)
from app.modules.identity.domain.authorization.exceptions import PermissionDeniedError
from app.modules.identity.domain.authorization.ports.platform_user_reader import PlatformUserReader
from app.modules.identity.domain.authorization.value_objects.identity.organization_id import (
    OrganizationId,
)
from app.modules.identity.domain.authorization.value_objects.identity.user_id import UserId

_bearer_scheme = HTTPBearer(auto_error=False)


def get_access_token_claims(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    token_service: TokenService = Depends(get_token_service),
    session_repository: SessionRepository = Depends(get_session_repository),
) -> AccessTokenClaims:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise AppException("Not authenticated", status_code=status.HTTP_401_UNAUTHORIZED)

    try:
        claims = token_service.decode_access_token(AccessToken.create(credentials.credentials))
    except (jwt.PyJWTError, ValueError) as exc:
        raise AppException("Invalid access token", status_code=status.HTTP_401_UNAUTHORIZED) from exc

    session = session_repository.get_by_id(claims.sid)
    if (
        session is None
        or not session.is_active
        or session.user_id.value != claims.sub.value
    ):
        raise AppException("Invalid access token", status_code=status.HTTP_401_UNAUTHORIZED)

    return claims


def get_organization_id(
    x_organization_id: Annotated[UUID, Header(alias="X-Organization-Id")],
) -> UUID:
    return x_organization_id


def is_super_admin(user_id: UUID, platform_user_reader: PlatformUserReader) -> bool:
    """Platform god mode. The DB flag is independent from organization RBAC."""
    snapshot = platform_user_reader.get_snapshot(UserId(user_id))
    return bool(snapshot is not None and snapshot.is_super_admin)


def get_authorization_context(
    claims: AccessTokenClaims = Depends(get_access_token_claims),
    organization_id: UUID = Depends(get_organization_id),
    platform_user_reader: PlatformUserReader = Depends(get_platform_user_reader),
) -> AuthorizationContext:
    return AuthorizationContext(
        user_id=claims.sub.value,
        organization_id=organization_id,
        email=claims.email.value,
        is_super_admin=is_super_admin(claims.sub.value, platform_user_reader),
        session_id=claims.sid.value,
    )


def require_super_admin(
    claims: AccessTokenClaims = Depends(get_access_token_claims),
    platform_user_reader: PlatformUserReader = Depends(get_platform_user_reader),
) -> AccessTokenClaims:
    """Require only the DB-backed Super Admin flag; RBAC is never consulted."""
    if not is_super_admin(claims.sub.value, platform_user_reader):
        raise AppException("Super admin required", status_code=status.HTTP_403_FORBIDDEN)
    return claims


def _assert_organization_access(
    claims: AccessTokenClaims,
    organization_id: UUID,
    platform_user_reader: PlatformUserReader,
) -> bool:
    """Validate direct user -> organization ownership using the user read port."""
    snapshot = platform_user_reader.get_snapshot(UserId(claims.sub.value))
    if snapshot is not None and snapshot.is_super_admin:
        return True

    if (
        snapshot is None
        or not snapshot.can_be_authorized()
        or snapshot.organization_id != organization_id
    ):
        raise AppException("Forbidden", status_code=status.HTTP_403_FORBIDDEN)
    return False


def require_organization_access() -> Callable[..., AuthenticatedOrganizationContext]:
    def dependency(
        claims: AccessTokenClaims = Depends(get_access_token_claims),
        organization_id: UUID = Depends(get_organization_id),
        platform_user_reader: PlatformUserReader = Depends(get_platform_user_reader),
    ) -> AuthenticatedOrganizationContext:
        actor_is_super_admin = _assert_organization_access(
            claims,
            organization_id,
            platform_user_reader,
        )
        return AuthenticatedOrganizationContext(
            user_id=claims.sub.value,
            organization_id=organization_id,
            email=claims.email.value,
            session_id=claims.sid.value,
            is_super_admin=actor_is_super_admin,
        )

    return dependency


def require_permission(
    permission_code: str,
) -> Callable[..., AuthorizationContext]:
    def dependency(
        context: AuthenticatedOrganizationContext = Depends(require_organization_access()),
        authorization_service: AuthorizationService = Depends(get_authorization_service),
    ) -> AuthorizationContext:
        if context.is_super_admin:
            return AuthorizationContext(
                user_id=context.user_id,
                organization_id=context.organization_id,
                email=context.email,
                is_super_admin=True,
                session_id=context.session_id,
            )

        try:
            authorization_service.require_permission(
                CheckPermissionCommand(
                    user_id=UserId(context.user_id),
                    organization_id=OrganizationId(context.organization_id),
                    permission_code=permission_code,
                )
            )
        except PermissionDeniedError as exc:
            raise map_authorization_error(exc) from exc

        return AuthorizationContext(
            user_id=context.user_id,
            organization_id=context.organization_id,
            email=context.email,
            is_super_admin=False,
            session_id=context.session_id,
        )

    return dependency
