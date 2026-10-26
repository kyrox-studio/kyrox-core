import jwt
from fastapi import Depends, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.exceptions import AppException
from app.modules.identity.api.authentication.dependencies import (
    get_clock,
    get_session_repository,
    get_token_service,
)
from app.modules.identity.domain.authentication.ports.clock import Clock
from app.modules.identity.domain.authentication.ports.session_repository import SessionRepository
from app.modules.identity.domain.authentication.ports.token_service import TokenService
from app.modules.identity.domain.authentication.value_objects.security.access_token import (
    AccessToken,
    AccessTokenClaims,
)

_bearer_scheme = HTTPBearer(auto_error=False)


def resolve_access_token_claims(
    credentials: HTTPAuthorizationCredentials | None,
    token_service: TokenService,
    session_repository: SessionRepository,
    clock: Clock,
) -> AccessTokenClaims:
    """Shared access-token check: signature, lifetime cap and a live, unexpired session."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise AppException("Not authenticated", status_code=status.HTTP_401_UNAUTHORIZED)

    try:
        claims = token_service.decode_access_token(AccessToken.create(credentials.credentials))
    except (jwt.PyJWTError, ValueError) as exc:
        raise AppException("Invalid access token", status_code=status.HTTP_401_UNAUTHORIZED) from exc

    session = session_repository.get_by_id(claims.sid)
    if (
        session is None
        or not session.is_usable_at(clock.now())
        or session.user_id.value != claims.sub.value
    ):
        raise AppException("Invalid access token", status_code=status.HTTP_401_UNAUTHORIZED)

    return claims


def get_authenticated_access_token_claims(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    token_service: TokenService = Depends(get_token_service),
    session_repository: SessionRepository = Depends(get_session_repository),
    clock: Clock = Depends(get_clock),
) -> AccessTokenClaims:
    return resolve_access_token_claims(credentials, token_service, session_repository, clock)
