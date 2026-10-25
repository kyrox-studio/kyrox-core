from datetime import UTC, datetime
from uuid import UUID

import jwt

from app.modules.identity.domain.authentication.ports.token_service import TokenService
from app.modules.identity.domain.authentication.value_objects.identity.session_id import SessionId
from app.modules.identity.domain.authentication.value_objects.identity.user_id import UserId
from app.modules.identity.domain.authentication.value_objects.security.access_token import (
    AccessToken,
    AccessTokenClaims,
)
from app.modules.identity.domain.authentication.value_objects.security.email import Email


class JwtTokenService:
    def __init__(self, secret_key: str, algorithm: str = "HS256") -> None:
        self._secret_key = secret_key
        self._algorithm = algorithm

    def create_access_token(self, claims: AccessTokenClaims) -> AccessToken:
        payload = {
            "sub": str(claims.sub.value),
            "email": claims.email.value,
            "sid": str(claims.sid.value),
            "exp": int(claims.exp.timestamp()),
            "iat": int(claims.iat.timestamp()),
            "jti": str(claims.jti),
        }
        encoded = jwt.encode(payload, self._secret_key, algorithm=self._algorithm)
        return AccessToken.create(encoded)

    def decode_access_token(self, token: AccessToken) -> AccessTokenClaims:
        payload = jwt.decode(
            token.value,
            self._secret_key,
            algorithms=[self._algorithm],
            options={"require": ["sub", "email", "sid", "exp", "iat", "jti"]},
        )
        try:
            return AccessTokenClaims(
                sub=UserId(UUID(payload["sub"])),
                email=Email(value=payload["email"]),
                sid=SessionId(UUID(payload["sid"])),
                exp=datetime.fromtimestamp(payload["exp"], tz=UTC),
                iat=datetime.fromtimestamp(payload["iat"], tz=UTC),
                jti=UUID(payload["jti"]),
            )
        except (KeyError, TypeError, AttributeError, OverflowError, OSError) as exc:
            raise jwt.InvalidTokenError("Malformed access token claims") from exc
