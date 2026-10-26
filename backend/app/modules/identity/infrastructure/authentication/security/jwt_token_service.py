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


# Clock skew tolerated between ``iat``/``exp`` and the configured lifetime.
_LIFETIME_LEEWAY_SECONDS = 60


class JwtTokenService:
    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        max_lifetime_seconds: int | None = None,
    ) -> None:
        self._secret_key = secret_key
        self._algorithm = algorithm
        # F-C8: a validly signed token whose iat->exp window is longer than the
        # configured access lifetime (or issued in the future) is rejected.
        self._max_lifetime_seconds = max_lifetime_seconds

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
            claims = AccessTokenClaims(
                sub=UserId(UUID(payload["sub"])),
                email=Email(value=payload["email"]),
                sid=SessionId(UUID(payload["sid"])),
                exp=datetime.fromtimestamp(payload["exp"], tz=UTC),
                iat=datetime.fromtimestamp(payload["iat"], tz=UTC),
                jti=UUID(payload["jti"]),
            )
        except (KeyError, TypeError, AttributeError, OverflowError, OSError) as exc:
            raise jwt.InvalidTokenError("Malformed access token claims") from exc
        self._assert_lifetime(claims)
        return claims

    def _assert_lifetime(self, claims: AccessTokenClaims) -> None:
        if self._max_lifetime_seconds is None:
            return
        lifetime = (claims.exp - claims.iat).total_seconds()
        if lifetime > self._max_lifetime_seconds + _LIFETIME_LEEWAY_SECONDS:
            raise jwt.InvalidTokenError("Access token lifetime exceeds the server limit")
        if (claims.iat - datetime.now(tz=UTC)).total_seconds() > _LIFETIME_LEEWAY_SECONDS:
            raise jwt.ImmatureSignatureError("Access token issued in the future")
