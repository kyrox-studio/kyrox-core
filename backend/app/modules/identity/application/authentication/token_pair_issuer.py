from datetime import timedelta

from app.modules.identity.application.authentication.client_context import ParsedClientContext
from app.modules.identity.application.authentication.id_generator import IdGenerator
from app.modules.identity.application.authentication.policy import TokenPolicy
from app.modules.identity.application.authentication.results import AuthTokenPairResult
from app.modules.identity.domain.authentication.entities.refresh_token import RefreshToken
from app.modules.identity.domain.authentication.entities.session import Session
from app.modules.identity.domain.authentication.entities.user import User
from app.modules.identity.domain.authentication.ports.clock import Clock
from app.modules.identity.domain.authentication.ports.refresh_token_repository import (
    RefreshTokenRepository,
)
from app.modules.identity.domain.authentication.ports.refresh_token_service import RefreshTokenService
from app.modules.identity.domain.authentication.ports.token_service import TokenService
from app.modules.identity.domain.authentication.value_objects.identity.family_id import FamilyId
from app.modules.identity.domain.authentication.value_objects.identity.refresh_token_id import (
    RefreshTokenId,
)
from app.modules.identity.domain.authentication.value_objects.security.access_token import (
    AccessTokenClaims,
)


class TokenPairIssuer:
    def __init__(
        self,
        refresh_token_repository: RefreshTokenRepository,
        token_service: TokenService,
        refresh_token_service: RefreshTokenService,
        clock: Clock,
        token_policy: TokenPolicy,
        id_generator: IdGenerator,
    ) -> None:
        self._refresh_token_repository = refresh_token_repository
        self._token_service = token_service
        self._refresh_token_service = refresh_token_service
        self._clock = clock
        self._token_policy = token_policy
        self._id_generator = id_generator

    @property
    def session_lifetime(self) -> timedelta:
        """Absolute session lifetime: the refresh lifetime (ADR-0003, F-C8)."""
        return timedelta(days=self._token_policy.refresh_token_expire_days)

    def issue(
        self,
        user: User,
        session: Session,
        family_id: FamilyId,
        rotated_from: RefreshTokenId | None = None,
        client: ParsedClientContext | None = None,
    ) -> AuthTokenPairResult:
        now = self._clock.now()
        parsed_client = client or ParsedClientContext()
        refresh_expires_at = now + timedelta(days=self._token_policy.refresh_token_expire_days)
        # Rotation never outlives the session's absolute end (F-C8).
        if session.expires_at is not None and session.expires_at < refresh_expires_at:
            refresh_expires_at = session.expires_at
        access_expires_at = now + timedelta(seconds=self._token_policy.access_token_expire_seconds)

        refresh_token_value = self._refresh_token_service.create()
        token_hash = self._refresh_token_service.hash(refresh_token_value)

        refresh_token = RefreshToken(
            id=RefreshTokenId(self._id_generator.generate_uuid()),
            session_id=session.id,
            token_hash=token_hash,
            family_id=family_id,
            expires_at=refresh_expires_at,
            created_at=now,
            rotated_from=rotated_from,
            created_by_ip=parsed_client.ip_address,
            created_by_user_agent=parsed_client.user_agent,
        )
        self._refresh_token_repository.add(refresh_token)

        access_token = self._token_service.create_access_token(
            AccessTokenClaims(
                sub=user.id,
                email=user.email,
                sid=session.id,
                exp=access_expires_at,
                iat=now,
                jti=self._id_generator.generate_uuid(),
            )
        )

        return AuthTokenPairResult(
            access_token=access_token,
            refresh_token=refresh_token_value,
            token_type="bearer",
            expires_in=self._token_policy.access_token_expire_seconds,
        )
