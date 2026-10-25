from collections.abc import Callable
from datetime import datetime

from app.modules.identity.application.authentication.client_context import parse_client_context
from app.modules.identity.application.authentication.commands import RefreshSessionCommand
from app.modules.identity.application.authentication.organization_lifecycle import (
    organization_allows_authentication,
)
from app.modules.identity.application.authentication.results import AuthTokenPairResult
from app.modules.identity.application.authentication.token_pair_issuer import TokenPairIssuer
from app.modules.identity.domain.authentication.enums.refresh_token_revoke_reason import (
    RefreshTokenRevokeReason,
)
from app.modules.identity.domain.authentication.exceptions import (
    AuthenticationError,
    InvalidRefreshTokenError,
    RevokedRefreshTokenError,
)
from app.modules.identity.domain.authentication.ports.clock import Clock
from app.modules.identity.domain.authentication.ports.refresh_token_repository import (
    RefreshTokenRepository,
)
from app.modules.identity.domain.authentication.ports.refresh_token_service import RefreshTokenService
from app.modules.identity.domain.authentication.ports.session_repository import SessionRepository
from app.modules.identity.domain.authentication.ports.user_repository import UserRepository
from app.modules.identity.domain.authentication.value_objects.identity.session_id import SessionId
from app.modules.identity.domain.organization.ports.organization_repository import OrganizationRepository


class RefreshSessionUseCase:
    def __init__(
        self,
        user_repository: UserRepository,
        session_repository: SessionRepository,
        refresh_token_repository: RefreshTokenRepository,
        refresh_token_service: RefreshTokenService,
        token_pair_issuer: TokenPairIssuer,
        clock: Clock,
        organization_repository: OrganizationRepository | None = None,
        persist_revocation: Callable[[], None] | None = None,
    ) -> None:
        self._user_repository = user_repository
        self._session_repository = session_repository
        self._refresh_token_repository = refresh_token_repository
        self._refresh_token_service = refresh_token_service
        self._token_pair_issuer = token_pair_issuer
        self._clock = clock
        self._organization_repository = organization_repository
        # Rejected requests roll back the request transaction; revocations made
        # before rejecting must be persisted explicitly to take effect.
        self._persist_revocation = persist_revocation

    def execute(self, command: RefreshSessionCommand) -> AuthTokenPairResult:
        token_hash = self._refresh_token_service.hash(command.refresh_token)
        stored_token = self._refresh_token_repository.get_by_token_hash(token_hash)
        if stored_token is None:
            raise InvalidRefreshTokenError("Invalid refresh token")

        if not self._refresh_token_service.verify(command.refresh_token, stored_token.token_hash):
            raise InvalidRefreshTokenError("Invalid refresh token")

        now = self._clock.now()

        if stored_token.is_used() or stored_token.is_revoked():
            if stored_token.reuse_detected_at is None:
                stored_token.mark_reuse_detected(now)
            self._refresh_token_repository.update(stored_token)
            self._revoke_session_if_active(stored_token.session_id, now)
            self._persist_revocation_before_rejecting()
            raise RevokedRefreshTokenError("Refresh token reuse detected")

        stored_token.assert_usable(now)

        session = self._session_repository.get_by_id(stored_token.session_id)
        if session is None:
            raise InvalidRefreshTokenError("Invalid refresh token")

        try:
            session.assert_active()
        except AuthenticationError as exc:
            raise InvalidRefreshTokenError(str(exc)) from exc

        user = self._user_repository.get_by_id(session.user_id)
        if user is None:
            raise InvalidRefreshTokenError("Invalid refresh token")

        user.assert_can_authenticate()
        if self._organization_repository is not None and not organization_allows_authentication(
            user,
            self._organization_repository,
        ):
            stored_token.revoke(now, RefreshTokenRevokeReason.ORGANIZATION_SUSPENDED)
            self._refresh_token_repository.update(stored_token)
            self._revoke_session_if_active(stored_token.session_id, now)
            self._persist_revocation_before_rejecting()
            raise InvalidRefreshTokenError("Invalid refresh token")

        stored_token.mark_used(now)
        stored_token.revoke(now, RefreshTokenRevokeReason.ROTATED)
        self._refresh_token_repository.update(stored_token)

        session.record_activity(now)
        self._session_repository.update(session)

        client = parse_client_context(command.client)
        return self._token_pair_issuer.issue(
            user=user,
            session=session,
            family_id=stored_token.family_id,
            rotated_from=stored_token.id,
            client=client,
        )

    def _persist_revocation_before_rejecting(self) -> None:
        if self._persist_revocation is not None:
            self._persist_revocation()

    def _revoke_session_if_active(self, session_id: SessionId, now: datetime) -> None:
        session = self._session_repository.get_by_id(session_id)
        if session is None or not session.is_active:
            return
        session.revoke(now)
        self._session_repository.update(session)
