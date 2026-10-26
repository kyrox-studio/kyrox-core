from typing import Protocol
from uuid import UUID

from app.modules.identity.application.authentication.commands import LogoutCommand
from app.modules.identity.domain.authentication.enums.refresh_token_revoke_reason import (
    RefreshTokenRevokeReason,
)
from app.modules.identity.domain.authentication.ports.clock import Clock
from app.modules.identity.domain.authentication.ports.refresh_token_repository import (
    RefreshTokenRepository,
)
from app.modules.identity.domain.authentication.ports.refresh_token_service import RefreshTokenService
from app.modules.identity.domain.authentication.ports.session_repository import SessionRepository


class LogoutAuditPort(Protocol):
    def record_logout(self, *, user_id: UUID, session_id: UUID) -> None: ...


class LogoutUseCase:
    def __init__(
        self,
        session_repository: SessionRepository,
        refresh_token_repository: RefreshTokenRepository,
        refresh_token_service: RefreshTokenService,
        clock: Clock,
        audit_port: LogoutAuditPort | None = None,
    ) -> None:
        self._session_repository = session_repository
        self._refresh_token_repository = refresh_token_repository
        self._refresh_token_service = refresh_token_service
        self._clock = clock
        self._audit_port = audit_port

    def execute(self, command: LogoutCommand) -> None:
        token_hash = self._refresh_token_service.hash(command.refresh_token)
        stored_token = self._refresh_token_repository.get_by_token_hash(token_hash)
        if stored_token is None:
            return

        now = self._clock.now()
        if not stored_token.is_revoked():
            stored_token.revoke(now, RefreshTokenRevokeReason.LOGOUT)
            self._refresh_token_repository.update(stored_token)

        session = self._session_repository.get_by_id(stored_token.session_id)
        if session is not None and session.is_active:
            session.revoke(now)
            self._session_repository.update(session)
            # Only a logout that ended a live session is an audit event (F-C13).
            if self._audit_port is not None:
                self._audit_port.record_logout(
                    user_id=session.user_id.value,
                    session_id=session.id.value,
                )
