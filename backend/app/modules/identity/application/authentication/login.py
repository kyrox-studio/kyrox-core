from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from app.modules.identity.application.authentication.client_context import (
    ParsedClientContext,
    parse_client_context,
)
from app.modules.identity.application.authentication.commands import LoginCommand
from app.modules.identity.application.authentication.id_generator import IdGenerator
from app.modules.identity.application.authentication.organization_lifecycle import (
    organization_allows_authentication,
)
from app.modules.identity.application.authentication.results import AuthTokenPairResult
from app.modules.identity.application.authentication.revoke_all_user_sessions import (
    RevokeAllUserSessionsUseCase,
)
from app.modules.identity.application.authentication.token_pair_issuer import TokenPairIssuer
from app.modules.identity.domain.authentication.entities.session import Session
from app.modules.identity.domain.authentication.entities.user import User
from app.modules.identity.domain.authentication.exceptions import (
    AuthenticationError,
    InactiveUserError,
    InvalidCredentialsError,
    LockedUserError,
    LoginThrottledError,
)
from app.modules.identity.domain.authentication.ports.clock import Clock
from app.modules.identity.domain.authentication.ports.login_attempt_limiter import (
    LoginAttemptLimiter,
)
from app.modules.identity.domain.authentication.ports.password_hasher import PasswordHasher
from app.modules.identity.domain.authentication.ports.session_repository import SessionRepository
from app.modules.identity.domain.authentication.ports.user_repository import UserRepository
from app.modules.identity.domain.authentication.value_objects.identity.family_id import FamilyId
from app.modules.identity.domain.authentication.value_objects.identity.session_id import SessionId
from app.modules.identity.domain.authentication.value_objects.security.email import Email
from app.modules.identity.domain.organization.ports.organization_repository import OrganizationRepository


@dataclass(frozen=True, slots=True)
class LoginAuditEvent:
    """Sign-in outcome for the audit trail. Never carries the password."""

    outcome: str  # "success" | "failure"
    reason: str | None
    user_id: UUID | None
    organization_id: UUID | None
    session_id: UUID | None
    ip_address: str | None
    user_agent: str | None


class LoginAuditPort(Protocol):
    def record_login(self, event: LoginAuditEvent) -> None: ...


def _failure_reason(exc: AuthenticationError) -> str:
    if isinstance(exc, LoginThrottledError):
        return "throttled"
    if isinstance(exc, InactiveUserError):
        return "inactive_user"
    if isinstance(exc, LockedUserError):
        return "locked_user"
    if isinstance(exc, InvalidCredentialsError):
        return "invalid_credentials"
    return "rejected"


class LoginUseCase:
    def __init__(
        self,
        user_repository: UserRepository,
        session_repository: SessionRepository,
        password_hasher: PasswordHasher,
        token_pair_issuer: TokenPairIssuer,
        clock: Clock,
        id_generator: IdGenerator,
        revoke_all_user_sessions: RevokeAllUserSessionsUseCase,
        organization_repository: OrganizationRepository | None = None,
        attempt_limiter: LoginAttemptLimiter | None = None,
        audit_port: LoginAuditPort | None = None,
        persist_failure: Callable[[], None] | None = None,
    ) -> None:
        self._user_repository = user_repository
        self._session_repository = session_repository
        self._password_hasher = password_hasher
        self._token_pair_issuer = token_pair_issuer
        self._clock = clock
        self._id_generator = id_generator
        self._revoke_all_user_sessions = revoke_all_user_sessions
        self._organization_repository = organization_repository
        self._attempt_limiter = attempt_limiter
        self._audit_port = audit_port
        # A rejected login rolls back the request transaction; the failure
        # counter and audit row written before rejecting must be persisted.
        self._persist_failure = persist_failure

    def execute(self, command: LoginCommand) -> AuthTokenPairResult:
        client = parse_client_context(command.client)
        normalized_email = command.email.strip().lower()
        ip_address = client.ip_address.value if client.ip_address else None
        now = self._clock.now()
        holder: list[User] = []

        try:
            # F-004: the lock is checked before the account is looked up or the
            # password verified, so the answer never depends on account existence.
            if self._attempt_limiter is not None and self._attempt_limiter.locked_until(
                normalized_email, ip_address, now
            ) is not None:
                raise LoginThrottledError("Too many sign-in attempts")
            result, session = self._authenticate(command, client, holder)
        except AuthenticationError as exc:
            self._on_failure(exc, normalized_email, ip_address, client, holder, now)
            raise

        user = holder[0]
        if self._attempt_limiter is not None:
            self._attempt_limiter.reset(normalized_email, ip_address)
        self._record(LoginAuditEvent(
            outcome="success",
            reason=None,
            user_id=user.id.value,
            organization_id=user.organization_id,
            session_id=session.id.value,
            ip_address=ip_address,
            user_agent=client.user_agent.value if client.user_agent else None,
        ))
        return result

    def _on_failure(
        self,
        exc: AuthenticationError,
        normalized_email: str,
        ip_address: str | None,
        client: ParsedClientContext,
        holder: list[User],
        now,
    ) -> None:
        throttled = isinstance(exc, LoginThrottledError)
        if self._attempt_limiter is not None and not throttled:
            self._attempt_limiter.register_failure(normalized_email, ip_address, now)
        user = holder[0] if holder else None
        if user is None and throttled and self._audit_port is not None:
            user = self._lookup_user(normalized_email)
        self._record(LoginAuditEvent(
            outcome="failure",
            reason=_failure_reason(exc),
            user_id=user.id.value if user else None,
            organization_id=user.organization_id if user else None,
            session_id=None,
            ip_address=ip_address,
            user_agent=client.user_agent.value if client.user_agent else None,
        ))
        if self._persist_failure is not None and (
            self._attempt_limiter is not None or self._audit_port is not None
        ):
            self._persist_failure()

    def _lookup_user(self, normalized_email: str) -> User | None:
        try:
            return self._user_repository.get_by_email(Email.create(normalized_email))
        except ValueError:
            return None

    def _record(self, event: LoginAuditEvent) -> None:
        if self._audit_port is not None:
            self._audit_port.record_login(event)

    def _authenticate(
        self,
        command: LoginCommand,
        client: ParsedClientContext,
        holder: list[User],
    ) -> tuple[AuthTokenPairResult, Session]:
        try:
            email = Email.create(command.email)
        except ValueError as exc:
            raise InvalidCredentialsError("Invalid email or password") from exc

        user = self._user_repository.get_by_email(email)
        if user is None or user.password_hash is None:
            raise InvalidCredentialsError("Invalid email or password")
        holder.append(user)

        user.assert_can_authenticate()
        if self._organization_repository is not None and not organization_allows_authentication(
            user,
            self._organization_repository,
        ):
            raise InvalidCredentialsError("Invalid email or password")

        if not self._password_hasher.verify(command.password, user.password_hash):
            raise InvalidCredentialsError("Invalid email or password")

        if self._password_hasher.needs_rehash(user.password_hash):
            user.password_hash = self._password_hasher.hash(command.password)
            user.updated_at = self._clock.now()
            user = self._user_repository.update(user)
            holder[0] = user

        self._revoke_all_user_sessions.execute(user.id)

        now = self._clock.now()
        session = Session(
            id=SessionId(self._id_generator.generate_uuid()),
            user_id=user.id,
            created_at=now,
            updated_at=now,
            last_activity_at=now,
            expires_at=now + self._token_pair_issuer.session_lifetime,
            ip_address=client.ip_address,
            user_agent=client.user_agent,
            device_name=client.device_name,
            client_fingerprint=client.client_fingerprint,
        )
        session = self._session_repository.add(session)

        result = self._token_pair_issuer.issue(
            user=user,
            session=session,
            family_id=FamilyId(self._id_generator.generate_uuid()),
            client=client,
        )
        return result, session
