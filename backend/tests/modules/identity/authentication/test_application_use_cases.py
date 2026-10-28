import uuid
from datetime import UTC, datetime

import pytest

from app.modules.identity.application.authentication.client_context import parse_client_context
from app.modules.identity.application.authentication.commands import (
    ClientContextCommand,
    LoginCommand,
    LogoutCommand,
    RefreshSessionCommand,
)
from app.modules.identity.application.authentication.login import LoginUseCase
from app.modules.identity.application.authentication.logout import LogoutUseCase
from app.modules.identity.application.authentication.policy import TokenPolicy
from app.modules.identity.application.authentication.refresh_session import RefreshSessionUseCase
from app.modules.identity.application.authentication.revoke_all_user_sessions import (
    RevokeAllUserSessionsUseCase,
)
from app.modules.identity.application.authentication.token_pair_issuer import TokenPairIssuer
from app.modules.identity.domain.authentication.entities.refresh_token import RefreshToken
from app.modules.identity.domain.authentication.entities.session import Session
from app.modules.identity.domain.authentication.entities.user import User
from app.modules.identity.domain.authentication.enums.refresh_token_revoke_reason import (
    RefreshTokenRevokeReason,
)
from app.modules.identity.domain.authentication.enums.user_status import UserStatus
from app.modules.identity.domain.authentication.exceptions import (
    InactiveUserError,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
    RevokedRefreshTokenError,
)
from app.modules.identity.domain.authentication.ports.clock import Clock
from app.modules.identity.domain.authentication.value_objects.identity.refresh_token_id import (
    RefreshTokenId,
)
from app.modules.identity.domain.authentication.value_objects.identity.session_id import SessionId
from app.modules.identity.domain.authentication.value_objects.identity.user_id import UserId
from app.modules.identity.domain.authentication.value_objects.security.access_token import (
    AccessToken,
    AccessTokenClaims,
)
from app.modules.identity.domain.authentication.value_objects.security.email import Email
from app.modules.identity.domain.authentication.value_objects.security.password_hash import (
    PasswordHash,
)
from app.modules.identity.domain.authentication.value_objects.security.refresh_token import (
    RefreshToken as RefreshTokenValue,
)
from app.modules.identity.domain.authentication.value_objects.security.token_hash import TokenHash


class FixedClock:
    def __init__(self, now: datetime) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now


class SequenceIdGenerator:
    def __init__(self, values: list[uuid.UUID]) -> None:
        self._values = values
        self._index = 0

    def generate_uuid(self) -> uuid.UUID:
        value = self._values[self._index % len(self._values)]
        self._index += 1
        return value


class FakePasswordHasher:
    def hash(self, password: str) -> PasswordHash:
        return PasswordHash(f"hash:{password}")

    def verify(self, password: str, password_hash: PasswordHash) -> bool:
        return password_hash.value == f"hash:{password}"

    def needs_rehash(self, password_hash: PasswordHash) -> bool:
        return False


class FakeTokenService:
    def create_access_token(self, claims: AccessTokenClaims) -> AccessToken:
        return AccessToken.create(f"access:{claims.jti}")

    def decode_access_token(self, token: AccessToken) -> AccessTokenClaims:
        raise NotImplementedError


class FakeRefreshTokenService:
    def __init__(self) -> None:
        self._counter = 0

    def create(self) -> RefreshTokenValue:
        self._counter += 1
        return RefreshTokenValue.create(f"refresh-{self._counter}")

    def hash(self, token: RefreshTokenValue) -> TokenHash:
        return TokenHash(f"hash:{token.value}")

    def verify(self, token: RefreshTokenValue, token_hash: TokenHash) -> bool:
        return token_hash.value == f"hash:{token.value}"


class InMemoryUserRepository:
    def __init__(self, users: list[User] | None = None) -> None:
        self._users = {user.email.value: user for user in users or []}

    def add(self, user: User) -> User:
        self._users[user.email.value] = user
        return user

    def update(self, user: User) -> User:
        self._users[user.email.value] = user
        return user

    def remove(self, user_id: UserId) -> None:
        self._users = {
            email: user for email, user in self._users.items() if user.id.value != user_id.value
        }

    def get_by_id(self, user_id: UserId) -> User | None:
        for user in self._users.values():
            if user.id.value == user_id.value:
                return user
        return None

    def get_by_email(self, email: Email) -> User | None:
        return self._users.get(email.value)


class InMemorySessionRepository:
    def __init__(self) -> None:
        self._sessions: dict[uuid.UUID, Session] = {}

    def add(self, session: Session) -> Session:
        self._sessions[session.id.value] = session
        return session

    def update(self, session: Session) -> Session:
        self._sessions[session.id.value] = session
        return session

    def remove(self, session_id: SessionId) -> None:
        self._sessions.pop(session_id.value, None)

    def get_by_id(self, session_id: SessionId) -> Session | None:
        return self._sessions.get(session_id.value)

    def get_active_by_user_id(self, user_id: UserId) -> list[Session]:
        return [
            session
            for session in self._sessions.values()
            if session.user_id.value == user_id.value and session.is_active
        ]


class InMemoryRefreshTokenRepository:
    def __init__(
        self,
        *,
        session_repository: InMemorySessionRepository,
        clock: Clock,
    ) -> None:
        self._session_repository = session_repository
        self._clock = clock
        self._tokens_by_hash: dict[str, RefreshToken] = {}
        self._tokens_by_id: dict[uuid.UUID, RefreshToken] = {}

    def add(self, refresh_token: RefreshToken) -> RefreshToken:
        self._tokens_by_hash[refresh_token.token_hash.value] = refresh_token
        self._tokens_by_id[refresh_token.id.value] = refresh_token
        return refresh_token

    def update(self, refresh_token: RefreshToken) -> RefreshToken:
        self._tokens_by_hash[refresh_token.token_hash.value] = refresh_token
        self._tokens_by_id[refresh_token.id.value] = refresh_token
        return refresh_token

    def remove(self, refresh_token_id: RefreshTokenId) -> None:
        token = self._tokens_by_id.pop(refresh_token_id.value, None)
        if token is not None:
            self._tokens_by_hash.pop(token.token_hash.value, None)

    def get_by_id(self, refresh_token_id: RefreshTokenId) -> RefreshToken | None:
        return self._tokens_by_id.get(refresh_token_id.value)

    def get_by_token_hash(self, token_hash: TokenHash) -> RefreshToken | None:
        return self._tokens_by_hash.get(token_hash.value)

    def get_active_by_session_id(self, session_id: SessionId) -> RefreshToken | None:
        for token in self._tokens_by_id.values():
            if token.session_id.value == session_id.value and token.is_usable(datetime.now(tz=UTC)):
                return token
        return None

    def get_active_by_user_id(self, user_id: UserId) -> list[RefreshToken]:
        now = self._clock.now()
        active: list[RefreshToken] = []
        for token in self._tokens_by_id.values():
            session = self._session_repository.get_by_id(token.session_id)
            if (
                session is not None
                and session.user_id.value == user_id.value
                and token.is_usable(now)
            ):
                active.append(token)
        return active


def _build_user(status: UserStatus = UserStatus.ACTIVE) -> User:
    now = datetime(2026, 7, 1, tzinfo=UTC)
    return User(
        id=UserId(uuid.UUID("00000000-0000-0000-0000-000000000001")),
        email=Email.create("user@example.com"),
        password_hash=PasswordHash("hash:secret"),
        status=status,
        created_at=now,
        updated_at=now,
    )


def _build_use_cases(
    *,
    users: list[User] | None = None,
    now: datetime | None = None,
    id_values: list[uuid.UUID] | None = None,
) -> tuple[LoginUseCase, RefreshSessionUseCase, LogoutUseCase, InMemoryRefreshTokenRepository, FakeRefreshTokenService]:
    fixed_now = now or datetime(2026, 7, 1, 12, 0, tzinfo=UTC)
    clock = FixedClock(fixed_now)
    ids = id_values or [
        uuid.UUID("10000000-0000-0000-0000-000000000010"),
        uuid.UUID("20000000-0000-0000-0000-000000000020"),
        uuid.UUID("30000000-0000-0000-0000-000000000030"),
        uuid.UUID("40000000-0000-0000-0000-000000000040"),
        uuid.UUID("50000000-0000-0000-0000-000000000050"),
    ]
    id_generator = SequenceIdGenerator(ids)
    user_repository = InMemoryUserRepository(users or [_build_user()])
    session_repository = InMemorySessionRepository()
    refresh_token_repository = InMemoryRefreshTokenRepository(
        session_repository=session_repository,
        clock=clock,
    )
    refresh_token_service = FakeRefreshTokenService()
    token_policy = TokenPolicy(access_token_expire_seconds=900, refresh_token_expire_days=30)
    token_pair_issuer = TokenPairIssuer(
        refresh_token_repository=refresh_token_repository,
        token_service=FakeTokenService(),
        refresh_token_service=refresh_token_service,
        clock=clock,
        token_policy=token_policy,
        id_generator=id_generator,
    )
    login_use_case = LoginUseCase(
        user_repository=user_repository,
        session_repository=session_repository,
        password_hasher=FakePasswordHasher(),
        token_pair_issuer=token_pair_issuer,
        clock=clock,
        id_generator=id_generator,
        revoke_all_user_sessions=RevokeAllUserSessionsUseCase(
            session_repository=session_repository,
            refresh_token_repository=refresh_token_repository,
            clock=clock,
        ),
    )
    refresh_use_case = RefreshSessionUseCase(
        user_repository=user_repository,
        session_repository=session_repository,
        refresh_token_repository=refresh_token_repository,
        refresh_token_service=refresh_token_service,
        token_pair_issuer=token_pair_issuer,
        clock=clock,
    )
    logout_use_case = LogoutUseCase(
        session_repository=session_repository,
        refresh_token_repository=refresh_token_repository,
        refresh_token_service=refresh_token_service,
        clock=clock,
    )
    return login_use_case, refresh_use_case, logout_use_case, refresh_token_repository, refresh_token_service


def test_login_success_returns_token_pair() -> None:
    login_use_case, _, _, _, _ = _build_use_cases()
    result = login_use_case.execute(LoginCommand(email="user@example.com", password="secret"))

    assert result.token_type == "bearer"
    assert result.expires_in == 900
    assert result.access_token.value.startswith("access:")
    assert result.refresh_token.value == "refresh-1"


def test_login_rejects_invalid_password() -> None:
    login_use_case, _, _, _, _ = _build_use_cases()

    with pytest.raises(InvalidCredentialsError):
        login_use_case.execute(LoginCommand(email="user@example.com", password="wrong"))


def test_successful_login_revokes_previous_user_sessions() -> None:
    login_use_case, refresh_use_case, _, refresh_token_repository, _ = _build_use_cases(
        id_values=[uuid.uuid4() for _ in range(16)],
    )
    first = login_use_case.execute(LoginCommand(email="user@example.com", password="secret"))
    second = login_use_case.execute(LoginCommand(email="user@example.com", password="secret"))

    stored_first = refresh_token_repository.get_by_token_hash(
        TokenHash(f"hash:{first.refresh_token.value}")
    )
    stored_second = refresh_token_repository.get_by_token_hash(
        TokenHash(f"hash:{second.refresh_token.value}")
    )
    assert stored_first is not None
    assert stored_first.is_revoked() is True
    assert stored_first.revoked_reason is RefreshTokenRevokeReason.SESSION_REVOKED
    assert stored_second is not None
    assert stored_second.is_usable(datetime(2026, 7, 1, 12, 0, tzinfo=UTC)) is True
    assert second.refresh_token.value != first.refresh_token.value

    with pytest.raises(RevokedRefreshTokenError):
        refresh_use_case.execute(RefreshSessionCommand(refresh_token=first.refresh_token))

    rotated = refresh_use_case.execute(RefreshSessionCommand(refresh_token=second.refresh_token))
    assert rotated.refresh_token.value != second.refresh_token.value


def test_failed_login_does_not_revoke_existing_session() -> None:
    login_use_case, refresh_use_case, _, refresh_token_repository, _ = _build_use_cases()
    first = login_use_case.execute(LoginCommand(email="user@example.com", password="secret"))

    with pytest.raises(InvalidCredentialsError):
        login_use_case.execute(LoginCommand(email="user@example.com", password="wrong"))

    stored = refresh_token_repository.get_by_token_hash(
        TokenHash(f"hash:{first.refresh_token.value}")
    )
    assert stored is not None
    assert stored.is_revoked() is False

    rotated = refresh_use_case.execute(RefreshSessionCommand(refresh_token=first.refresh_token))
    assert rotated.refresh_token.value != first.refresh_token.value


def test_login_rejects_inactive_user() -> None:
    inactive_user = _build_user(status=UserStatus.INACTIVE)
    login_use_case, _, _, _, _ = _build_use_cases(users=[inactive_user])

    with pytest.raises(InactiveUserError):
        login_use_case.execute(LoginCommand(email="user@example.com", password="secret"))


def test_login_does_not_fail_on_invalid_client_context() -> None:
    login_use_case, _, _, _, _ = _build_use_cases()
    result = login_use_case.execute(
        LoginCommand(
            email="user@example.com",
            password="secret",
            client=ClientContextCommand(ip_address="x" * 46),
        )
    )

    assert result.refresh_token.value == "refresh-1"


def test_parse_client_context_skips_invalid_fields() -> None:
    parsed = parse_client_context(ClientContextCommand(user_agent="   "))

    assert parsed.user_agent is None


def test_refresh_success_rotates_token() -> None:
    login_use_case, refresh_use_case, _, refresh_token_repository, _ = _build_use_cases()
    login_result = login_use_case.execute(LoginCommand(email="user@example.com", password="secret"))

    refresh_result = refresh_use_case.execute(
        RefreshSessionCommand(refresh_token=login_result.refresh_token)
    )

    assert refresh_result.refresh_token.value == "refresh-2"
    stored_old = refresh_token_repository.get_by_token_hash(
        TokenHash(f"hash:{login_result.refresh_token.value}")
    )
    assert stored_old is not None
    assert stored_old.is_used() is True
    assert stored_old.revoked_reason is RefreshTokenRevokeReason.ROTATED


def test_refresh_rejects_invalid_token() -> None:
    _, refresh_use_case, _, _, _ = _build_use_cases()

    with pytest.raises(InvalidRefreshTokenError):
        refresh_use_case.execute(
            RefreshSessionCommand(refresh_token=RefreshTokenValue.create("missing-token"))
        )


def test_refresh_detects_reuse_of_rotated_token() -> None:
    login_use_case, refresh_use_case, _, _, _ = _build_use_cases()
    login_result = login_use_case.execute(LoginCommand(email="user@example.com", password="secret"))
    refresh_use_case.execute(RefreshSessionCommand(refresh_token=login_result.refresh_token))

    with pytest.raises(RevokedRefreshTokenError):
        refresh_use_case.execute(RefreshSessionCommand(refresh_token=login_result.refresh_token))


def test_logout_revokes_session_and_token() -> None:
    login_use_case, _, logout_use_case, refresh_token_repository, _ = _build_use_cases()
    login_result = login_use_case.execute(LoginCommand(email="user@example.com", password="secret"))

    logout_use_case.execute(LogoutCommand(refresh_token=login_result.refresh_token))

    stored = refresh_token_repository.get_by_token_hash(
        TokenHash(f"hash:{login_result.refresh_token.value}")
    )
    assert stored is not None
    assert stored.is_revoked() is True
    assert stored.revoked_reason is RefreshTokenRevokeReason.LOGOUT


def test_logout_is_idempotent_for_unknown_token() -> None:
    _, _, logout_use_case, _, _ = _build_use_cases()

    logout_use_case.execute(LogoutCommand(refresh_token=RefreshTokenValue.create("unknown")))
