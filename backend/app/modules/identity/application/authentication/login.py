from app.modules.identity.application.authentication.client_context import parse_client_context
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
from app.modules.identity.domain.authentication.exceptions import InvalidCredentialsError
from app.modules.identity.domain.authentication.ports.clock import Clock
from app.modules.identity.domain.authentication.ports.password_hasher import PasswordHasher
from app.modules.identity.domain.authentication.ports.session_repository import SessionRepository
from app.modules.identity.domain.authentication.ports.user_repository import UserRepository
from app.modules.identity.domain.authentication.value_objects.identity.family_id import FamilyId
from app.modules.identity.domain.authentication.value_objects.identity.session_id import SessionId
from app.modules.identity.domain.authentication.value_objects.security.email import Email
from app.modules.identity.domain.organization.ports.organization_repository import OrganizationRepository


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
    ) -> None:
        self._user_repository = user_repository
        self._session_repository = session_repository
        self._password_hasher = password_hasher
        self._token_pair_issuer = token_pair_issuer
        self._clock = clock
        self._id_generator = id_generator
        self._revoke_all_user_sessions = revoke_all_user_sessions
        self._organization_repository = organization_repository

    def execute(self, command: LoginCommand) -> AuthTokenPairResult:
        try:
            email = Email.create(command.email)
        except ValueError as exc:
            raise InvalidCredentialsError("Invalid email or password") from exc

        user = self._user_repository.get_by_email(email)
        if user is None or user.password_hash is None:
            raise InvalidCredentialsError("Invalid email or password")

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

        self._revoke_all_user_sessions.execute(user.id)

        now = self._clock.now()
        client = parse_client_context(command.client)
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

        return self._token_pair_issuer.issue(
            user=user,
            session=session,
            family_id=FamilyId(self._id_generator.generate_uuid()),
            client=client,
        )
