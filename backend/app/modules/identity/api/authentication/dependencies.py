from datetime import timedelta
from functools import lru_cache
from uuid import UUID

from fastapi import Depends
from sqlalchemy.orm import Session as DbSession

from app.core.config import settings
from app.db.session import get_db
from app.modules.audit.application.dto import RecordAuditEventCommand
from app.modules.audit.application.record_organization_audit_event import (
    RecordOrganizationAuditEventCommand,
    RecordOrganizationAuditEventUseCase,
)
from app.modules.audit.application.service import AuditService
from app.modules.audit.infrastructure.repositories import SqlAlchemyAuditLogRepository
from app.modules.identity.application.authentication.activation import (
    ActivationAuditPort,
    CompleteActivationUseCase,
)
from app.modules.identity.application.authentication.id_generator import (
    IdGenerator,
    Uuid4IdGenerator,
)
from app.modules.identity.application.authentication.identity_action_tokens import (
    ConsumeIdentityActionToken,
    IssueIdentityActionToken,
)
from app.modules.identity.application.authentication.login import (
    LoginAuditEvent,
    LoginAuditPort,
    LoginUseCase,
)
from app.modules.identity.application.authentication.logout import LogoutAuditPort, LogoutUseCase
from app.modules.identity.application.authentication.password_change import (
    ChangePasswordUseCase,
    PasswordChangeAuditPort,
)
from app.modules.identity.application.authentication.password_recovery import (
    ForgotPasswordUseCase,
    PasswordResetAuditPort,
    PasswordResetNotificationPort,
    ResetPasswordUseCase,
)
from app.modules.identity.application.authentication.policy import TokenPolicy
from app.modules.identity.application.authentication.public_signup import (
    ActivationNotificationPort,
    PublicSignupUseCase,
)
from app.modules.identity.application.authentication.refresh_session import RefreshSessionUseCase
from app.modules.identity.application.authentication.revoke_all_user_sessions import (
    RevokeAllUserSessionsUseCase,
)
from app.modules.identity.application.authentication.token_pair_issuer import TokenPairIssuer
from app.modules.identity.domain.authentication.exceptions.authentication import (
    PublicSignupProvisioningError,
)
from app.modules.identity.domain.authentication.ports.clock import Clock
from app.modules.identity.domain.authentication.ports.identity_action_token_repository import (
    IdentityActionTokenRepository,
)
from app.modules.identity.domain.authentication.ports.identity_action_token_service import (
    IdentityActionTokenService,
)
from app.modules.identity.domain.authentication.ports.password_hasher import PasswordHasher
from app.modules.identity.domain.authentication.ports.refresh_token_repository import (
    RefreshTokenRepository,
)
from app.modules.identity.domain.authentication.ports.refresh_token_service import RefreshTokenService
from app.modules.identity.domain.authentication.ports.session_repository import SessionRepository
from app.modules.identity.domain.authentication.ports.token_service import TokenService
from app.modules.identity.domain.authentication.ports.user_repository import UserRepository
from app.modules.identity.domain.authentication.value_objects.identity.identity_action_token_id import (
    IdentityActionTokenId,
)
from app.modules.identity.domain.authentication.value_objects.identity.user_id import UserId
from app.modules.identity.infrastructure.authentication.clock import UtcClock
from app.modules.identity.infrastructure.authentication.repositories import (
    SqlAlchemyIdentityActionTokenRepository,
    SqlAlchemyRefreshTokenRepository,
    SqlAlchemySessionRepository,
    SqlAlchemyUserRepository,
)
from app.modules.identity.infrastructure.authentication.repositories.sqlalchemy_login_attempt_limiter import (
    LoginThrottlePolicy,
    SqlAlchemyLoginAttemptLimiter,
)
from app.modules.identity.infrastructure.authentication.security import (
    Argon2idPasswordHasher,
    JwtTokenService,
    RefreshTokenService as RefreshTokenServiceImpl,
)
from app.modules.identity.infrastructure.authentication.security.identity_action_token_service import (
    IdentityActionTokenService as IdentityActionTokenServiceImpl,
)
from app.modules.identity.infrastructure.authorization.repositories.sqlalchemy_role_repository import (
    SqlAlchemyRoleRepository,
)
from app.modules.identity.infrastructure.authorization.repositories.sqlalchemy_user_role_repository import (
    SqlAlchemyUserRoleRepository,
)
from app.modules.identity.infrastructure.organization.repositories.sqlalchemy_organization_repository import (
    SqlAlchemyOrganizationRepository,
)
from app.modules.identity.infrastructure.persistence.models import UserModel
from app.modules.notifications.api.dependencies import get_send_notification_use_case
from app.modules.notifications.application.commands import SendNotificationCommand
from app.modules.notifications.application.identity_templates import (
    IDENTITY_ACTIVATION_TEMPLATE_KEY,
    IDENTITY_PASSWORD_RESET_TEMPLATE_KEY,
)
from app.modules.notifications.application.send_notification import SendNotificationUseCase
from app.modules.notifications.domain.value_objects.notification_status import NotificationStatus


class _CoreActivationNotificationAdapter(ActivationNotificationPort):
    def __init__(self, send_notification_use_case: SendNotificationUseCase) -> None:
        self._send_notification_use_case = send_notification_use_case

    def enqueue_activation(
        self,
        *,
        recipient: str,
        user_id: UserId,
        token_id: IdentityActionTokenId,
    ) -> UUID:
        result = self._send_notification_use_case.execute(
            SendNotificationCommand(
                organization_id=None,
                channel="email",
                recipient=recipient,
                subject="Activate your KYROX account",
                body=(
                    "Your KYROX account is awaiting activation. "
                    "The secure activation link is generated only at delivery time."
                ),
                template_key=IDENTITY_ACTIVATION_TEMPLATE_KEY,
                variables={"identity_action_token_id": str(token_id.value)},
                idempotency_key=f"identity:activation:{user_id.value}",
            )
        )
        if result.status is not NotificationStatus.QUEUED:
            raise PublicSignupProvisioningError("Signup is temporarily unavailable")
        return result.notification_id


class _CoreActivationAuditAdapter(ActivationAuditPort):
    def __init__(self, db: DbSession) -> None:
        self._use_case = RecordOrganizationAuditEventUseCase(
            AuditService(SqlAlchemyAuditLogRepository(db))
        )

    def record_activation(self, *, organization_id: UUID, user_id: UUID) -> None:
        self._use_case.execute(
            RecordOrganizationAuditEventCommand(
                organization_id=organization_id,
                user_id=user_id,
                session_id=None,
                action="identity.activation.complete",
                resource_type="identity_user",
                resource_id=str(user_id),
                old_values={
                    "user_status": "inactive",
                    "organization_status": "pending_activation",
                },
                new_values={
                    "user_status": "active",
                    "organization_status": "active",
                },
                metadata={"source": "public_account_activation"},
            )
        )


class _CorePasswordResetNotificationAdapter(PasswordResetNotificationPort):
    def __init__(self, send_notification_use_case: SendNotificationUseCase) -> None:
        self._send_notification_use_case = send_notification_use_case

    def enqueue_password_reset(
        self,
        *,
        recipient: str,
        user_id: UserId,
        token_id: IdentityActionTokenId,
    ) -> bool:
        result = self._send_notification_use_case.execute(
            SendNotificationCommand(
                organization_id=None,
                channel="email",
                recipient=recipient,
                subject="Reset your KYROX password",
                body=(
                    "A password reset was requested for your KYROX account. "
                    "The secure reset link is generated only at delivery time."
                ),
                template_key=IDENTITY_PASSWORD_RESET_TEMPLATE_KEY,
                variables={"identity_action_token_id": str(token_id.value)},
                idempotency_key=f"identity:password-reset:{token_id.value}",
            )
        )
        return result.status is NotificationStatus.QUEUED


class _CorePasswordResetAuditAdapter(PasswordResetAuditPort):
    def __init__(self, db: DbSession) -> None:
        self._audit_service = AuditService(SqlAlchemyAuditLogRepository(db))

    def record_password_reset(
        self,
        *,
        organization_id: UUID | None,
        user_id: UUID,
        sessions_revoked: int,
        refresh_tokens_revoked: int,
    ) -> None:
        self._audit_service.record(
            RecordAuditEventCommand(
                organization_id=organization_id,
                user_id=user_id,
                session_id=None,
                action="identity.password.reset",
                resource_type="identity_user",
                resource_id=str(user_id),
                new_values={"credential_replaced": True},
                metadata={
                    "source": "public_password_reset",
                    "sessions_revoked": sessions_revoked,
                    "refresh_tokens_revoked": refresh_tokens_revoked,
                },
            )
        )


class _CoreLoginAuditAdapter(LoginAuditPort):
    """``identity.user.login`` with outcome metadata (ADR-0004, F-C13)."""

    def __init__(self, db: DbSession) -> None:
        self._audit_service = AuditService(SqlAlchemyAuditLogRepository(db))

    def record_login(self, event: LoginAuditEvent) -> None:
        metadata: dict[str, str] = {"source": "password_login", "outcome": event.outcome}
        if event.reason is not None:
            metadata["reason"] = event.reason
        self._audit_service.record(
            RecordAuditEventCommand(
                organization_id=event.organization_id,
                user_id=event.user_id,
                session_id=event.session_id,
                action="identity.user.login",
                resource_type="user",
                resource_id=None if event.user_id is None else str(event.user_id),
                metadata=metadata,
                ip_address=event.ip_address,
                user_agent=event.user_agent,
            )
        )


class _CoreLogoutAuditAdapter(LogoutAuditPort):
    def __init__(self, db: DbSession) -> None:
        self._db = db
        self._audit_service = AuditService(SqlAlchemyAuditLogRepository(db))

    def record_logout(self, *, user_id: UUID, session_id: UUID) -> None:
        user = self._db.get(UserModel, user_id)
        self._audit_service.record(
            RecordAuditEventCommand(
                organization_id=None if user is None else user.organization_id,
                user_id=user_id,
                session_id=session_id,
                action="identity.user.logout",
                resource_type="user",
                resource_id=str(user_id),
                metadata={"source": "refresh_token_logout"},
            )
        )


def build_login_attempt_limiter(db: DbSession) -> SqlAlchemyLoginAttemptLimiter:
    return SqlAlchemyLoginAttemptLimiter(
        db,
        LoginThrottlePolicy(
            window_seconds=settings.CORE_LOGIN_FAILURE_WINDOW_SECONDS,
            lockout_seconds=settings.CORE_LOGIN_LOCKOUT_SECONDS,
            max_failures_per_account_ip=settings.CORE_LOGIN_MAX_FAILURES_PER_ACCOUNT_IP,
            max_failures_per_account=settings.CORE_LOGIN_MAX_FAILURES_PER_ACCOUNT,
            max_failures_per_ip=settings.CORE_LOGIN_MAX_FAILURES_PER_IP,
        ),
    )


def build_login_audit_port(db: DbSession) -> LoginAuditPort:
    return _CoreLoginAuditAdapter(db)


class _CorePasswordChangeAuditAdapter(PasswordChangeAuditPort):
    def __init__(self, db: DbSession) -> None:
        self._audit_service = AuditService(SqlAlchemyAuditLogRepository(db))

    def record_password_change(
        self,
        *,
        organization_id: UUID | None,
        user_id: UUID,
        sessions_revoked: int,
        refresh_tokens_revoked: int,
    ) -> None:
        self._audit_service.record(
            RecordAuditEventCommand(
                organization_id=organization_id,
                user_id=user_id,
                session_id=None,
                action="identity.password.change",
                resource_type="identity_user",
                resource_id=str(user_id),
                new_values={"credential_replaced": True},
                metadata={
                    "source": "authenticated_password_change",
                    "sessions_revoked": sessions_revoked,
                    "refresh_tokens_revoked": refresh_tokens_revoked,
                },
            )
        )


@lru_cache
def get_clock() -> Clock:
    return UtcClock()


@lru_cache
def get_password_hasher() -> PasswordHasher:
    return Argon2idPasswordHasher()


@lru_cache
def get_token_service() -> TokenService:
    return JwtTokenService(
        secret_key=settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
        max_lifetime_seconds=settings.access_token_expire_seconds,
    )


@lru_cache
def get_refresh_token_service() -> RefreshTokenService:
    return RefreshTokenServiceImpl()


@lru_cache
def get_identity_action_token_service() -> IdentityActionTokenService:
    return IdentityActionTokenServiceImpl(
        secret_key=settings.CORE_IDENTITY_ACTION_TOKEN_SECRET_KEY
    )


def get_id_generator() -> IdGenerator:
    return Uuid4IdGenerator()


def get_token_policy() -> TokenPolicy:
    return TokenPolicy(
        access_token_expire_seconds=settings.access_token_expire_seconds,
        refresh_token_expire_days=settings.REFRESH_TOKEN_EXPIRE_DAYS,
    )


def get_user_repository(
    db: DbSession = Depends(get_db),
    clock: Clock = Depends(get_clock),
) -> UserRepository:
    return SqlAlchemyUserRepository(db, clock)


def get_identity_action_token_repository(
    db: DbSession = Depends(get_db),
) -> IdentityActionTokenRepository:
    return SqlAlchemyIdentityActionTokenRepository(db)


def get_session_repository(db: DbSession = Depends(get_db)) -> SessionRepository:
    return SqlAlchemySessionRepository(db)


def get_refresh_token_repository(
    db: DbSession = Depends(get_db),
    clock: Clock = Depends(get_clock),
) -> RefreshTokenRepository:
    return SqlAlchemyRefreshTokenRepository(db, clock)


def get_issue_identity_action_token(
    repository: IdentityActionTokenRepository = Depends(get_identity_action_token_repository),
    token_service: IdentityActionTokenService = Depends(get_identity_action_token_service),
    clock: Clock = Depends(get_clock),
    id_generator: IdGenerator = Depends(get_id_generator),
) -> IssueIdentityActionToken:
    return IssueIdentityActionToken(
        repository=repository,
        token_service=token_service,
        clock=clock,
        id_generator=id_generator,
    )


def get_consume_identity_action_token(
    repository: IdentityActionTokenRepository = Depends(get_identity_action_token_repository),
    token_service: IdentityActionTokenService = Depends(get_identity_action_token_service),
    clock: Clock = Depends(get_clock),
) -> ConsumeIdentityActionToken:
    return ConsumeIdentityActionToken(
        repository=repository,
        token_service=token_service,
        clock=clock,
    )


def get_token_pair_issuer(
    refresh_token_repository: RefreshTokenRepository = Depends(get_refresh_token_repository),
    token_service: TokenService = Depends(get_token_service),
    refresh_token_service: RefreshTokenService = Depends(get_refresh_token_service),
    clock: Clock = Depends(get_clock),
    token_policy: TokenPolicy = Depends(get_token_policy),
    id_generator: IdGenerator = Depends(get_id_generator),
) -> TokenPairIssuer:
    return TokenPairIssuer(
        refresh_token_repository=refresh_token_repository,
        token_service=token_service,
        refresh_token_service=refresh_token_service,
        clock=clock,
        token_policy=token_policy,
        id_generator=id_generator,
    )


def get_login_use_case(
    db: DbSession = Depends(get_db),
    user_repository: UserRepository = Depends(get_user_repository),
    session_repository: SessionRepository = Depends(get_session_repository),
    refresh_token_repository: RefreshTokenRepository = Depends(get_refresh_token_repository),
    password_hasher: PasswordHasher = Depends(get_password_hasher),
    token_pair_issuer: TokenPairIssuer = Depends(get_token_pair_issuer),
    clock: Clock = Depends(get_clock),
    id_generator: IdGenerator = Depends(get_id_generator),
) -> LoginUseCase:
    return LoginUseCase(
        user_repository=user_repository,
        session_repository=session_repository,
        password_hasher=password_hasher,
        token_pair_issuer=token_pair_issuer,
        clock=clock,
        id_generator=id_generator,
        revoke_all_user_sessions=RevokeAllUserSessionsUseCase(
            session_repository=session_repository,
            refresh_token_repository=refresh_token_repository,
            clock=clock,
        ),
        attempt_limiter=build_login_attempt_limiter(db),
        audit_port=build_login_audit_port(db),
        persist_failure=db.commit,
    )


def get_refresh_session_use_case(
    db: DbSession = Depends(get_db),
    user_repository: UserRepository = Depends(get_user_repository),
    session_repository: SessionRepository = Depends(get_session_repository),
    refresh_token_repository: RefreshTokenRepository = Depends(get_refresh_token_repository),
    refresh_token_service: RefreshTokenService = Depends(get_refresh_token_service),
    token_pair_issuer: TokenPairIssuer = Depends(get_token_pair_issuer),
    clock: Clock = Depends(get_clock),
) -> RefreshSessionUseCase:
    return RefreshSessionUseCase(
        user_repository=user_repository,
        session_repository=session_repository,
        refresh_token_repository=refresh_token_repository,
        refresh_token_service=refresh_token_service,
        token_pair_issuer=token_pair_issuer,
        clock=clock,
        persist_revocation=db.commit,
    )


def get_logout_use_case(
    db: DbSession = Depends(get_db),
    session_repository: SessionRepository = Depends(get_session_repository),
    refresh_token_repository: RefreshTokenRepository = Depends(get_refresh_token_repository),
    refresh_token_service: RefreshTokenService = Depends(get_refresh_token_service),
    clock: Clock = Depends(get_clock),
) -> LogoutUseCase:
    return LogoutUseCase(
        session_repository=session_repository,
        refresh_token_repository=refresh_token_repository,
        refresh_token_service=refresh_token_service,
        clock=clock,
        audit_port=_CoreLogoutAuditAdapter(db),
    )


def get_public_signup_use_case(
    db: DbSession = Depends(get_db),
    user_repository: UserRepository = Depends(get_user_repository),
    issue_identity_action_token: IssueIdentityActionToken = Depends(get_issue_identity_action_token),
    send_notification_use_case: SendNotificationUseCase = Depends(get_send_notification_use_case),
    clock: Clock = Depends(get_clock),
    id_generator: IdGenerator = Depends(get_id_generator),
) -> PublicSignupUseCase:
    return PublicSignupUseCase(
        organization_repository=SqlAlchemyOrganizationRepository(db, clock),
        user_repository=user_repository,
        role_repository=SqlAlchemyRoleRepository(db),
        user_role_repository=SqlAlchemyUserRoleRepository(db),
        issue_identity_action_token=issue_identity_action_token,
        activation_notification_port=_CoreActivationNotificationAdapter(send_notification_use_case),
        clock=clock,
        id_generator=id_generator,
        activation_token_ttl=timedelta(hours=settings.CORE_IDENTITY_ACTION_TOKEN_TTL_HOURS),
    )


def get_complete_activation_use_case(
    db: DbSession = Depends(get_db),
    user_repository: UserRepository = Depends(get_user_repository),
    consume_identity_action_token: ConsumeIdentityActionToken = Depends(
        get_consume_identity_action_token
    ),
    password_hasher: PasswordHasher = Depends(get_password_hasher),
    clock: Clock = Depends(get_clock),
) -> CompleteActivationUseCase:
    return CompleteActivationUseCase(
        consume_identity_action_token=consume_identity_action_token,
        user_repository=user_repository,
        organization_repository=SqlAlchemyOrganizationRepository(db, clock),
        password_hasher=password_hasher,
        clock=clock,
        audit_port=_CoreActivationAuditAdapter(db),
    )


def get_forgot_password_use_case(
    db: DbSession = Depends(get_db),
    user_repository: UserRepository = Depends(get_user_repository),
    token_repository: IdentityActionTokenRepository = Depends(
        get_identity_action_token_repository
    ),
    issue_identity_action_token: IssueIdentityActionToken = Depends(
        get_issue_identity_action_token
    ),
    send_notification_use_case: SendNotificationUseCase = Depends(
        get_send_notification_use_case
    ),
    clock: Clock = Depends(get_clock),
) -> ForgotPasswordUseCase:
    return ForgotPasswordUseCase(
        user_repository=user_repository,
        organization_repository=SqlAlchemyOrganizationRepository(db, clock),
        identity_action_token_repository=token_repository,
        issue_identity_action_token=issue_identity_action_token,
        notification_port=_CorePasswordResetNotificationAdapter(
            send_notification_use_case
        ),
        clock=clock,
        token_ttl=timedelta(
            minutes=settings.CORE_IDENTITY_PASSWORD_RESET_TTL_MINUTES
        ),
        resend_cooldown=timedelta(
            seconds=settings.CORE_IDENTITY_PASSWORD_RESET_COOLDOWN_SECONDS
        ),
    )


def get_reset_password_use_case(
    db: DbSession = Depends(get_db),
    user_repository: UserRepository = Depends(get_user_repository),
    consume_identity_action_token: ConsumeIdentityActionToken = Depends(
        get_consume_identity_action_token
    ),
    password_hasher: PasswordHasher = Depends(get_password_hasher),
    session_repository: SessionRepository = Depends(get_session_repository),
    refresh_token_repository: RefreshTokenRepository = Depends(
        get_refresh_token_repository
    ),
    clock: Clock = Depends(get_clock),
) -> ResetPasswordUseCase:
    return ResetPasswordUseCase(
        consume_identity_action_token=consume_identity_action_token,
        user_repository=user_repository,
        organization_repository=SqlAlchemyOrganizationRepository(db, clock),
        password_hasher=password_hasher,
        revoke_all_user_sessions=RevokeAllUserSessionsUseCase(
            session_repository=session_repository,
            refresh_token_repository=refresh_token_repository,
            clock=clock,
        ),
        clock=clock,
        audit_port=_CorePasswordResetAuditAdapter(db),
    )


def get_change_password_use_case(
    db: DbSession = Depends(get_db),
    user_repository: UserRepository = Depends(get_user_repository),
    password_hasher: PasswordHasher = Depends(get_password_hasher),
    session_repository: SessionRepository = Depends(get_session_repository),
    refresh_token_repository: RefreshTokenRepository = Depends(
        get_refresh_token_repository
    ),
    clock: Clock = Depends(get_clock),
) -> ChangePasswordUseCase:
    return ChangePasswordUseCase(
        user_repository=user_repository,
        password_hasher=password_hasher,
        revoke_all_user_sessions=RevokeAllUserSessionsUseCase(
            session_repository=session_repository,
            refresh_token_repository=refresh_token_repository,
            clock=clock,
        ),
        clock=clock,
        audit_port=_CorePasswordChangeAuditAdapter(db),
    )
