import uuid
from datetime import UTC, datetime, timedelta


from app.core.config import settings
from app.modules.identity.domain.authentication.entities.refresh_token import RefreshToken
from app.modules.identity.domain.authentication.entities.session import Session
from app.modules.identity.domain.authentication.entities.user import User
from app.modules.identity.domain.authentication.enums.refresh_token_revoke_reason import (
    RefreshTokenRevokeReason,
)
from app.modules.identity.domain.authentication.enums.user_status import UserStatus
from app.modules.identity.domain.authentication.value_objects.client.ip_address import IpAddress
from app.modules.identity.domain.authentication.value_objects.identity.family_id import FamilyId
from app.modules.identity.domain.authentication.value_objects.identity.refresh_token_id import (
    RefreshTokenId,
)
from app.modules.identity.domain.authentication.value_objects.identity.session_id import SessionId
from app.modules.identity.domain.authentication.value_objects.identity.user_id import UserId
from app.modules.identity.domain.authentication.value_objects.security.access_token import (
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
from app.modules.identity.infrastructure.authentication.persistence.mappers.refresh_token_mapper import (
    RefreshTokenMapper,
)
from app.modules.identity.infrastructure.authentication.persistence.mappers.session_mapper import (
    SessionMapper,
)
from app.modules.identity.infrastructure.authentication.persistence.mappers.user_mapper import (
    UserMapper,
)
from app.modules.identity.infrastructure.authentication.persistence.models.refresh_token import (
    RefreshTokenModel,
)
from app.modules.identity.infrastructure.authentication.persistence.models.session import SessionModel
from app.modules.identity.infrastructure.authentication.security.argon2_password_hasher import (
    Argon2idPasswordHasher,
)
from app.modules.identity.infrastructure.authentication.security.jwt_token_service import (
    JwtTokenService,
)
from app.modules.identity.infrastructure.authentication.security.refresh_token_service import (
    RefreshTokenService,
)
from app.modules.identity.infrastructure.persistence.models import UserModel


def _now() -> datetime:
    return datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)


def test_user_mapper_roundtrip() -> None:
    user = User(
        id=UserId(uuid.uuid4()),
        email=Email.create("user@example.com"),
        password_hash=PasswordHash("hash"),
        status=UserStatus.ACTIVE,
        created_at=_now(),
        updated_at=_now(),
    )
    model = UserMapper.to_model(user)
    assert isinstance(model, UserModel)
    assert UserMapper.to_domain(model) == user


def test_session_mapper_roundtrip() -> None:
    session = Session(
        id=SessionId(uuid.uuid4()),
        user_id=UserId(uuid.uuid4()),
        created_at=_now(),
        updated_at=_now(),
        last_activity_at=_now(),
        ip_address=IpAddress.create("127.0.0.1"),
    )
    model = SessionMapper.to_model(session)
    assert isinstance(model, SessionModel)
    restored = SessionMapper.to_domain(model)
    assert restored.id.value == session.id.value
    assert restored.ip_address == session.ip_address


def test_refresh_token_mapper_roundtrip() -> None:
    token = RefreshToken(
        id=RefreshTokenId(uuid.uuid4()),
        session_id=SessionId(uuid.uuid4()),
        token_hash=TokenHash("abc123"),
        family_id=FamilyId(uuid.uuid4()),
        expires_at=_now() + timedelta(days=1),
        created_at=_now(),
        revoked_reason=RefreshTokenRevokeReason.LOGOUT,
    )
    model = RefreshTokenMapper.to_model(token)
    assert isinstance(model, RefreshTokenModel)
    restored = RefreshTokenMapper.to_domain(model)
    assert restored.token_hash.value == token.token_hash.value
    assert restored.revoked_reason is RefreshTokenRevokeReason.LOGOUT


def test_argon2_password_hasher_hashes_and_verifies() -> None:
    hasher = Argon2idPasswordHasher()
    password_hash = hasher.hash("secret")
    assert hasher.verify("secret", password_hash) is True
    assert hasher.verify("wrong", password_hash) is False


def test_jwt_token_service_roundtrip_with_constructor_injection() -> None:
    service = JwtTokenService(
        secret_key=settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    issued_at = datetime.now(tz=UTC)
    claims = AccessTokenClaims(
        sub=UserId(uuid.uuid4()),
        email=Email.create("user@example.com"),
        sid=SessionId(uuid.uuid4()),
        exp=issued_at + timedelta(minutes=15),
        iat=issued_at,
        jti=uuid.uuid4(),
    )
    token = service.create_access_token(claims)
    decoded = service.decode_access_token(token)
    assert decoded.sub.value == claims.sub.value
    assert decoded.email.value == claims.email.value


def test_refresh_token_service_uses_constant_time_compare() -> None:
    service = RefreshTokenService()
    token = service.create()
    token_hash = service.hash(token)
    assert service.verify(token, token_hash) is True
    assert service.verify(RefreshTokenValue.create("other-token"), token_hash) is False
