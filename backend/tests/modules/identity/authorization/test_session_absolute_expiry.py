"""F-C8 regression: token lifetime cap and absolute session expiry.

E-023 evidence: a 10-year access token signed with the key and naming an
active session ``sid`` was accepted (200); sessions had no end.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import jwt
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.modules.identity.infrastructure.authentication.persistence.models import (
    RefreshTokenModel,
    SessionModel,
)
from tests.modules.identity.authorization.privilege_seed import PASSWORD, seed_organization

CONTEXT_URL = "/api/v1/user-management/context"


def _login(client: TestClient, email: str) -> dict:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return response.json()


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _forge(access_token: str, *, iat: datetime, exp: datetime) -> str:
    claims = jwt.decode(access_token, options={"verify_signature": False})
    claims.update({"iat": int(iat.timestamp()), "exp": int(exp.timestamp()), "jti": str(uuid.uuid4())})
    return jwt.encode(claims, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def test_ten_year_token_for_active_session_is_rejected(client: TestClient, db_session: Session) -> None:
    seed = seed_organization(db_session)
    tokens = _login(client, seed.emails["member"])
    assert client.get(CONTEXT_URL, headers=_bearer(tokens["access_token"])).status_code == 200

    now = datetime.now(UTC)
    ten_years = _forge(tokens["access_token"], iat=now, exp=now + timedelta(days=3650))
    assert client.get(CONTEXT_URL, headers=_bearer(ten_years)).status_code == 401
    from_future = _forge(
        tokens["access_token"],
        iat=now + timedelta(days=1),
        exp=now + timedelta(days=1, seconds=settings.access_token_expire_seconds),
    )
    assert client.get(CONTEXT_URL, headers=_bearer(from_future)).status_code == 401
    # The genuine token of the same session still works.
    assert client.get(CONTEXT_URL, headers=_bearer(tokens["access_token"])).status_code == 200


def test_expired_session_rejects_access_and_refresh(client: TestClient, db_session: Session) -> None:
    seed = seed_organization(db_session)
    tokens = _login(client, seed.emails["member"])
    sid = uuid.UUID(jwt.decode(tokens["access_token"], options={"verify_signature": False})["sid"])

    db_session.expire_all()
    session = db_session.get(SessionModel, sid)
    session.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    db_session.commit()

    assert client.get(CONTEXT_URL, headers=_bearer(tokens["access_token"])).status_code == 401
    refreshed = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refreshed.status_code == 401


def test_login_sets_absolute_end_and_rotation_never_extends_it(client: TestClient, db_session: Session) -> None:
    seed = seed_organization(db_session)
    before = datetime.now(UTC)
    tokens = _login(client, seed.emails["member"])
    sid = uuid.UUID(jwt.decode(tokens["access_token"], options={"verify_signature": False})["sid"])

    db_session.expire_all()
    expires_at = db_session.get(SessionModel, sid).expires_at.replace(tzinfo=UTC)
    lifetime = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    assert before + lifetime - timedelta(minutes=1) <= expires_at <= datetime.now(UTC) + lifetime

    # Shorten the session: a rotated refresh token is capped at the session end.
    session_end = datetime.now(UTC) + timedelta(hours=1)
    db_session.get(SessionModel, sid).expires_at = session_end
    db_session.commit()
    rotated = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert rotated.status_code == 200, rotated.text

    db_session.expire_all()
    newest = db_session.scalars(
        select(RefreshTokenModel)
        .where(RefreshTokenModel.session_id == sid, RefreshTokenModel.revoked_at.is_(None))
    ).one()
    assert newest.expires_at.replace(tzinfo=UTC) <= session_end + timedelta(seconds=1)
