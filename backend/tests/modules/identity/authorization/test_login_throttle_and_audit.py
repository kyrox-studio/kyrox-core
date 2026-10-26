"""F-004 (login) and F-C13 (sign-in audit) regression tests.

E-023 evidence: after 30 wrong passwords the correct password still returned
200; login (success/failure) and logout left ``audit_logs`` empty.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import jwt
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.modules.audit.infrastructure.persistence.models import AuditLogModel
from app.modules.identity.infrastructure.authentication.persistence.models import LoginThrottleModel
from tests.modules.identity.authorization.privilege_seed import PASSWORD, seed_organization

LOGIN = "/api/v1/auth/login"
WRONG = "Wrong-Passw0rd-123!"
THROTTLED = "Too many sign-in attempts. Try again later."


def _attempt(client: TestClient, email: str, password: str) -> int:
    return client.post(LOGIN, json={"email": email, "password": password}).status_code


def test_correct_password_is_refused_while_locked(client: TestClient, db_session: Session) -> None:
    seed = seed_organization(db_session)
    email = seed.emails["member"]

    assert [_attempt(client, email, WRONG) for _ in range(5)] == [401] * 5
    locked = client.post(LOGIN, json={"email": email, "password": PASSWORD})
    assert locked.status_code == 429
    assert locked.json() == {"detail": THROTTLED}


def test_lock_does_not_reveal_whether_account_exists(client: TestClient, db_session: Session) -> None:
    seed_organization(db_session)
    ghost = "nobody-here@example.com"

    assert [_attempt(client, ghost, WRONG) for _ in range(5)] == [401] * 5
    response = client.post(LOGIN, json={"email": ghost, "password": WRONG})
    assert response.status_code == 429
    assert response.json() == {"detail": THROTTLED}
    # Counters are hashed; the submitted address is not stored.
    db_session.expire_all()
    keys = db_session.scalars(select(LoginThrottleModel.key_hash)).all()
    assert keys and all(ghost not in key for key in keys)


def test_successful_login_resets_counter(client: TestClient, db_session: Session) -> None:
    seed = seed_organization(db_session)
    email = seed.emails["member"]

    assert [_attempt(client, email, WRONG) for _ in range(4)] == [401] * 4
    assert _attempt(client, email, PASSWORD) == 200
    assert [_attempt(client, email, WRONG) for _ in range(4)] == [401] * 4
    assert _attempt(client, email, PASSWORD) == 200


def test_lock_is_temporary(client: TestClient, db_session: Session) -> None:
    seed = seed_organization(db_session)
    email = seed.emails["member"]
    for _ in range(5):
        _attempt(client, email, WRONG)
    assert _attempt(client, email, PASSWORD) == 429

    past = datetime.now(UTC) - timedelta(hours=1)
    db_session.execute(update(LoginThrottleModel).values(locked_until=past, window_started_at=past))
    db_session.commit()
    assert _attempt(client, email, PASSWORD) == 200


def test_sign_in_events_are_audited_without_secrets(client: TestClient, db_session: Session) -> None:
    seed = seed_organization(db_session)
    email = seed.emails["member"]
    member_id = seed.user_ids["member"]

    assert _attempt(client, email, WRONG) == 401
    assert _attempt(client, "unknown-user@example.com", WRONG) == 401
    ok = client.post(LOGIN, json={"email": email, "password": PASSWORD})
    assert ok.status_code == 200
    sid = uuid.UUID(jwt.decode(ok.json()["access_token"], options={"verify_signature": False})["sid"])
    assert client.post("/api/v1/auth/logout", json={"refresh_token": ok.json()["refresh_token"]}).status_code == 204

    db_session.expire_all()
    rows = list(db_session.scalars(select(AuditLogModel).order_by(AuditLogModel.created_at)).all())
    summary = [(row.action, (row.event_metadata or {}).get("outcome"), (row.event_metadata or {}).get("reason")) for row in rows]
    assert summary == [
        ("identity.user.login", "failure", "invalid_credentials"),
        ("identity.user.login", "failure", "invalid_credentials"),
        ("identity.user.login", "success", None),
        ("identity.user.logout", None, None),
    ]
    known_failure, unknown_failure, success, logout = rows
    assert known_failure.user_id == member_id and known_failure.organization_id == seed.organization_id
    assert unknown_failure.user_id is None and unknown_failure.resource_id is None
    assert success.user_id == member_id and success.session_id == sid
    assert logout.user_id == member_id and logout.session_id == sid
    assert logout.organization_id == seed.organization_id
    serialized = json.dumps([[row.old_values, row.new_values, row.event_metadata, row.resource_id] for row in rows])
    assert WRONG not in serialized and PASSWORD not in serialized
    assert "unknown-user@example.com" not in serialized


def test_throttled_attempt_is_audited(client: TestClient, db_session: Session) -> None:
    seed = seed_organization(db_session)
    email = seed.emails["member"]
    for _ in range(5):
        _attempt(client, email, WRONG)
    assert _attempt(client, email, PASSWORD) == 429

    db_session.expire_all()
    last = db_session.scalars(select(AuditLogModel).order_by(AuditLogModel.created_at.desc())).first()
    assert last.action == "identity.user.login"
    assert last.event_metadata["reason"] == "throttled"
    assert last.user_id == seed.user_ids["member"]
