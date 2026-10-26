"""F-C13 regression: identity administration writes ADR-0004 audit events.

E-023 evidence: user creation, role assignment, deactivation, deletion and
Super Admin grant left ``audit_logs`` empty; role management used 2-segment
actions with ``session_id`` NULL.
"""

from __future__ import annotations

import json
import re
import uuid

import jwt
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.modules.audit.infrastructure.persistence.models import AuditLogModel
from app.modules.identity.infrastructure.authentication.security import Argon2idPasswordHasher
from app.modules.identity.infrastructure.persistence.models import UserModel
from tests.modules.identity.authorization.privilege_seed import (
    EDITOR_CODES,
    PASSWORD,
    login,
    seed_organization,
)

ADR_0004_ACTION = re.compile(r"^identity\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
SECRET = "Audit-Secret-Passw0rd!"


def _rows(db: Session) -> list[AuditLogModel]:
    """Administration events only; sign-in events are covered by the login tests."""
    db.expire_all()
    return list(db.scalars(
        select(AuditLogModel)
        .where(AuditLogModel.action != "identity.user.login")
        .order_by(AuditLogModel.created_at)
    ).all())


def _sid(token: str) -> uuid.UUID:
    return uuid.UUID(jwt.decode(token, options={"verify_signature": False})["sid"])


def _auth(token: str, seed) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "X-Organization-Id": str(seed.organization_id)}


def test_user_lifecycle_and_role_changes_are_audited(client: TestClient, db_session: Session) -> None:
    seed = seed_organization(db_session)
    token = login(client, seed.emails["admin"])
    auth = _auth(token, seed)
    base = f"/api/v1/organizations/{seed.organization_id}"

    created = client.post(
        f"{base}/users/manual",
        json={"email": "audited@example.com", "password": SECRET, "role_id": str(seed.role_ids["member"])},
        headers=auth,
    )
    assert created.status_code == 201, created.text
    user_id = created.json()["id"]
    assert client.patch(f"{base}/users/{user_id}", json={"password": SECRET + "x", "email": "audited2@example.com"}, headers=auth).status_code == 200
    assert client.patch(f"{base}/users/{user_id}", json={"role_id": str(seed.role_ids["editor"])}, headers=auth).status_code == 200
    assert client.patch(f"{base}/users/{user_id}", json={"status": "inactive"}, headers=auth).status_code == 200
    assert client.delete(f"{base}/users/{user_id}", headers=auth).status_code == 204
    assert client.put(
        f"{base}/roles/{seed.role_ids['member']}/permissions",
        json={"permission_ids": seed.ids("fair_crm.customers.read", "identity.users.read")},
        headers=auth,
    ).status_code == 200

    rows = _rows(db_session)
    actions = [row.action for row in rows]
    for expected in (
        "identity.user.created",
        "identity.role.assigned",
        "identity.user.updated",
        "identity.user.deactivated",
        "identity.user.deleted",
        "identity.permission.granted",
    ):
        assert expected in actions, (expected, actions)
    assert actions.count("identity.role.assigned") == 2
    assert all(ADR_0004_ACTION.match(action) for action in actions), actions
    assert {row.session_id for row in rows} == {_sid(token)}
    assert {row.user_id for row in rows} == {seed.user_ids["admin"]}
    assert all(row.organization_id == seed.organization_id for row in rows)
    updated = next(row for row in rows if row.action == "identity.user.updated")
    assert updated.event_metadata["changed_fields"] == ["email", "password"]
    serialized = json.dumps([[row.old_values, row.new_values, row.event_metadata] for row in rows])
    assert SECRET not in serialized
    assert "argon2" not in serialized


def test_role_management_actions_follow_naming_with_session(client: TestClient, db_session: Session) -> None:
    seed = seed_organization(db_session)
    token = login(client, seed.emails["admin"])
    auth = _auth(token, seed)
    base = f"/api/v1/organizations/{seed.organization_id}"

    created = client.post(f"{base}/roles", json={"name": "Audit", "slug": "audit_role", "permission_ids": seed.ids(*EDITOR_CODES)}, headers=auth)
    assert created.status_code == 201, created.text
    role_id = created.json()["id"]
    assert client.patch(f"{base}/roles/{role_id}", json={"name": "Audit 2"}, headers=auth).status_code == 200
    assert client.put(f"{base}/roles/{role_id}/permissions", json={"permission_ids": seed.ids("identity.users.read")}, headers=auth).status_code == 200
    assert client.delete(f"{base}/roles/{role_id}", headers=auth).status_code == 204

    rows = _rows(db_session)
    actions = [row.action for row in rows]
    assert actions == [
        "identity.role.created",
        "identity.permission.granted",
        "identity.role.updated",
        "identity.permission.revoked",
        "identity.role.deleted",
    ]
    assert {row.session_id for row in rows} == {_sid(token)}


def test_super_admin_grant_is_audited(client: TestClient, db_session: Session) -> None:
    seed = seed_organization(db_session)
    super_admin_id = uuid.uuid4()
    db_session.add(UserModel(
        id=super_admin_id, email="root@example.com",
        password_hash=Argon2idPasswordHasher().hash(PASSWORD).value,
        status="active", is_super_admin=True, organization_id=seed.organization_id,
    ))
    db_session.commit()
    token = login(client, "root@example.com")

    response = client.patch(
        f"/api/v1/organizations/{seed.organization_id}/users/{seed.user_ids['member']}",
        json={"is_super_admin": True},
        headers=_auth(token, seed),
    )
    assert response.status_code == 200, response.text

    rows = [row for row in _rows(db_session) if row.action == "identity.user.super_admin_granted"]
    assert len(rows) == 1
    assert rows[0].resource_id == str(seed.user_ids["member"])
    assert rows[0].user_id == super_admin_id
    assert rows[0].session_id == _sid(token)
