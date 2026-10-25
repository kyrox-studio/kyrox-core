"""Session revocation regressions (SECURITY_PROGRAM F-C3, F-C4, F-C4b, F-C10)
and the ADR-0003 last-active-Super-Admin invariant at the API layer (F-C9).

The database override mirrors production ``get_db`` (commit on success,
rollback on error) so revocations written on rejected requests are observable.
"""

from collections.abc import Generator
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.modules.identity.infrastructure.authentication.persistence.models.refresh_token import (
    RefreshTokenModel,
)
from app.modules.identity.infrastructure.authentication.persistence.models.session import SessionModel
from app.modules.identity.infrastructure.authentication.security import Argon2idPasswordHasher
from app.modules.identity.infrastructure.authorization.persistence.models import (
    PermissionGroupModel,
    PermissionModel,
    RoleModel,
    RolePermissionModel,
    UserRoleModel,
)
from app.modules.identity.infrastructure.organization.persistence.models.organization import (
    OrganizationModel,
)
from app.modules.identity.infrastructure.persistence.models import UserModel

PASSWORD = "session revocation 12345"
NEW_PASSWORD = "session revocation 67890"
ADMIN_PERMISSIONS = (
    "identity.users.read",
    "identity.users.create",
    "identity.users.update",
    "identity.users.delete",
    "identity.roles.read",
    "identity.roles.assign",
    "identity.organizations.read",
)


@dataclass
class World:
    client: TestClient
    session_factory: sessionmaker
    org_a: UUID
    org_b: UUID
    super_admin: UUID
    second_super_admin: UUID
    org_admin: UUID
    member: UUID


@pytest.fixture
def world() -> Generator[World, None, None]:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime.now(tz=UTC)
    password_hash = Argon2idPasswordHasher().hash(PASSWORD).value

    with session_factory() as db:
        group = PermissionGroupModel(code="identity", name="Identity", module="identity", description="d")
        db.add(group)
        db.flush()
        permissions = [
            PermissionModel(
                group_id=group.id,
                code=code,
                description=code,
                is_assignable=True,
                permission_scope="organization",
            )
            for code in ADMIN_PERMISSIONS
        ]
        db.add_all(permissions)
        org_a = OrganizationModel(name="Org A", slug="org-a", status="active")
        org_b = OrganizationModel(name="Org B", slug="org-b", status="active")
        db.add_all([org_a, org_b])
        db.flush()
        admin_role = RoleModel(
            name="OrganizationAdmin",
            slug="organization_admin",
            scope="organization",
            is_system=True,
            role_kind="protected_global",
            organization_id=None,
            is_assignable=True,
            is_protected=True,
        )
        member_role = RoleModel(
            name="Member",
            slug="member",
            scope="organization",
            role_kind="organization",
            organization_id=org_a.id,
            is_assignable=True,
            is_protected=False,
        )
        db.add_all([admin_role, member_role])
        db.flush()
        for permission in permissions:
            db.add(RolePermissionModel(role_id=admin_role.id, permission_id=permission.id))

        def user(email: str, *, role: RoleModel | None = None, super_admin: bool = False) -> UUID:
            model = UserModel(
                email=email,
                password_hash=password_hash,
                status="active",
                is_super_admin=super_admin,
                organization_id=org_a.id,
            )
            db.add(model)
            db.flush()
            if role is not None:
                db.add(
                    UserRoleModel(
                        user_id=model.id,
                        organization_id=org_a.id,
                        role_id=role.id,
                        status="active",
                        assigned_at=now,
                    )
                )
            return model.id

        super_admin = user("sa1@revocation-audit.com", super_admin=True)
        second_super_admin = user("sa2@revocation-audit.com", super_admin=True)
        org_admin = user("admin@revocation-audit.com", role=admin_role)
        member = user("member@revocation-audit.com", role=member_role)
        db.commit()
        org_a_id, org_b_id = org_a.id, org_b.id

    app = create_app()

    def production_like_get_db() -> Generator[Session, None, None]:
        db = session_factory()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    app.dependency_overrides[get_db] = production_like_get_db
    client = TestClient(app, raise_server_exceptions=False)
    try:
        yield World(
            client=client,
            session_factory=session_factory,
            org_a=org_a_id,
            org_b=org_b_id,
            super_admin=super_admin,
            second_super_admin=second_super_admin,
            org_admin=org_admin,
            member=member,
        )
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def _login(world: World, email: str, password: str = PASSWORD) -> dict[str, str]:
    response = world.client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()


def _headers(access_token: str, organization_id: UUID | None = None) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {access_token}"}
    if organization_id is not None:
        headers["X-Organization-Id"] = str(organization_id)
    return headers


def _active_sessions(world: World, user_id: UUID) -> list[SessionModel]:
    with world.session_factory() as db:
        return list(
            db.scalars(
                select(SessionModel).where(
                    SessionModel.user_id == user_id,
                    SessionModel.revoked_at.is_(None),
                )
            )
        )


def test_refresh_reuse_revokes_session_and_rotated_pair(world: World) -> None:
    original = _login(world, "member@revocation-audit.com")
    rotated = world.client.post("/api/v1/auth/refresh", json={"refresh_token": original["refresh_token"]})
    assert rotated.status_code == 200, rotated.text
    rotated_pair = rotated.json()

    reuse = world.client.post("/api/v1/auth/refresh", json={"refresh_token": original["refresh_token"]})

    assert reuse.status_code == 401
    assert _active_sessions(world, world.member) == []
    with world.session_factory() as db:
        assert db.scalars(
            select(RefreshTokenModel).where(RefreshTokenModel.reuse_detected_at.is_not(None))
        ).all()
    assert (
        world.client.get(
            "/api/v1/user-management/context",
            headers=_headers(rotated_pair["access_token"]),
        ).status_code
        == 401
    )
    assert (
        world.client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": rotated_pair["refresh_token"]},
        ).status_code
        == 401
    )


@pytest.mark.parametrize(
    "change",
    [
        {"password": NEW_PASSWORD},
        {"status": "inactive"},
        {"email": "renamed@revocation-audit.com"},
    ],
)
def test_admin_user_change_revokes_existing_sessions(world: World, change: dict[str, str]) -> None:
    member_tokens = _login(world, "member@revocation-audit.com")
    admin_token = _login(world, "admin@revocation-audit.com")["access_token"]

    response = world.client.patch(
        f"/api/v1/organizations/{world.org_a}/users/{world.member}",
        json=change,
        headers=_headers(admin_token, world.org_a),
    )

    assert response.status_code == 200, response.text
    assert _active_sessions(world, world.member) == []
    assert (
        world.client.get(
            "/api/v1/user-management/context",
            headers=_headers(member_tokens["access_token"]),
        ).status_code
        == 401
    )
    assert (
        world.client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": member_tokens["refresh_token"]},
        ).status_code
        == 401
    )


def test_admin_user_role_only_change_keeps_sessions(world: World) -> None:
    _login(world, "member@revocation-audit.com")
    admin_token = _login(world, "admin@revocation-audit.com")["access_token"]

    response = world.client.patch(
        f"/api/v1/organizations/{world.org_a}/users/{world.member}",
        json={"status": "active"},
        headers=_headers(admin_token, world.org_a),
    )

    assert response.status_code == 200, response.text
    assert len(_active_sessions(world, world.member)) == 1


def test_admin_user_delete_revokes_existing_sessions(world: World) -> None:
    member_tokens = _login(world, "member@revocation-audit.com")
    admin_token = _login(world, "admin@revocation-audit.com")["access_token"]

    response = world.client.delete(
        f"/api/v1/organizations/{world.org_a}/users/{world.member}",
        headers=_headers(admin_token, world.org_a),
    )

    assert response.status_code == 204, response.text
    assert _active_sessions(world, world.member) == []
    assert (
        world.client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": member_tokens["refresh_token"]},
        ).status_code
        == 401
    )


@pytest.mark.parametrize("action", ["deactivate", "delete", "demote"])
def test_removed_super_admin_old_token_loses_bypass(world: World, action: str) -> None:
    removed_token = _login(world, "sa2@revocation-audit.com")["access_token"]
    actor_token = _login(world, "sa1@revocation-audit.com")["access_token"]
    path = f"/api/v1/organizations/{world.org_a}/users/{world.second_super_admin}"

    if action == "deactivate":
        response = world.client.patch(path, json={"status": "inactive"}, headers=_headers(actor_token, world.org_a))
    elif action == "delete":
        response = world.client.delete(path, headers=_headers(actor_token, world.org_a))
    else:
        with world.session_factory() as db:
            admin_role_id = db.scalar(select(RoleModel.id).where(RoleModel.slug == "organization_admin"))
        response = world.client.patch(
            path,
            json={"is_super_admin": False, "role_id": str(admin_role_id)},
            headers=_headers(actor_token, world.org_a),
        )

    assert response.status_code in (200, 204), response.text
    assert world.client.get("/api/v1/system/settings", headers=_headers(removed_token)).status_code == 401
    assert (
        world.client.get(
            f"/api/v1/organizations/{world.org_b}/users",
            headers=_headers(removed_token, world.org_b),
        ).status_code
        == 401
    )


@pytest.mark.parametrize("action", ["deactivate", "delete", "demote"])
def test_last_active_super_admin_cannot_remove_itself(world: World, action: str) -> None:
    actor_token = _login(world, "sa1@revocation-audit.com")["access_token"]
    removed = world.client.delete(
        f"/api/v1/organizations/{world.org_a}/users/{world.second_super_admin}",
        headers=_headers(actor_token, world.org_a),
    )
    assert removed.status_code == 204, removed.text
    path = f"/api/v1/organizations/{world.org_a}/users/{world.super_admin}"

    if action == "deactivate":
        response = world.client.patch(path, json={"status": "inactive"}, headers=_headers(actor_token, world.org_a))
    elif action == "delete":
        response = world.client.delete(path, headers=_headers(actor_token, world.org_a))
    else:
        with world.session_factory() as db:
            admin_role_id = db.scalar(select(RoleModel.id).where(RoleModel.slug == "organization_admin"))
        response = world.client.patch(
            path,
            json={"is_super_admin": False, "role_id": str(admin_role_id)},
            headers=_headers(actor_token, world.org_a),
        )

    assert response.status_code == 409, response.text
    with world.session_factory() as db:
        last = db.get(UserModel, world.super_admin)
        assert last is not None
        assert last.is_super_admin is True
        assert last.status == "active"
        assert last.deleted_at is None
    assert len(_active_sessions(world, world.super_admin)) == 1
    assert world.client.get("/api/v1/system/settings", headers=_headers(actor_token)).status_code == 200


@pytest.mark.parametrize("claim", ["exp", "iat", "sid", "jti", "email"])
def test_validly_signed_token_with_missing_claim_is_401(world: World, claim: str) -> None:
    access_token = _login(world, "member@revocation-audit.com")["access_token"]
    claims = jwt.decode(access_token, options={"verify_signature": False})
    claims.pop(claim)
    forged = jwt.encode(claims, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

    response = world.client.get("/api/v1/user-management/context", headers=_headers(forged))

    assert response.status_code == 401
