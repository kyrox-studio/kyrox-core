"""Realistic organization RBAC seed for privilege / audit regression tests.

Users authenticate through the real ``/api/v1/auth/login`` route, so tests use
real access tokens, sessions and RBAC lookups (no dependency overrides).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.modules.identity.infrastructure.authentication.security import Argon2idPasswordHasher
from app.modules.identity.infrastructure.authorization.persistence.models import (
    PermissionGroupModel,
    PermissionModel,
    RoleModel,
    RolePermissionModel,
    UserRoleModel,
)
from app.modules.identity.infrastructure.organization.persistence.models import OrganizationModel
from app.modules.identity.infrastructure.persistence.models import UserModel

PASSWORD = "Seed-Passw0rd-2026!"

CATALOG = (
    ("identity.users.read", True),
    ("identity.users.create", True),
    ("identity.users.update", True),
    ("identity.users.delete", True),
    ("identity.roles.read", True),
    ("identity.roles.create", True),
    ("identity.roles.update", True),
    ("identity.roles.delete", True),
    ("identity.roles.assign", True),
    ("identity.roles.assign_protected", False),
    ("identity.permissions.read", True),
    ("fair_crm.customers.read", True),
    ("fair_crm.customers.update", True),
)

# Editor: the E-023 evidence role (create/update user + role editing, no delete,
# no role assignment, no customer update).
EDITOR_CODES = (
    "identity.users.read",
    "identity.users.create",
    "identity.users.update",
    "identity.roles.read",
    "identity.roles.create",
    "identity.roles.update",
    "fair_crm.customers.read",
)
MEMBER_CODES = ("fair_crm.customers.read",)


@dataclass
class Seed:
    organization_id: uuid.UUID
    permission_ids: dict[str, uuid.UUID]
    role_ids: dict[str, uuid.UUID]
    user_ids: dict[str, uuid.UUID]
    emails: dict[str, str] = field(default_factory=dict)

    def ids(self, *codes: str) -> list[str]:
        return [str(self.permission_ids[code]) for code in codes]


def _now() -> datetime:
    return datetime.now(UTC)


def seed_organization(db: Session) -> Seed:
    tag = uuid.uuid4().hex[:8]
    organization_id = uuid.uuid4()
    db.add(OrganizationModel(id=organization_id, name=f"Org {tag}", slug=f"org-{tag}", status="active"))
    group_id = uuid.uuid4()
    db.add(PermissionGroupModel(
        id=group_id, code=f"seed.{tag}", name="Seed", module="identity",
        description="Seed", sort_order=1, is_system=False,
    ))
    db.flush()
    permission_ids: dict[str, uuid.UUID] = {}
    for code, assignable in CATALOG:
        permission_ids[code] = uuid.uuid4()
        db.add(PermissionModel(
            id=permission_ids[code], group_id=group_id, code=code, description=code,
            is_system=True, lifecycle_state="active", is_assignable=assignable,
        ))
    db.flush()

    role_ids = {
        "organization_admin": uuid.uuid4(),
        "editor": uuid.uuid4(),
        "member": uuid.uuid4(),
    }
    db.add(RoleModel(
        id=role_ids["organization_admin"], name="OrganizationAdmin", slug="organization_admin",
        scope="organization", is_system=True, role_kind="protected_global", organization_id=None,
        template_version=1, permissions_customized=False, is_assignable=True, is_protected=True,
        auto_include_new_permissions=True,
    ))
    for key in ("editor", "member"):
        db.add(RoleModel(
            id=role_ids[key], name=key.title(), slug=f"{key}_{tag}", scope="organization",
            is_system=False, role_kind="organization", organization_id=organization_id,
            template_version=1, permissions_customized=True, is_assignable=True,
            is_protected=False, auto_include_new_permissions=False,
        ))
    db.flush()
    for code in permission_ids:
        db.add(RolePermissionModel(role_id=role_ids["organization_admin"], permission_id=permission_ids[code]))
    for code in EDITOR_CODES:
        db.add(RolePermissionModel(role_id=role_ids["editor"], permission_id=permission_ids[code]))
    for code in MEMBER_CODES:
        db.add(RolePermissionModel(role_id=role_ids["member"], permission_id=permission_ids[code]))
    db.flush()

    seed = Seed(organization_id=organization_id, permission_ids=permission_ids, role_ids=role_ids, user_ids={})
    for key in ("admin", "editor", "member"):
        add_user(db, seed, key, role_key="organization_admin" if key == "admin" else key)
    db.commit()
    return seed


def add_role(db: Session, seed: Seed, key: str, codes: tuple[str, ...]) -> uuid.UUID:
    role_id = uuid.uuid4()
    db.add(RoleModel(
        id=role_id, name=key.title(), slug=f"{key}_{uuid.uuid4().hex[:6]}", scope="organization",
        is_system=False, role_kind="organization", organization_id=seed.organization_id,
        template_version=1, permissions_customized=True, is_assignable=True,
        is_protected=False, auto_include_new_permissions=False,
    ))
    db.flush()
    for code in codes:
        db.add(RolePermissionModel(role_id=role_id, permission_id=seed.permission_ids[code]))
    db.commit()
    seed.role_ids[key] = role_id
    return role_id


def add_user(db: Session, seed: Seed, key: str, *, role_key: str) -> uuid.UUID:
    user_id = uuid.uuid4()
    email = f"{key}-{uuid.uuid4().hex[:6]}@example.com"
    db.add(UserModel(
        id=user_id, email=email, password_hash=Argon2idPasswordHasher().hash(PASSWORD).value,
        status="active", is_super_admin=False, organization_id=seed.organization_id,
        created_at=_now(), updated_at=_now(),
    ))
    db.flush()
    db.add(UserRoleModel(
        user_id=user_id, organization_id=seed.organization_id, role_id=seed.role_ids[role_key],
        status="active", assigned_at=_now(),
    ))
    db.commit()
    seed.user_ids[key] = user_id
    seed.emails[key] = email
    return user_id


def login(client: TestClient, email: str, password: str = PASSWORD) -> str:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def headers(client: TestClient, seed: Seed, key: str) -> dict[str, str]:
    token = login(client, seed.emails[key])
    return {"Authorization": f"Bearer {token}", "X-Organization-Id": str(seed.organization_id)}
