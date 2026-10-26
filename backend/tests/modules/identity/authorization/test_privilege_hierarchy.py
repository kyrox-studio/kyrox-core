"""F-C1 / F-C2 regression tests (SECURITY_PROGRAM §6.16, E-023 evidence).

F-C1: a ``identity.users.update`` holder (Editor) changed an OrganizationAdmin's
password/email, logged in as them and deactivated them.
F-C2: the Editor added ``identity.users.delete`` to its own role, deleted the
OrganizationAdmin and could grant itself every assignable permission;
``identity.roles.assign`` was never required.
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.modules.identity.infrastructure.authorization.persistence.models import (
    RolePermissionModel,
    UserRoleModel,
)
from app.modules.identity.infrastructure.persistence.models import UserModel
from tests.modules.identity.authorization.privilege_seed import (
    EDITOR_CODES,
    PASSWORD,
    add_role,
    add_user,
    headers,
    seed_organization,
)

NEW_PASSWORD = "Taken-0ver-Passw0rd!"


def _user_url(seed, key: str) -> str:
    return f"/api/v1/organizations/{seed.organization_id}/users/{seed.user_ids[key]}"


def _role_codes(db: Session, seed, role_key: str) -> set[str]:
    db.expire_all()
    ids = set(db.scalars(select(RolePermissionModel.permission_id).where(
        RolePermissionModel.role_id == seed.role_ids[role_key]
    )).all())
    return {code for code, permission_id in seed.permission_ids.items() if permission_id in ids}


# --- F-C1: target hierarchy -------------------------------------------------

def test_editor_cannot_take_over_or_disable_org_admin(client: TestClient, db_session: Session) -> None:
    seed = seed_organization(db_session)
    editor = headers(client, seed, "editor")

    for body in (
        {"password": NEW_PASSWORD},
        {"email": "taken-over@example.com"},
        {"status": "inactive"},
        {"role_id": str(seed.role_ids["member"])},
    ):
        response = client.patch(_user_url(seed, "admin"), json=body, headers=editor)
        assert response.status_code == 403, (body, response.text)

    db_session.expire_all()
    admin = db_session.get(UserModel, seed.user_ids["admin"])
    assert admin.email == seed.emails["admin"]
    assert admin.status == "active"
    assert client.post("/api/v1/auth/login", json={"email": seed.emails["admin"], "password": NEW_PASSWORD}).status_code == 401
    assert client.post("/api/v1/auth/login", json={"email": seed.emails["admin"], "password": PASSWORD}).status_code == 200


def test_delete_holder_cannot_delete_more_privileged_user(client: TestClient, db_session: Session) -> None:
    seed = seed_organization(db_session)
    add_role(db_session, seed, "deleter", (*EDITOR_CODES, "identity.users.delete"))
    add_user(db_session, seed, "deleter", role_key="deleter")
    deleter = headers(client, seed, "deleter")

    assert client.delete(_user_url(seed, "admin"), headers=deleter).status_code == 403
    db_session.expire_all()
    assert db_session.get(UserModel, seed.user_ids["admin"]).deleted_at is None
    # A user whose grants are a subset of the actor's can still be deleted.
    assert client.delete(_user_url(seed, "member"), headers=deleter).status_code == 204


def test_editor_still_manages_less_privileged_user(client: TestClient, db_session: Session) -> None:
    seed = seed_organization(db_session)
    editor = headers(client, seed, "editor")

    response = client.patch(
        _user_url(seed, "member"),
        json={"password": NEW_PASSWORD, "email": seed.emails["member"], "status": "active"},
        headers=editor,
    )
    assert response.status_code == 200, response.text


def test_org_admin_manages_peer_org_admin(client: TestClient, db_session: Session) -> None:
    seed = seed_organization(db_session)
    add_user(db_session, seed, "admin2", role_key="organization_admin")
    admin = headers(client, seed, "admin")

    response = client.patch(_user_url(seed, "admin2"), json={"status": "inactive"}, headers=admin)
    assert response.status_code == 200, response.text


# --- F-C2: no escalation and role assignment permission ---------------------

def test_editor_cannot_add_unheld_permission_to_own_role(client: TestClient, db_session: Session) -> None:
    seed = seed_organization(db_session)
    editor = headers(client, seed, "editor")
    url = f"/api/v1/organizations/{seed.organization_id}/roles/{seed.role_ids['editor']}/permissions"

    response = client.put(url, json={"permission_ids": seed.ids(*EDITOR_CODES, "identity.users.delete")}, headers=editor)
    assert response.status_code == 403, response.text
    every_assignable = [code for code in seed.permission_ids if code != "identity.roles.assign_protected"]
    assert client.put(url, json={"permission_ids": seed.ids(*every_assignable)}, headers=editor).status_code == 403
    assert _role_codes(db_session, seed, "editor") == set(EDITOR_CODES)
    # The OrganizationAdmin can still not be deleted by the editor.
    assert client.delete(_user_url(seed, "admin"), headers=editor).status_code == 403


def test_editor_cannot_grant_unheld_permission_to_any_role(client: TestClient, db_session: Session) -> None:
    seed = seed_organization(db_session)
    editor = headers(client, seed, "editor")

    member_url = f"/api/v1/organizations/{seed.organization_id}/roles/{seed.role_ids['member']}/permissions"
    response = client.put(member_url, json={"permission_ids": seed.ids("fair_crm.customers.read", "identity.users.delete")}, headers=editor)
    assert response.status_code == 403
    created = client.post(
        f"/api/v1/organizations/{seed.organization_id}/roles",
        json={"name": "Escalate", "slug": "escalate", "permission_ids": seed.ids("identity.users.delete")},
        headers=editor,
    )
    assert created.status_code == 403
    # Permissions the editor holds can still be granted.
    response = client.put(member_url, json={"permission_ids": seed.ids("fair_crm.customers.read", "identity.users.read")}, headers=editor)
    assert response.status_code == 200, response.text


def test_actor_cannot_reshape_role_holding_unheld_permissions(client: TestClient, db_session: Session) -> None:
    seed = seed_organization(db_session)
    add_role(db_session, seed, "manager", ("fair_crm.customers.read", "fair_crm.customers.update"))
    editor = headers(client, seed, "editor")

    url = f"/api/v1/organizations/{seed.organization_id}/roles/{seed.role_ids['manager']}/permissions"
    response = client.put(url, json={"permission_ids": seed.ids("fair_crm.customers.read")}, headers=editor)
    assert response.status_code == 403
    assert _role_codes(db_session, seed, "manager") == {"fair_crm.customers.read", "fair_crm.customers.update"}


def test_role_assignment_requires_roles_assign(client: TestClient, db_session: Session) -> None:
    seed = seed_organization(db_session)
    add_role(db_session, seed, "viewer", ("fair_crm.customers.read",))
    editor = headers(client, seed, "editor")

    changed = client.patch(_user_url(seed, "member"), json={"role_id": str(seed.role_ids["viewer"])}, headers=editor)
    assert changed.status_code == 403
    created = client.post(
        f"/api/v1/organizations/{seed.organization_id}/users/manual",
        json={"email": "new-user@example.com", "password": NEW_PASSWORD, "role_id": str(seed.role_ids["member"])},
        headers=editor,
    )
    assert created.status_code == 403
    # Re-sending the user's current role is not an assignment.
    unchanged = client.patch(_user_url(seed, "member"), json={"role_id": str(seed.role_ids["member"])}, headers=editor)
    assert unchanged.status_code == 200, unchanged.text


def test_assigner_cannot_assign_role_exceeding_own_grants(client: TestClient, db_session: Session) -> None:
    seed = seed_organization(db_session)
    add_role(db_session, seed, "assigner", (*EDITOR_CODES, "identity.roles.assign"))
    add_role(db_session, seed, "powerful", ("fair_crm.customers.read", "identity.users.delete"))
    add_user(db_session, seed, "assigner", role_key="assigner")
    assigner = headers(client, seed, "assigner")

    to_self = client.patch(_user_url(seed, "assigner"), json={"role_id": str(seed.role_ids["powerful"])}, headers=assigner)
    assert to_self.status_code == 403
    to_member = client.patch(_user_url(seed, "member"), json={"role_id": str(seed.role_ids["powerful"])}, headers=assigner)
    assert to_member.status_code == 403
    protected = client.patch(_user_url(seed, "member"), json={"role_id": str(seed.role_ids["organization_admin"])}, headers=assigner)
    assert protected.status_code == 403
    db_session.expire_all()
    active_roles = set(db_session.scalars(select(UserRoleModel.role_id).where(
        UserRoleModel.user_id == seed.user_ids["member"], UserRoleModel.status == "active"
    )).all())
    assert active_roles == {seed.role_ids["member"]}
    # A role within the assigner's grants can be assigned.
    allowed = client.patch(_user_url(seed, "member"), json={"role_id": str(seed.role_ids["editor"])}, headers=assigner)
    assert allowed.status_code == 200, allowed.text


def test_org_admin_keeps_full_role_management(client: TestClient, db_session: Session) -> None:
    seed = seed_organization(db_session)
    admin = headers(client, seed, "admin")

    url = f"/api/v1/organizations/{seed.organization_id}/roles/{seed.role_ids['editor']}/permissions"
    assert client.put(url, json={"permission_ids": seed.ids(*EDITOR_CODES, "identity.users.delete")}, headers=admin).status_code == 200
    assert client.patch(_user_url(seed, "member"), json={"role_id": str(seed.role_ids["organization_admin"])}, headers=admin).status_code == 200
    created = client.post(
        f"/api/v1/organizations/{seed.organization_id}/users/manual",
        json={"email": "admin-made@example.com", "password": NEW_PASSWORD, "role_id": str(seed.role_ids["editor"])},
        headers=admin,
    )
    assert created.status_code == 201, created.text
