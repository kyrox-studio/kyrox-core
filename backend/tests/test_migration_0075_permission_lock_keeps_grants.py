"""Migration 0075: locking a permission keeps role grants (ADR-0005 §6, F-C12).

The lifecycle triggers are PostgreSQL-only. The SQL-shape tests run everywhere;
``test_lock_keeps_grants_on_postgres`` runs the real role-management routes and
permission checker against the real triggers when ``KYROX_TEST_POSTGRES_URL``
points to a disposable database migrated to head.
"""

from __future__ import annotations

import importlib.util
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "backend" / "alembic" / "versions" / "20261026_0075_permission_lock_keeps_grants.py"


def _module():
    spec = importlib.util.spec_from_file_location("migration_0075", MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_revision_chain_is_linear_head() -> None:
    script = ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini")))

    assert script.get_heads() == ["20261026_0075"]
    assert script.get_revision("20261026_0075").down_revision == "20261026_0074"


class RecordingBind:
    def __init__(self, dialect: str) -> None:
        self.dialect = type("D", (), {"name": dialect})()
        self.sql: list[str] = []

    def execute(self, statement, *args, **kwargs) -> None:
        self.sql.append(" ".join(str(statement).split()))


def _run(monkeypatch, direction: str, dialect: str) -> list[str]:
    module = _module()
    bind = RecordingBind(dialect)
    monkeypatch.setattr(module.op, "get_bind", lambda: bind)
    getattr(module, direction)()
    return bind.sql


def test_upgrade_deletes_grants_only_for_inactive_or_system_scope(monkeypatch) -> None:
    sql = " ".join(_run(monkeypatch, "upgrade", "postgresql"))

    assert "ELSIF NEW.lifecycle_state='inactive' OR NEW.permission_scope<>'organization' THEN DELETE" in sql
    assert "ELSE DELETE" not in sql
    assert "'Locked permission cannot be newly assigned'" in sql
    # Only function bodies are replaced; no existing grant row is touched.
    assert "INSERT INTO identity_role_permissions (role_id, permission_id) SELECT id, NEW.id" in sql
    assert not any(s.startswith(("DELETE", "UPDATE", "INSERT")) for s in _run(monkeypatch, "upgrade", "postgresql"))


def test_downgrade_restores_0055_functions(monkeypatch) -> None:
    sql = " ".join(_run(monkeypatch, "downgrade", "postgresql"))

    assert "ELSE DELETE FROM identity_role_permissions WHERE permission_id=NEW.id" in sql
    assert "lifecycle_state='active' AND permission_scope='organization'" in sql
    assert "Locked permission" not in sql


def test_non_postgres_is_a_no_op(monkeypatch) -> None:
    assert _run(monkeypatch, "upgrade", "sqlite") == []
    assert _run(monkeypatch, "downgrade", "sqlite") == []


def _grant_count(db: Session, permission_id: uuid.UUID, role_ids: list[uuid.UUID]) -> int:
    from app.modules.identity.infrastructure.authorization.persistence.models import RolePermissionModel

    return db.scalar(
        sa.select(sa.func.count()).select_from(RolePermissionModel).where(
            RolePermissionModel.permission_id == permission_id,
            RolePermissionModel.role_id.in_(role_ids),
        )
    )


def _insert_rejected(db: Session, role_id: uuid.UUID, permission_id: uuid.UUID) -> bool:
    nested = db.connection().begin_nested()
    try:
        db.connection().execute(
            sa.text("INSERT INTO identity_role_permissions (role_id, permission_id) VALUES (:r, :p)"),
            {"r": role_id, "p": permission_id},
        )
    except DBAPIError:
        nested.rollback()
        return True
    nested.rollback()
    return False


@pytest.mark.skipif(not os.environ.get("KYROX_TEST_POSTGRES_URL"), reason="needs a disposable PostgreSQL")
def test_lock_keeps_grants_on_postgres() -> None:
    from app.core.exceptions import AppException
    from app.modules.identity.api.authorization.context import AuthorizationContext
    from app.modules.identity.api.role_management import routes
    from app.modules.identity.api.role_management.schemas import (
        DeriveRoleRequest,
        PermissionLifecycleRequest,
        RoleCreateRequest,
        RolePermissionsRequest,
        TemplateSyncRequest,
    )
    from app.modules.identity.domain.authorization.value_objects.identity.organization_id import OrganizationId
    from app.modules.identity.domain.authorization.value_objects.identity.user_id import UserId
    from app.modules.identity.domain.authorization.value_objects.rbac.permission_code import PermissionCode
    from app.modules.identity.infrastructure.authorization.persistence.models import (
        PermissionGroupModel,
        PermissionModel,
        RoleModel,
        RolePermissionModel,
        UserRoleModel,
    )
    from app.modules.identity.infrastructure.authorization.services.sqlalchemy_permission_checker import (
        SqlAlchemyPermissionChecker,
    )
    from app.modules.identity.infrastructure.organization.persistence.models import OrganizationModel
    from app.modules.identity.infrastructure.persistence.models import UserModel

    engine = sa.create_engine(os.environ["KYROX_TEST_POSTGRES_URL"])
    connection = engine.connect()
    outer = connection.begin()
    db = Session(bind=connection, join_transaction_mode="create_savepoint")
    try:
        tag = uuid.uuid4().hex[:8]
        actor_id, member_id, org_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        group_id, permission_id, template_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        other_template_id = uuid.uuid4()
        code = f"fc{tag}.grants.read"
        db.add(OrganizationModel(id=org_id, name=f"FC12 {tag}", slug=f"fc12-{tag}", status="active"))
        db.flush()
        db.add_all([
            UserModel(id=actor_id, email=f"fc12-admin-{tag}@example.com", password_hash="x", status="active", is_super_admin=True),
            UserModel(id=member_id, organization_id=org_id, email=f"fc12-member-{tag}@example.com", password_hash="x", status="active", is_super_admin=False),
            PermissionGroupModel(id=group_id, code=f"fc{tag}.grants", name="FC12", module="identity", description="FC12", sort_order=1, is_system=False),
        ])
        db.flush()
        db.add(PermissionModel(id=permission_id, group_id=group_id, code=code, description="FC12 read", is_system=False, lifecycle_state="active", is_assignable=True))
        for role_id, slug in ((template_id, "tpl"), (other_template_id, "tpl2")):
            db.add(RoleModel(
                id=role_id, name=f"FC12 {slug} {tag}", slug=f"fc12_{slug}_{tag}", scope="organization", is_system=False,
                role_kind="template", organization_id=None, template_version=1, permissions_customized=False,
                is_assignable=False, is_protected=False, auto_include_new_permissions=False,
            ))
        db.flush()
        db.add(RolePermissionModel(role_id=template_id, permission_id=permission_id))
        db.flush()

        claims = SimpleNamespace(sub=SimpleNamespace(value=actor_id), sid=SimpleNamespace(value=uuid.uuid4()))
        admin = AuthorizationContext(user_id=actor_id, organization_id=org_id, email="a@example.com", is_super_admin=True)

        # 6 roles hold the grant: template + 3 derived + 2 custom organization roles.
        derived_ids = [
            routes.derive_template(template_id, DeriveRoleRequest(organization_id=org_id, name=f"D{i}", slug=f"fc12_d{i}_{tag}"), claims, db).id
            for i in range(3)
        ]
        custom_ids = [
            routes.create_organization_role(org_id, RoleCreateRequest(name=f"C{i}", slug=f"fc12_c{i}_{tag}", permission_ids=[permission_id]), admin, db).id
            for i in range(2)
        ]
        role_ids = [template_id, *derived_ids, *custom_ids]
        db.add(UserRoleModel(user_id=member_id, organization_id=org_id, role_id=custom_ids[0], status="active", assigned_at=datetime.now(tz=UTC)))
        db.flush()

        checker = SqlAlchemyPermissionChecker(db)
        has_access = lambda: checker.has_permission(UserId(member_id), OrganizationId(org_id), PermissionCode(code))  # noqa: E731
        assert _grant_count(db, permission_id, role_ids) == 6
        assert has_access() is True

        # Lock: runtime access stops, every grant row stays.
        routes.update_permission_lifecycle(permission_id, PermissionLifecycleRequest(state="locked", reason="FC12 lock"), claims, db)
        db.flush()
        assert _grant_count(db, permission_id, role_ids) == 6
        assert has_access() is False

        # Saving roles / syncing the template keeps existing locked grants.
        routes.update_template(template_id, RolePermissionsRequest(permission_ids=[]), claims, db)
        routes.update_organization_role_permissions(org_id, custom_ids[1], RolePermissionsRequest(permission_ids=[]), admin, db)
        routes.sync_template(template_id, TemplateSyncRequest(organization_id=org_id), claims, db)
        db.flush()
        assert _grant_count(db, permission_id, role_ids) == 6

        # A locked permission cannot be newly assigned: app layer and DB agree.
        rejected = db.begin_nested()
        with pytest.raises(AppException, match="Locked or inactive permissions cannot be assigned"):
            routes.create_organization_role(org_id, RoleCreateRequest(name="New", slug=f"fc12_new_{tag}", permission_ids=[permission_id]), admin, db)
        rejected.rollback()
        fresh_custom = routes.create_organization_role(org_id, RoleCreateRequest(name="Fresh", slug=f"fc12_fresh_{tag}"), admin, db).id
        fresh_other = routes.derive_template(other_template_id, DeriveRoleRequest(organization_id=org_id, name="O", slug=f"fc12_o_{tag}"), claims, db).id
        db.flush()
        assert _insert_rejected(db, fresh_custom, permission_id)
        assert _insert_rejected(db, fresh_other, permission_id)
        assert _insert_rejected(db, other_template_id, permission_id)
        # Template propagation of a grant the template still holds stays allowed.
        late_derived = routes.derive_template(template_id, DeriveRoleRequest(organization_id=org_id, name="L", slug=f"fc12_l_{tag}"), claims, db).id
        db.flush()
        assert _grant_count(db, permission_id, [late_derived]) == 1

        # Unlock: access returns without re-assignment.
        routes.update_permission_lifecycle(permission_id, PermissionLifecycleRequest(state="active", reason="FC12 unlock"), claims, db)
        db.flush()
        assert _grant_count(db, permission_id, role_ids) == 6
        assert has_access() is True

        # Inactive: every grant is removed and re-activation does not restore them.
        routes.update_permission_lifecycle(permission_id, PermissionLifecycleRequest(state="inactive", reason="FC12 off"), claims, db)
        db.flush()
        assert _grant_count(db, permission_id, [*role_ids, late_derived]) == 0
        assert _insert_rejected(db, fresh_custom, permission_id)
        db.execute(sa.text("UPDATE identity_permissions SET lifecycle_state='active' WHERE id=:p"), {"p": permission_id})
        assert _grant_count(db, permission_id, [*role_ids, late_derived]) == 0
        assert has_access() is False
    finally:
        db.close()
        outer.rollback()
        connection.close()
        engine.dispose()
