"""Migration 0076: user-management roles receive ``identity.roles.assign`` (F-C2)."""

from __future__ import annotations

import importlib.util
import os
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic.config import Config
from alembic.script import ScriptDirectory

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "backend" / "alembic" / "versions" / "20261027_0076_role_assign_permission_grants.py"


def _module():
    spec = importlib.util.spec_from_file_location("migration_0076", MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_revision_follows_0075() -> None:
    script = ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini")))

    assert script.get_revision("20261027_0076").down_revision == "20261026_0075"


def test_upgrade_only_inserts_assign_grants() -> None:
    sql = " ".join(_module().GRANT_ROLE_ASSIGN.split())

    assert sql.startswith("INSERT INTO identity_role_permissions")
    assert "assign_permission.code = 'identity.roles.assign'" in sql
    assert "held_permission.code IN ('identity.users.create', 'identity.users.update')" in sql
    assert "r.slug = 'organization_admin'" in sql
    assert "r.deleted_at IS NULL" in sql
    assert "assign_permission.lifecycle_state = 'active'" in sql
    assert "NOT EXISTS" in sql
    assert "DELETE" not in sql and "UPDATE" not in sql


@pytest.mark.skipif(not os.environ.get("KYROX_TEST_POSTGRES_URL"), reason="needs a disposable PostgreSQL")
def test_grants_on_postgres() -> None:
    engine = sa.create_engine(os.environ["KYROX_TEST_POSTGRES_URL"])
    sql = sa.text(_module().GRANT_ROLE_ASSIGN)
    with engine.connect() as connection:
        outer = connection.begin()
        try:
            tag = uuid.uuid4().hex[:8]
            org_id, editor_id, viewer_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
            connection.execute(sa.text(
                "INSERT INTO identity_organizations (id, name, slug, status, created_at, updated_at) "
                "VALUES (:id, :name, :slug, 'active', now(), now())"
            ), {"id": org_id, "name": f"M76 {tag}", "slug": f"m76-{tag}"})
            for role_id, slug in ((editor_id, "editor"), (viewer_id, "viewer")):
                connection.execute(sa.text(
                    "INSERT INTO identity_roles (id, name, slug, scope, is_system, role_kind, organization_id, "
                    "template_version, permissions_customized, is_assignable, is_protected, "
                    "auto_include_new_permissions, created_at, updated_at) VALUES (:id, :name, :slug, "
                    "'organization', FALSE, 'organization', :org, 1, TRUE, TRUE, FALSE, FALSE, now(), now())"
                ), {"id": role_id, "name": f"{slug} {tag}", "slug": f"m76_{slug}_{tag}", "org": org_id})
            connection.execute(sa.text(
                "INSERT INTO identity_role_permissions (role_id, permission_id) "
                "SELECT :role, id FROM identity_permissions WHERE code = 'identity.users.update'"
            ), {"role": editor_id})

            def has_assign(role_id: uuid.UUID) -> bool:
                return bool(connection.execute(sa.text(
                    "SELECT count(*) FROM identity_role_permissions rp JOIN identity_permissions p "
                    "ON p.id = rp.permission_id WHERE rp.role_id = :role AND p.code = 'identity.roles.assign'"
                ), {"role": role_id}).scalar_one())

            connection.execute(sql)
            assert has_assign(editor_id) is True
            assert has_assign(viewer_id) is False
            admin_has_assign = connection.execute(sa.text(
                "SELECT count(*) FROM identity_role_permissions rp JOIN identity_permissions p ON p.id = rp.permission_id "
                "JOIN identity_roles r ON r.id = rp.role_id WHERE r.slug = 'organization_admin' "
                "AND p.code = 'identity.roles.assign'"
            )).scalar_one()
            assert admin_has_assign == 1
            # Idempotent: a second run inserts nothing.
            assert connection.execute(sql).rowcount == 0
        finally:
            outer.rollback()
