"""Migration 0074 removes the email-based Super Admin trigger (SECURITY_PROGRAM R-1).

The trigger is PostgreSQL-only. These tests pin the revision chain and the
upgrade/downgrade SQL; the PostgreSQL behaviour is covered by
``test_drop_trigger_on_postgres`` when ``KYROX_TEST_POSTGRES_URL`` points to a
disposable database.
"""

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
MIGRATION = ROOT / "backend" / "alembic" / "versions" / "20261026_0074_drop_default_owner_super_admin_trigger.py"
TRIGGER = "trg_identity_users_default_owner_super_admin"
FUNCTION = "identity_default_owner_super_admin_on_insert"


def _module():
    spec = importlib.util.spec_from_file_location("migration_0074", MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_revision_chain_is_linear() -> None:
    script = ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini")))

    assert len(script.get_heads()) == 1
    assert script.get_revision("20261026_0074").down_revision == "20261012_0073"
    assert "20261026_0074" in {rev.revision for rev in script.walk_revisions()}


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


def test_upgrade_drops_trigger_and_function_only(monkeypatch) -> None:
    sql = _run(monkeypatch, "upgrade", "postgresql")

    assert sql == [
        f"DROP TRIGGER IF EXISTS {TRIGGER} ON identity_users",
        f"DROP FUNCTION IF EXISTS {FUNCTION}()",
    ]
    assert not any(s.startswith("UPDATE") for s in sql)


def test_downgrade_restores_trigger_without_touching_rows(monkeypatch) -> None:
    sql = _run(monkeypatch, "downgrade", "postgresql")

    assert any(f"CREATE TRIGGER {TRIGGER}" in s for s in sql)
    assert not any("UPDATE identity_users" in s for s in sql)


def test_non_postgres_is_a_no_op(monkeypatch) -> None:
    assert _run(monkeypatch, "upgrade", "sqlite") == []
    assert _run(monkeypatch, "downgrade", "sqlite") == []


@pytest.mark.skipif(not os.environ.get("KYROX_TEST_POSTGRES_URL"), reason="needs a disposable PostgreSQL")
def test_drop_trigger_on_postgres() -> None:
    engine = sa.create_engine(os.environ["KYROX_TEST_POSTGRES_URL"])
    with engine.connect() as conn:
        assert conn.execute(sa.text("SELECT count(*) FROM pg_trigger WHERE tgname = :n"), {"n": TRIGGER}).scalar() == 0
        assert conn.execute(sa.text("SELECT count(*) FROM pg_proc WHERE proname = :n"), {"n": FUNCTION}).scalar() == 0
        exists = conn.execute(
            sa.text("SELECT count(*) FROM identity_users WHERE email = 'dev@example.com'")
        ).scalar()
        conn.rollback()
        if exists:
            return  # existing rows are intentionally untouched by 0074
        tx = conn.begin()
        try:
            conn.execute(
                sa.text(
                    "INSERT INTO identity_users (id, email, password_hash, status, is_super_admin, created_at, updated_at) "
                    "VALUES (:id, 'dev@example.com', 'x', 'active', FALSE, NOW(), NOW())"
                ),
                {"id": str(uuid.uuid4())},
            )
            promoted = conn.execute(
                sa.text("SELECT is_super_admin FROM identity_users WHERE email = 'dev@example.com'")
            ).scalar()
            assert promoted is False
        finally:
            tx.rollback()
