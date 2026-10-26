"""Migration 0078: identity_login_throttles table (F-004)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic.config import Config
from alembic.script import ScriptDirectory

from app.modules.identity.infrastructure.authentication.persistence.models import LoginThrottleModel

ROOT = Path(__file__).resolve().parents[2]


def test_revision_is_linear_head() -> None:
    script = ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini")))

    assert script.get_heads() == ["20261027_0078"]
    assert script.get_revision("20261027_0078").down_revision == "20261027_0077"


def test_model_matches_migration_columns() -> None:
    columns = {column.name: column for column in LoginThrottleModel.__table__.columns}

    assert set(columns) == {"key_hash", "scope", "failure_count", "window_started_at", "locked_until", "updated_at"}
    assert columns["key_hash"].primary_key
    assert columns["locked_until"].nullable is True
    assert all(not columns[name].nullable for name in ("scope", "failure_count", "window_started_at", "updated_at"))


@pytest.mark.skipif(not os.environ.get("KYROX_TEST_POSTGRES_URL"), reason="needs a disposable PostgreSQL")
def test_table_exists_on_postgres() -> None:
    engine = sa.create_engine(os.environ["KYROX_TEST_POSTGRES_URL"])
    inspector = sa.inspect(engine)

    assert "identity_login_throttles" in inspector.get_table_names()
    assert inspector.get_pk_constraint("identity_login_throttles")["constrained_columns"] == ["key_hash"]
