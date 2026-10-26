"""Migration 0077: absolute session expiry column (F-C8)."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic.config import Config
from alembic.script import ScriptDirectory

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "backend" / "alembic" / "versions" / "20261027_0077_session_absolute_expiry.py"


def _module():
    spec = importlib.util.spec_from_file_location("migration_0077", MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RecordingOp:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple, dict]] = []

    def __getattr__(self, name: str):
        def record(*args, **kwargs):
            self.calls.append((name, args, kwargs))

        return record


def test_revision_follows_0076() -> None:
    script = ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini")))

    assert script.get_revision("20261027_0077").down_revision == "20261027_0076"


def test_upgrade_adds_backfills_then_requires_expiry(monkeypatch) -> None:
    module = _module()
    recorder = RecordingOp()
    monkeypatch.setattr(module, "op", recorder)

    module.upgrade()

    names = [name for name, _, _ in recorder.calls]
    assert names == ["add_column", "execute", "alter_column"]
    assert recorder.calls[0][1][0] == "identity_sessions"
    assert recorder.calls[0][1][1].name == "expires_at"
    assert recorder.calls[1][1][0] == module.BACKFILL
    assert "created_at + INTERVAL '30 days'" in module.BACKFILL
    assert recorder.calls[2][2] == {"nullable": False}


@pytest.mark.skipif(not os.environ.get("KYROX_TEST_POSTGRES_URL"), reason="needs a disposable PostgreSQL")
def test_expires_at_is_required_on_postgres() -> None:
    engine = sa.create_engine(os.environ["KYROX_TEST_POSTGRES_URL"])
    columns = {column["name"]: column for column in sa.inspect(engine).get_columns("identity_sessions")}

    assert columns["expires_at"]["nullable"] is False
