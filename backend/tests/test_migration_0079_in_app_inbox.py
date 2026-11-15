from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

from app.modules.notifications.infrastructure.persistence.models import PlatformNotificationModel


def test_in_app_inbox_migration_is_linear_and_preserves_unread_default():
    root = Path(__file__).resolve().parents[2]
    script = ScriptDirectory.from_config(Config(str(root / "alembic.ini")))
    assert script.get_heads() == ["20261115_0079"]
    assert script.get_revision("20261115_0079").down_revision == "20261027_0078"
    column = PlatformNotificationModel.__table__.c.read_at
    assert column.nullable and column.server_default is None
