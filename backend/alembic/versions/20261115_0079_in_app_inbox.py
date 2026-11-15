"""Track the read state of an in-app delivery."""

import sqlalchemy as sa
from alembic import op

revision = "20261115_0079"
down_revision = "20261027_0078"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("platform_notifications", sa.Column("read_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index(
        "ix_platform_notifications_inbox", "platform_notifications",
        ["recipient", "channel", "status", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_platform_notifications_inbox", table_name="platform_notifications")
    op.drop_column("platform_notifications", "read_at")
