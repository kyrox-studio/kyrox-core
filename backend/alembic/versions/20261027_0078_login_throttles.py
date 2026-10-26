"""Database-backed sign-in throttle (SECURITY_PROGRAM F-004, login only).

Revision ID: 20261027_0078
Revises: 20261027_0077

Core runs several workers, so failed sign-in counters live in a shared table
(``SqlAlchemyLoginAttemptLimiter``). Keys are SHA-256 hashes of the counter
scope and value; no email address or IP is stored. Rows older than one day are
pruned on the next failure. New empty table; no existing data is touched.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261027_0078"
down_revision = "20261027_0077"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "identity_login_throttles",
        sa.Column("key_hash", sa.String(64), primary_key=True),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_identity_login_throttles_updated_at", "identity_login_throttles", ["updated_at"])


def downgrade() -> None:
    op.drop_index("ix_identity_login_throttles_updated_at", table_name="identity_login_throttles")
    op.drop_table("identity_login_throttles")
