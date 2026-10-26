"""Absolute session expiry (SECURITY_PROGRAM F-C8, ADR-0003 refresh lifetime).

Revision ID: 20261027_0077
Revises: 20261027_0076

Sessions had no end: refresh rotation could keep one alive forever, and any
validly signed access token naming an active session was accepted.
``identity_sessions.expires_at`` is the absolute end of a session; access and
refresh tokens of an expired session are rejected and rotation never extends
it.

Backfill: ``created_at + 30 days`` (ADR-0003 refresh lifetime). Sessions
older than 30 days therefore end at deploy and those users sign in again.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261027_0077"
down_revision = "20261027_0076"
branch_labels = None
depends_on = None

BACKFILL = "UPDATE identity_sessions SET expires_at = created_at + INTERVAL '30 days' WHERE expires_at IS NULL"


def upgrade() -> None:
    op.add_column("identity_sessions", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
    op.execute(BACKFILL)
    op.alter_column("identity_sessions", "expires_at", nullable=False)


def downgrade() -> None:
    op.drop_column("identity_sessions", "expires_at")
