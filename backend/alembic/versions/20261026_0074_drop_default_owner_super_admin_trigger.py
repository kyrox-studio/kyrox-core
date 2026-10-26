"""Drop the email-based default owner Super Admin trigger.

Revision ID: 20261026_0074
Revises: 20261012_0073

Migration 20260814_0041 promoted any row INSERTed with email
``dev@example.com`` to Platform Super Admin. The Fair CRM bootstrap seed now
creates that user itself (create-only, ``is_super_admin = TRUE`` on insert),
so the trigger only remained as an implicit "this email becomes Super Admin"
path (SECURITY_PROGRAM R-1). Existing users and their ``is_super_admin`` flags
are left exactly as they are; only future inserts stop being promoted.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20261026_0074"
down_revision = "20261012_0073"
branch_labels = None
depends_on = None

DEFAULT_OWNER_EMAIL = "dev@example.com"
TRIGGER_NAME = "trg_identity_users_default_owner_super_admin"
FUNCTION_NAME = "identity_default_owner_super_admin_on_insert"


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    bind.execute(sa.text(f"DROP TRIGGER IF EXISTS {TRIGGER_NAME} ON identity_users"))
    bind.execute(sa.text(f"DROP FUNCTION IF EXISTS {FUNCTION_NAME}()"))


def downgrade() -> None:
    # Restores the 0041 trigger only; no existing row is changed.
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    bind.execute(
        sa.text(
            f"""
            CREATE OR REPLACE FUNCTION {FUNCTION_NAME}()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                IF NEW.email = '{DEFAULT_OWNER_EMAIL}' THEN
                    NEW.is_super_admin := TRUE;
                END IF;
                RETURN NEW;
            END;
            $$
            """
        )
    )
    bind.execute(
        sa.text(
            f"""
            DROP TRIGGER IF EXISTS {TRIGGER_NAME} ON identity_users;
            CREATE TRIGGER {TRIGGER_NAME}
            BEFORE INSERT ON identity_users
            FOR EACH ROW
            EXECUTE FUNCTION {FUNCTION_NAME}()
            """
        )
    )
