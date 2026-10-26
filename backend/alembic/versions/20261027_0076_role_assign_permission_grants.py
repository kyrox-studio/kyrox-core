"""Keep user-management roles able to assign roles (SECURITY_PROGRAM F-C2).

Revision ID: 20261027_0076
Revises: 20261026_0075

Role assignment now requires ``identity.roles.assign`` (catalog code since
20260814_0046, never enforced before). Until now any holder of
``identity.users.create`` / ``identity.users.update`` could assign roles, so
every non-deleted role (templates included) that holds one of those two codes
receives ``identity.roles.assign`` here; ``organization_admin`` is ensured too.
Existing users keep creating/editing users with a role. Escalation is closed
by the application rules, not by withholding this grant: an actor can only
assign roles whose grants it already holds, and only to users whose grants it
already holds (``role_management/privilege.py``).

Only rows are inserted; nothing is updated or deleted. Downgrade is a no-op:
the inserted grants cannot be told apart from deliberate ones.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261027_0076"
down_revision = "20261026_0075"
branch_labels = None
depends_on = None

GRANT_ROLE_ASSIGN = """
INSERT INTO identity_role_permissions (role_id, permission_id)
SELECT DISTINCT r.id, assign_permission.id
FROM identity_roles r
JOIN identity_permissions assign_permission
  ON assign_permission.code = 'identity.roles.assign'
 AND assign_permission.lifecycle_state = 'active'
WHERE r.deleted_at IS NULL
  AND (
    r.slug = 'organization_admin'
    OR EXISTS (
      SELECT 1
      FROM identity_role_permissions held
      JOIN identity_permissions held_permission ON held_permission.id = held.permission_id
      WHERE held.role_id = r.id
        AND held_permission.code IN ('identity.users.create', 'identity.users.update')
    )
  )
  AND NOT EXISTS (
    SELECT 1 FROM identity_role_permissions existing
    WHERE existing.role_id = r.id AND existing.permission_id = assign_permission.id
  )
"""


def upgrade() -> None:
    op.get_bind().execute(sa.text(GRANT_ROLE_ASSIGN))


def downgrade() -> None:
    """No-op: grants added by upgrade are indistinguishable from deliberate ones."""
