"""Keep role grants when a permission is locked (ADR-0005 §6, SECURITY_PROGRAM F-C12).

Revision ID: 20261026_0075
Revises: 20261026_0074

ADR-0005 §6 (2026-09-22): locking a permission only suspends runtime
authorization; ``identity_role_permissions`` rows stay so unlocking restores
access without re-assignment. Deactivating (``inactive``) removes every grant
and re-activation does not bring them back. The application layer already
behaves this way, but the PostgreSQL triggers from 20260816_0055 deleted grants
on every non-active state and refused any locked row.

New trigger behaviour:

* ``identity_apply_permission_lifecycle``: deletes grants only when the
  permission becomes ``inactive`` or leaves the organization scope; ``locked``
  keeps them. Activation still auto-grants ``auto_include_new_permissions``
  roles.
* ``identity_enforce_permission_lifecycle``: inactive and system permissions
  are never assignable. A locked permission is not newly assignable, except
  (a) an UPDATE that keeps the same (role, permission) pair, i.e. an existing
  grant, and (b) a derived role receiving a grant its source template still
  holds (template derive/sync propagation, ``_permissions_for_propagation``).

No existing row is changed: grants deleted by the old trigger are not restored.
Downgrade reinstalls the 0055 functions verbatim.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261026_0075"
down_revision = "20261026_0074"
branch_labels = None
depends_on = None


ENFORCE_FUNCTION = """
CREATE OR REPLACE FUNCTION identity_enforce_permission_lifecycle()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    permission_state text;
BEGIN
    SELECT lifecycle_state INTO permission_state
    FROM identity_permissions
    WHERE id=NEW.permission_id AND permission_scope='organization';

    IF permission_state IS NULL OR permission_state NOT IN ('active', 'locked') THEN
        RAISE EXCEPTION 'Permission is not an active organization permission and cannot be assigned';
    END IF;

    IF permission_state='locked' THEN
        IF TG_OP='UPDATE'
           AND NEW.role_id=OLD.role_id
           AND NEW.permission_id=OLD.permission_id THEN
            RETURN NEW;
        END IF;
        IF EXISTS (
            SELECT 1
            FROM identity_roles derived
            JOIN identity_role_permissions template_grant
              ON template_grant.role_id=derived.source_template_role_id
             AND template_grant.permission_id=NEW.permission_id
            WHERE derived.id=NEW.role_id
        ) THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'Locked permission cannot be newly assigned';
    END IF;

    RETURN NEW;
END; $$;
"""

APPLY_FUNCTION = """
CREATE OR REPLACE FUNCTION identity_apply_permission_lifecycle()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.lifecycle_state='active' AND NEW.permission_scope='organization' THEN
        INSERT INTO identity_role_permissions (role_id, permission_id)
        SELECT id, NEW.id FROM identity_roles
        WHERE auto_include_new_permissions=TRUE AND deleted_at IS NULL
        ON CONFLICT DO NOTHING;
    ELSIF NEW.lifecycle_state='inactive' OR NEW.permission_scope<>'organization' THEN
        DELETE FROM identity_role_permissions WHERE permission_id=NEW.id;
    END IF;
    -- 'locked': grants are kept; the permission checker requires 'active'.
    RETURN NEW;
END; $$;
"""

# 20260816_0055 definitions, restored on downgrade.
LEGACY_ENFORCE_FUNCTION = """
CREATE OR REPLACE FUNCTION identity_enforce_permission_lifecycle()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM identity_permissions
        WHERE id=NEW.permission_id
          AND lifecycle_state='active'
          AND permission_scope='organization'
    ) THEN
        RAISE EXCEPTION 'Permission is not an active organization permission and cannot be assigned';
    END IF;
    RETURN NEW;
END; $$;
"""

LEGACY_APPLY_FUNCTION = """
CREATE OR REPLACE FUNCTION identity_apply_permission_lifecycle()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.lifecycle_state='active' AND NEW.permission_scope='organization' THEN
        INSERT INTO identity_role_permissions (role_id, permission_id)
        SELECT id, NEW.id FROM identity_roles
        WHERE auto_include_new_permissions=TRUE AND deleted_at IS NULL
        ON CONFLICT DO NOTHING;
    ELSE
        DELETE FROM identity_role_permissions WHERE permission_id=NEW.id;
    END IF;
    RETURN NEW;
END; $$;
"""


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    bind.execute(sa.text(ENFORCE_FUNCTION))
    bind.execute(sa.text(APPLY_FUNCTION))


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    bind.execute(sa.text(LEGACY_ENFORCE_FUNCTION))
    bind.execute(sa.text(LEGACY_APPLY_FUNCTION))
