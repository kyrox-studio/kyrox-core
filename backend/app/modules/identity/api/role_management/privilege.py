"""Single home of the organization privilege hierarchy (SECURITY_PROGRAM F-C1, F-C2).

Rules, enforced for every actor that is not an active Super Admin:

* **Target hierarchy:** an actor may manage (update credentials, email, status,
  role, delete) another user only when every permission granted to that user is
  also granted to the actor. Peers with an equal set are allowed (ADR-0005: an
  OrganizationAdmin may manage another OrganizationAdmin); a user holding any
  permission the actor lacks is "more privileged" and is off limits. Super
  Admin targets stay Super-Admin-only.
* **No escalation:** an actor can never put a permission it does not hold on a
  role, and can never assign a role whose grants exceed its own. Editing a role
  that already holds permissions the actor lacks is refused as well, so an actor
  cannot demote or reshape a more privileged role.
* **Role assignment** requires ``identity.roles.assign``; protected roles still
  additionally require ``identity.roles.assign_protected``.

The grant set used on both sides is the same: organization-scoped permissions
held through active, non-revoked role assignments in the organization, in
``active`` or ``locked`` lifecycle (a locked grant is kept for unlock and will
authorize again, so it still counts as held). Inactive permissions have no
grants.
"""

from __future__ import annotations

from collections.abc import Iterable
from uuid import UUID

from fastapi import status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import AppException
from app.modules.identity.api.authorization.context import AuthorizationContext
from app.modules.identity.infrastructure.authorization.persistence.models import (
    PermissionModel,
    RoleModel,
    RolePermissionModel,
    UserRoleModel,
)
from app.modules.identity.infrastructure.persistence.models import UserModel

ROLE_ASSIGN_PERMISSION = "identity.roles.assign"
PROTECTED_ROLE_ASSIGN_PERMISSION = "identity.roles.assign_protected"
_HELD_LIFECYCLE_STATES = ("active", "locked")


def _forbidden(message: str) -> AppException:
    return AppException(message, status_code=status.HTTP_403_FORBIDDEN)


def user_grant_ids(db: Session, user_id: UUID, organization_id: UUID) -> frozenset[UUID]:
    """Permission ids a user holds in an organization (see module docstring)."""
    stmt = (
        select(PermissionModel.id)
        .join(RolePermissionModel, RolePermissionModel.permission_id == PermissionModel.id)
        .join(RoleModel, RoleModel.id == RolePermissionModel.role_id)
        .join(UserRoleModel, UserRoleModel.role_id == RoleModel.id)
        .where(
            UserRoleModel.user_id == user_id,
            UserRoleModel.organization_id == organization_id,
            UserRoleModel.status == "active",
            UserRoleModel.revoked_at.is_(None),
            RoleModel.deleted_at.is_(None),
            PermissionModel.permission_scope == "organization",
            PermissionModel.lifecycle_state.in_(_HELD_LIFECYCLE_STATES),
        )
    )
    return frozenset(db.scalars(stmt).all())


def role_grant_ids(db: Session, role_id: UUID) -> frozenset[UUID]:
    stmt = (
        select(PermissionModel.id)
        .join(RolePermissionModel, RolePermissionModel.permission_id == PermissionModel.id)
        .where(
            RolePermissionModel.role_id == role_id,
            PermissionModel.permission_scope == "organization",
            PermissionModel.lifecycle_state.in_(_HELD_LIFECYCLE_STATES),
        )
    )
    return frozenset(db.scalars(stmt).all())


def _actor_grant_ids(db: Session, context: AuthorizationContext) -> frozenset[UUID]:
    return user_grant_ids(db, context.user_id, context.organization_id)


def _actor_holds_code(db: Session, context: AuthorizationContext, code: str) -> bool:
    stmt = (
        select(PermissionModel.id)
        .join(RolePermissionModel, RolePermissionModel.permission_id == PermissionModel.id)
        .join(RoleModel, RoleModel.id == RolePermissionModel.role_id)
        .join(UserRoleModel, UserRoleModel.role_id == RoleModel.id)
        .where(
            UserRoleModel.user_id == context.user_id,
            UserRoleModel.organization_id == context.organization_id,
            UserRoleModel.status == "active",
            UserRoleModel.revoked_at.is_(None),
            RoleModel.deleted_at.is_(None),
            PermissionModel.code == code,
            PermissionModel.lifecycle_state == "active",
            PermissionModel.permission_scope == "organization",
        )
    )
    return db.scalars(stmt).first() is not None


def assert_can_manage_user(db: Session, context: AuthorizationContext, target: UserModel) -> None:
    """Target hierarchy: the target's grants must be a subset of the actor's."""
    if context.is_super_admin:
        return
    if target.is_super_admin:
        raise _forbidden("Only a Super Admin can modify a Super Admin")
    if target.id == context.user_id:
        return
    target_grants = user_grant_ids(db, target.id, context.organization_id)
    if not target_grants <= _actor_grant_ids(db, context):
        raise _forbidden("Cannot manage a user who holds permissions you do not have")


def assert_can_grant_permissions(
    db: Session,
    context: AuthorizationContext,
    permission_ids: Iterable[UUID],
) -> None:
    """No escalation: every granted permission must already be held by the actor."""
    if context.is_super_admin:
        return
    requested = frozenset(permission_ids)
    if requested and not requested <= _actor_grant_ids(db, context):
        raise _forbidden("Cannot grant a permission you do not have")


def assert_can_edit_role_permissions(
    db: Session,
    context: AuthorizationContext,
    role: RoleModel,
) -> None:
    """A role holding permissions the actor lacks cannot be reshaped by that actor."""
    if context.is_super_admin:
        return
    if not role_grant_ids(db, role.id) <= _actor_grant_ids(db, context):
        raise _forbidden("Cannot change a role that holds permissions you do not have")


def assert_can_assign_role(db: Session, context: AuthorizationContext, role: RoleModel) -> None:
    """Role assignment permission, protected-role ceiling and no escalation."""
    if context.is_super_admin:
        return
    if not _actor_holds_code(db, context, ROLE_ASSIGN_PERMISSION):
        raise _forbidden("Role assignment is not allowed")
    if role.is_protected and not _actor_holds_code(db, context, PROTECTED_ROLE_ASSIGN_PERMISSION):
        raise _forbidden("Protected role assignment is not allowed")
    if not role_grant_ids(db, role.id) <= _actor_grant_ids(db, context):
        raise _forbidden("Cannot assign a role that holds permissions you do not have")
