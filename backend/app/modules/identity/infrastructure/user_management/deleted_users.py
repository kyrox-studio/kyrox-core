"""Deleted organization users: listing and restore (OrganizationAdmin or Super Admin)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from http import HTTPStatus
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.exceptions import AppException
from app.modules.identity.application.authorization.context import AuthorizationContext
from app.modules.identity.infrastructure.authorization.persistence.models import (
    RoleModel,
    UserRoleModel,
)
from app.modules.identity.infrastructure.persistence.models import UserModel


def assert_deleted_user_admin(db: Session, context: AuthorizationContext) -> None:
    if context.is_super_admin:
        return

    organization_admin_role = db.scalar(
        select(UserRoleModel.id)
        .join(RoleModel, RoleModel.id == UserRoleModel.role_id)
        .where(
            UserRoleModel.user_id == context.user_id,
            UserRoleModel.organization_id == context.organization_id,
            UserRoleModel.status == "active",
            UserRoleModel.revoked_at.is_(None),
            RoleModel.slug == "organization_admin",
            RoleModel.deleted_at.is_(None),
        )
        .limit(1)
    )
    if organization_admin_role is None:
        raise AppException(
            "OrganizationAdmin required",
            status_code=HTTPStatus.FORBIDDEN,
        )


def latest_restorable_assignment(db: Session, organization_id: UUID, user_id: UUID) -> UserRoleModel | None:
    return db.scalars(
        select(UserRoleModel)
        .join(RoleModel, RoleModel.id == UserRoleModel.role_id)
        .where(
            UserRoleModel.user_id == user_id,
            UserRoleModel.organization_id == organization_id,
            RoleModel.deleted_at.is_(None),
            RoleModel.scope == "organization",
            RoleModel.is_assignable.is_(True),
            RoleModel.role_kind != "template",
            or_(
                RoleModel.organization_id.is_(None),
                RoleModel.organization_id == organization_id,
            ),
        )
        .order_by(UserRoleModel.assigned_at.desc())
        .limit(1)
    ).first()


def role_for_assignment(db: Session, assignment: UserRoleModel | None) -> RoleModel | None:
    if assignment is None:
        return None
    role = db.get(RoleModel, assignment.role_id)
    if role is None or role.deleted_at is not None:
        return None
    return role


def list_deleted_users(db: Session, context: AuthorizationContext, organization_id: UUID) -> list[UserModel]:
    assert_deleted_user_admin(db, context)
    return list(db.scalars(
        select(UserModel)
        .where(
            UserModel.organization_id == organization_id,
            UserModel.deleted_at.is_not(None),
        )
        .order_by(UserModel.email.asc())
    ).all())


def restore_deleted_user(
    db: Session, context: AuthorizationContext, *, organization_id: UUID, user_id: UUID
) -> tuple[UserModel, UserRoleModel]:
    assert_deleted_user_admin(db, context)

    user = db.get(UserModel, user_id)
    if user is None or user.organization_id != organization_id:
        raise AppException(
            "User not found in this organization",
            status_code=HTTPStatus.NOT_FOUND,
        )
    if user.deleted_at is None:
        raise AppException(
            "User is not deleted",
            status_code=HTTPStatus.CONFLICT,
        )
    if user.is_super_admin:
        raise AppException(
            "Super Admin cannot be restored through an organization",
            status_code=HTTPStatus.CONFLICT,
        )

    assignment = latest_restorable_assignment(db, organization_id, user_id)
    if assignment is None:
        raise AppException(
            "Deleted user has no restorable role",
            status_code=HTTPStatus.CONFLICT,
        )

    now = datetime.now(tz=UTC)
    active_assignments = db.scalars(
        select(UserRoleModel).where(
            UserRoleModel.user_id == user_id,
            UserRoleModel.status == "active",
            UserRoleModel.revoked_at.is_(None),
        )
    ).all()
    for active_assignment in active_assignments:
        if active_assignment.id == assignment.id:
            continue
        active_assignment.status = "revoked"
        active_assignment.revoked_at = now

    assignment.status = "active"
    assignment.revoked_at = None
    assignment.assigned_at = now
    assignment.assigned_by = context.user_id

    user.deleted_at = None
    user.status = "active"
    user.updated_at = now
    user.organization_id = organization_id
    db.flush()
    return user, assignment
