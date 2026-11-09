from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.exceptions import AppException
from app.db.session import get_db
from app.modules.identity.api.authorization.context import AuthorizationContext
from app.modules.identity.api.authorization.guards import require_permission
from app.modules.identity.api.authorization.scope import assert_organization_scope
from app.modules.identity.api.user_management.schemas import (
    AssignableRoleResponse,
    ErrorResponse,
    ManagedUserListResponse,
    ManagedUserResponse,
)
from app.modules.identity.infrastructure.authorization.persistence.models import (
    RoleModel,
    UserRoleModel,
)
from app.modules.identity.infrastructure.persistence.models import UserModel

router = APIRouter(tags=["user-management"])


def _now():
    from datetime import UTC, datetime

    return datetime.now(tz=UTC)


def _assert_deleted_user_admin(
    db: Session,
    context: AuthorizationContext,
) -> None:
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
            status_code=status.HTTP_403_FORBIDDEN,
        )


def _latest_restorable_assignment(
    db: Session,
    organization_id: UUID,
    user_id: UUID,
) -> UserRoleModel | None:
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


def _role_response_for_assignment(
    db: Session,
    assignment: UserRoleModel | None,
) -> AssignableRoleResponse | None:
    if assignment is None:
        return None
    role = db.get(RoleModel, assignment.role_id)
    if role is None or role.deleted_at is not None:
        return None
    return AssignableRoleResponse(id=role.id, name=role.name, slug=role.slug)


def _deleted_user_response(
    db: Session,
    organization_id: UUID,
    user: UserModel,
    *,
    expose_super_admin: bool,
) -> ManagedUserResponse:
    assignment = _latest_restorable_assignment(db, organization_id, user.id)
    return ManagedUserResponse(
        id=user.id,
        email=user.email,
        status=user.status,
        organization_id=organization_id,
        role=_role_response_for_assignment(db, assignment),
        created_at=user.created_at,
        updated_at=user.updated_at,
        is_super_admin=user.is_super_admin if expose_super_admin else None,
    )


@router.get(
    "/organizations/{organization_id}/users/deleted",
    response_model=ManagedUserListResponse,
    responses={
        400: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
    },
)
def list_deleted_users(
    organization_id: UUID,
    context: AuthorizationContext = Depends(require_permission("identity.users.read")),
    db: Session = Depends(get_db, scope="function"),
) -> ManagedUserListResponse:
    assert_organization_scope(organization_id, context)
    _assert_deleted_user_admin(db, context)

    users = db.scalars(
        select(UserModel)
        .where(
            UserModel.organization_id == organization_id,
            UserModel.deleted_at.is_not(None),
        )
        .order_by(UserModel.email.asc())
    ).all()
    return ManagedUserListResponse(
        items=[
            _deleted_user_response(
                db,
                organization_id,
                user,
                expose_super_admin=context.is_super_admin,
            )
            for user in users
        ],
        can_manage_super_admin=context.is_super_admin,
    )


@router.post(
    "/organizations/{organization_id}/users/{user_id}/restore",
    response_model=ManagedUserResponse,
    responses={
        400: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
    },
)
def restore_deleted_user(
    organization_id: UUID,
    user_id: UUID,
    context: AuthorizationContext = Depends(require_permission("identity.users.update")),
    db: Session = Depends(get_db, scope="function"),
) -> ManagedUserResponse:
    assert_organization_scope(organization_id, context)
    _assert_deleted_user_admin(db, context)

    user = db.get(UserModel, user_id)
    if user is None or user.organization_id != organization_id:
        raise AppException(
            "User not found in this organization",
            status_code=status.HTTP_404_NOT_FOUND,
        )
    if user.deleted_at is None:
        raise AppException(
            "User is not deleted",
            status_code=status.HTTP_409_CONFLICT,
        )
    if user.is_super_admin:
        raise AppException(
            "Super Admin cannot be restored through an organization",
            status_code=status.HTTP_409_CONFLICT,
        )

    assignment = _latest_restorable_assignment(db, organization_id, user_id)
    if assignment is None:
        raise AppException(
            "Deleted user has no restorable role",
            status_code=status.HTTP_409_CONFLICT,
        )

    now = _now()
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

    return ManagedUserResponse(
        id=user.id,
        email=user.email,
        status=user.status,
        organization_id=organization_id,
        role=_role_response_for_assignment(db, assignment),
        created_at=user.created_at,
        updated_at=user.updated_at,
        is_super_admin=user.is_super_admin if context.is_super_admin else None,
    )
