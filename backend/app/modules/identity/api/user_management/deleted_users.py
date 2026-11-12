from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

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
from app.modules.identity.infrastructure.user_management import deleted_users as service

router = APIRouter(tags=["user-management"])


def _role_response(role) -> AssignableRoleResponse | None:
    if role is None:
        return None
    return AssignableRoleResponse(id=role.id, name=role.name, slug=role.slug)


def _user_response(db: Session, organization_id: UUID, user, assignment, *, expose_super_admin: bool) -> ManagedUserResponse:
    return ManagedUserResponse(
        id=user.id,
        email=user.email,
        status=user.status,
        organization_id=organization_id,
        role=_role_response(service.role_for_assignment(db, assignment)),
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
    users = service.list_deleted_users(db, context, organization_id)
    return ManagedUserListResponse(
        items=[
            _user_response(
                db,
                organization_id,
                user,
                service.latest_restorable_assignment(db, organization_id, user.id),
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
    user, assignment = service.restore_deleted_user(db, context, organization_id=organization_id, user_id=user_id)
    return _user_response(db, organization_id, user, assignment, expose_super_admin=context.is_super_admin)
