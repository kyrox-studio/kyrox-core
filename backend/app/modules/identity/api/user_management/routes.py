from uuid import UUID

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.modules.identity.api.authentication.dependencies import (
    get_clock,
    get_refresh_token_repository,
    get_session_repository,
)
from app.modules.identity.api.authorization.context import AuthorizationContext
from app.modules.identity.api.authorization.guards import get_access_token_claims, require_permission
from app.modules.identity.api.authorization.scope import assert_organization_scope
from app.modules.identity.api.user_management.schemas import (
    AssignableRoleResponse,
    ErrorResponse,
    ManagedOrganizationResponse,
    ManagedUserListResponse,
    ManagedUserResponse,
    ManualUserCreateRequest,
    ManualUserUpdateRequest,
    UserManagementContextResponse,
)
from app.modules.identity.application.authentication.revoke_all_user_sessions import (
    RevokeAllUserSessionsUseCase,
)
from app.modules.identity.infrastructure.user_management import service
from app.modules.identity.infrastructure.user_management.service import NewUser, UserChanges
from app.modules.identity.domain.authentication.ports.clock import Clock
from app.modules.identity.domain.authentication.ports.refresh_token_repository import (
    RefreshTokenRepository,
)
from app.modules.identity.domain.authentication.ports.session_repository import SessionRepository
from app.modules.identity.domain.authentication.value_objects.security.access_token import AccessTokenClaims

router = APIRouter(tags=["user-management"])


def get_revoke_all_user_sessions_use_case(
    session_repository: SessionRepository = Depends(get_session_repository),
    refresh_token_repository: RefreshTokenRepository = Depends(get_refresh_token_repository),
    clock: Clock = Depends(get_clock),
) -> RevokeAllUserSessionsUseCase:
    return RevokeAllUserSessionsUseCase(
        session_repository=session_repository,
        refresh_token_repository=refresh_token_repository,
        clock=clock,
    )


def _role_response(role) -> AssignableRoleResponse | None:
    if role is None:
        return None
    return AssignableRoleResponse(id=role.id, name=role.name, slug=role.slug)


def _to_response(
    db: Session,
    organization_id: UUID,
    user,
    *,
    expose_super_admin: bool,
) -> ManagedUserResponse:
    return ManagedUserResponse(
        id=user.id,
        email=user.email,
        status=user.status,
        organization_id=organization_id,
        role=_role_response(service.active_role_for_user(db, organization_id, user.id)),
        created_at=user.created_at,
        updated_at=user.updated_at,
        is_super_admin=user.is_super_admin if expose_super_admin else None,
    )


@router.get(
    "/user-management/context",
    response_model=UserManagementContextResponse,
    responses={401: {"model": ErrorResponse}},
)
def get_user_management_context(
    claims: AccessTokenClaims = Depends(get_access_token_claims),
    db: Session = Depends(get_db, scope="function"),
) -> UserManagementContextResponse:
    result = service.management_context(db, UUID(str(claims.sub.value)))
    return UserManagementContextResponse(
        is_super_admin=result.is_super_admin,
        organization_id=result.organization_id,
        organizations=[
            ManagedOrganizationResponse(id=item.id, name=item.name, slug=item.slug)
            for item in result.organizations
        ],
    )


@router.get(
    "/organizations/{organization_id}/roles",
    response_model=list[AssignableRoleResponse],
    responses={400: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
)
def list_assignable_roles(
    organization_id: UUID,
    context: AuthorizationContext = Depends(require_permission("identity.roles.read")),
    db: Session = Depends(get_db, scope="function"),
) -> list[AssignableRoleResponse]:
    assert_organization_scope(organization_id, context)
    return [
        AssignableRoleResponse(id=role.id, name=role.name, slug=role.slug)
        for role in service.list_assignable_roles(db, organization_id)
    ]


@router.get(
    "/organizations/{organization_id}/users",
    response_model=ManagedUserListResponse,
    responses={400: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
)
def list_users(
    organization_id: UUID,
    context: AuthorizationContext = Depends(require_permission("identity.users.read")),
    db: Session = Depends(get_db, scope="function"),
) -> ManagedUserListResponse:
    assert_organization_scope(organization_id, context)
    actor_is_super = service.actor_is_super_admin(db, context.user_id)
    return ManagedUserListResponse(
        items=[
            _to_response(db, organization_id, user, expose_super_admin=actor_is_super)
            for user in service.list_organization_users(db, organization_id)
        ],
        can_manage_super_admin=actor_is_super,
    )


@router.get(
    "/organizations/{organization_id}/users/{user_id}",
    response_model=ManagedUserResponse,
    responses={
        400: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
    },
)
def get_user(
    organization_id: UUID,
    user_id: UUID,
    context: AuthorizationContext = Depends(require_permission("identity.users.read")),
    db: Session = Depends(get_db, scope="function"),
) -> ManagedUserResponse:
    assert_organization_scope(organization_id, context)
    user = service.organization_user(db, organization_id, user_id)
    return _to_response(
        db,
        organization_id,
        user,
        expose_super_admin=service.actor_is_super_admin(db, context.user_id),
    )


@router.post(
    "/organizations/{organization_id}/users/manual",
    response_model=ManagedUserResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
)
def create_user(
    organization_id: UUID,
    payload: ManualUserCreateRequest,
    context: AuthorizationContext = Depends(require_permission("identity.users.create")),
    db: Session = Depends(get_db, scope="function"),
) -> ManagedUserResponse:
    assert_organization_scope(organization_id, context)
    user, actor_is_super = service.create_user(
        db,
        context,
        organization_id=organization_id,
        new_user=NewUser(
            email=payload.email,
            password=payload.password,
            role_id=payload.role_id,
            status=payload.status.value,
            is_super_admin=payload.is_super_admin,
        ),
    )
    return _to_response(db, organization_id, user, expose_super_admin=actor_is_super)


@router.patch(
    "/organizations/{organization_id}/users/{user_id}",
    response_model=ManagedUserResponse,
    responses={
        400: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
)
def update_user(
    organization_id: UUID,
    user_id: UUID,
    payload: ManualUserUpdateRequest,
    context: AuthorizationContext = Depends(require_permission("identity.users.update")),
    db: Session = Depends(get_db, scope="function"),
    revoke_all_user_sessions: RevokeAllUserSessionsUseCase = Depends(
        get_revoke_all_user_sessions_use_case
    ),
) -> ManagedUserResponse:
    assert_organization_scope(organization_id, context)
    user, actor_is_super = service.update_user(
        db,
        context,
        organization_id=organization_id,
        user_id=user_id,
        changes=UserChanges(
            email=payload.email,
            password=payload.password,
            role_id=payload.role_id,
            status=None if payload.status is None else payload.status.value,
            is_super_admin=payload.is_super_admin,
        ),
        revoke_all_user_sessions=revoke_all_user_sessions,
    )
    return _to_response(db, organization_id, user, expose_super_admin=actor_is_super)


@router.delete(
    "/organizations/{organization_id}/users/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        400: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
    },
)
def delete_user(
    organization_id: UUID,
    user_id: UUID,
    context: AuthorizationContext = Depends(require_permission("identity.users.delete")),
    db: Session = Depends(get_db, scope="function"),
    revoke_all_user_sessions: RevokeAllUserSessionsUseCase = Depends(
        get_revoke_all_user_sessions_use_case
    ),
) -> Response:
    assert_organization_scope(organization_id, context)
    service.delete_user(
        db,
        context,
        organization_id=organization_id,
        user_id=user_id,
        revoke_all_user_sessions=revoke_all_user_sessions,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
