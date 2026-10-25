from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.exceptions import AppException
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
from app.modules.identity.application.authentication.password_policy import (
    DEFAULT_PASSWORD_POLICY,
    PasswordPolicyViolation,
)
from app.modules.identity.application.authentication.revoke_all_user_sessions import (
    RevokeAllUserSessionsUseCase,
)
from app.modules.identity.domain.authentication.ports.clock import Clock
from app.modules.identity.domain.authentication.ports.refresh_token_repository import (
    RefreshTokenRepository,
)
from app.modules.identity.domain.authentication.ports.session_repository import SessionRepository
from app.modules.identity.domain.authentication.value_objects.identity.user_id import UserId
from app.modules.identity.domain.authentication.value_objects.security.access_token import AccessTokenClaims
from app.modules.identity.infrastructure.authentication.security import Argon2idPasswordHasher
from app.modules.identity.infrastructure.authorization.persistence.models import (
    PermissionModel,
    RoleModel,
    RolePermissionModel,
    UserRoleModel,
)
from app.modules.identity.infrastructure.organization.persistence.models import OrganizationModel
from app.modules.identity.infrastructure.persistence.models import UserModel

router = APIRouter(tags=["user-management"])


def _now() -> datetime:
    return datetime.now(tz=UTC)


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


def _hash_password(password: str) -> str:
    try:
        DEFAULT_PASSWORD_POLICY.validate(password)
    except PasswordPolicyViolation as exc:
        raise AppException(
            str(exc),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        ) from exc
    return Argon2idPasswordHasher().hash(password).value


def _actor_is_super_admin(db: Session, user_id: UUID) -> bool:
    actor = db.get(UserModel, user_id)
    return bool(actor and actor.deleted_at is None and actor.status == "active" and actor.is_super_admin)


def _assert_super_admin_change_allowed(
    db: Session,
    context: AuthorizationContext,
    requested: bool | None,
) -> bool:
    actor_is_super = _actor_is_super_admin(db, context.user_id)
    if requested is not None and not actor_is_super:
        raise AppException(
            "Only a Super Admin can change Super Admin access",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    return actor_is_super


def _resolve_role(
    db: Session,
    organization_id: UUID,
    role_id: UUID,
) -> RoleModel:
    role = db.get(RoleModel, role_id)
    if (
        role is None
        or role.deleted_at is not None
        or role.scope != "organization"
        or not role.is_assignable
        or role.role_kind == "template"
        or (role.organization_id is not None and role.organization_id != organization_id)
    ):
        raise AppException(
            "Role is not available for this organization",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return role


def _assert_can_assign_role(
    db: Session,
    context: AuthorizationContext,
    role: RoleModel,
) -> None:
    if context.is_super_admin or not role.is_protected:
        return
    allowed = db.scalar(
        select(PermissionModel.id)
        .join(RolePermissionModel, RolePermissionModel.permission_id == PermissionModel.id)
        .join(UserRoleModel, UserRoleModel.role_id == RolePermissionModel.role_id)
        .where(
            UserRoleModel.user_id == context.user_id,
            UserRoleModel.organization_id == context.organization_id,
            UserRoleModel.status == "active",
            UserRoleModel.revoked_at.is_(None),
            PermissionModel.code == "identity.roles.assign_protected",
            PermissionModel.lifecycle_state == "active",
        )
    )
    if allowed is None:
        raise AppException(
            "Protected role assignment is not allowed",
            status_code=status.HTTP_403_FORBIDDEN,
        )


def _active_role_for_user(
    db: Session,
    organization_id: UUID,
    user_id: UUID,
) -> AssignableRoleResponse | None:
    stmt = (
        select(RoleModel)
        .join(UserRoleModel, UserRoleModel.role_id == RoleModel.id)
        .where(
            UserRoleModel.user_id == user_id,
            UserRoleModel.organization_id == organization_id,
            UserRoleModel.status == "active",
            UserRoleModel.revoked_at.is_(None),
            RoleModel.deleted_at.is_(None),
        )
        .order_by(UserRoleModel.assigned_at.desc())
        .limit(1)
    )
    role = db.scalars(stmt).first()
    if role is None:
        return None
    return AssignableRoleResponse(id=role.id, name=role.name, slug=role.slug)


def _organization_user(
    db: Session,
    organization_id: UUID,
    user_id: UUID,
) -> UserModel:
    user = db.get(UserModel, user_id)
    if (
        user is None
        or user.deleted_at is not None
        or user.organization_id != organization_id
    ):
        raise AppException(
            "User not found in this organization",
            status_code=status.HTTP_404_NOT_FOUND,
        )
    return user


def _to_response(
    db: Session,
    organization_id: UUID,
    user: UserModel,
    *,
    expose_super_admin: bool,
) -> ManagedUserResponse:
    return ManagedUserResponse(
        id=user.id,
        email=user.email,
        status=user.status,
        organization_id=organization_id,
        role=_active_role_for_user(db, organization_id, user.id),
        created_at=user.created_at,
        updated_at=user.updated_at,
        is_super_admin=user.is_super_admin if expose_super_admin else None,
    )


def _assign_role(
    db: Session,
    *,
    organization_id: UUID,
    user_id: UUID,
    role_id: UUID,
    assigned_by: UUID,
) -> None:
    role = _resolve_role(db, organization_id, role_id)
    user = db.get(UserModel, user_id)
    if user is None or user.deleted_at is not None or user.organization_id != organization_id:
        raise AppException(
            "User does not belong to this organization",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    now = _now()
    active_roles = db.scalars(
        select(UserRoleModel).where(
            UserRoleModel.user_id == user_id,
            UserRoleModel.status == "active",
            UserRoleModel.revoked_at.is_(None),
        )
    ).all()
    for item in active_roles:
        if item.organization_id == organization_id and item.role_id == role.id:
            return
        item.status = "revoked"
        item.revoked_at = now

    db.add(
        UserRoleModel(
            user_id=user_id,
            organization_id=organization_id,
            role_id=role.id,
            status="active",
            assigned_at=now,
            revoked_at=None,
            assigned_by=assigned_by,
        )
    )


@router.get(
    "/user-management/context",
    response_model=UserManagementContextResponse,
    responses={401: {"model": ErrorResponse}},
)
def get_user_management_context(
    claims: AccessTokenClaims = Depends(get_access_token_claims),
    db: Session = Depends(get_db),
) -> UserManagementContextResponse:
    user_id = UUID(str(claims.sub.value))
    user = db.get(UserModel, user_id)
    is_super_admin = _actor_is_super_admin(db, user_id)

    if is_super_admin:
        organizations = db.scalars(
            select(OrganizationModel).where(
                OrganizationModel.deleted_at.is_(None),
                OrganizationModel.status == "active",
            ).order_by(OrganizationModel.name.asc())
        ).all()
    elif user is not None and user.deleted_at is None and user.organization_id is not None:
        organization = db.get(OrganizationModel, user.organization_id)
        organizations = (
            [organization]
            if organization is not None
            and organization.deleted_at is None
            and organization.status == "active"
            else []
        )
    else:
        organizations = []

    owned_organization_id = None
    if user is not None and user.deleted_at is None:
        owned_organization_id = user.organization_id

    return UserManagementContextResponse(
        is_super_admin=is_super_admin,
        organization_id=owned_organization_id,
        organizations=[
            ManagedOrganizationResponse(id=item.id, name=item.name, slug=item.slug)
            for item in organizations
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
    db: Session = Depends(get_db),
) -> list[AssignableRoleResponse]:
    assert_organization_scope(organization_id, context)
    stmt = (
        select(RoleModel)
        .where(
            RoleModel.deleted_at.is_(None),
            RoleModel.scope == "organization",
            RoleModel.is_assignable.is_(True),
            or_(
                RoleModel.role_kind == "protected_global",
                RoleModel.organization_id == organization_id,
            ),
        )
        .distinct()
        .order_by(RoleModel.name.asc())
    )
    return [
        AssignableRoleResponse(id=role.id, name=role.name, slug=role.slug)
        for role in db.scalars(stmt).all()
    ]


@router.get(
    "/organizations/{organization_id}/users",
    response_model=ManagedUserListResponse,
    responses={400: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
)
def list_users(
    organization_id: UUID,
    context: AuthorizationContext = Depends(require_permission("identity.users.read")),
    db: Session = Depends(get_db),
) -> ManagedUserListResponse:
    assert_organization_scope(organization_id, context)
    actor_is_super = _actor_is_super_admin(db, context.user_id)
    users = db.scalars(
        select(UserModel)
        .where(
            UserModel.organization_id == organization_id,
            UserModel.deleted_at.is_(None),
        )
        .order_by(UserModel.email.asc())
    ).all()
    return ManagedUserListResponse(
        items=[
            _to_response(db, organization_id, user, expose_super_admin=actor_is_super)
            for user in users
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
    db: Session = Depends(get_db),
) -> ManagedUserResponse:
    assert_organization_scope(organization_id, context)
    user = _organization_user(db, organization_id, user_id)
    return _to_response(
        db,
        organization_id,
        user,
        expose_super_admin=_actor_is_super_admin(db, context.user_id),
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
    db: Session = Depends(get_db),
) -> ManagedUserResponse:
    assert_organization_scope(organization_id, context)
    actor_is_super = _actor_is_super_admin(db, context.user_id)
    if payload.is_super_admin:
        _assert_super_admin_change_allowed(db, context, payload.is_super_admin)

    email = payload.email.strip().lower()
    existing = db.scalars(
        select(UserModel).where(func.lower(UserModel.email) == email)
    ).first()
    if existing is not None:
        raise AppException("User already exists", status_code=status.HTTP_409_CONFLICT)

    if not payload.is_super_admin:
        selected_role = _resolve_role(db, organization_id, payload.role_id)
        _assert_can_assign_role(db, context, selected_role)

    now = _now()
    user = UserModel(
        email=email,
        password_hash=_hash_password(payload.password),
        status=payload.status.value,
        is_super_admin=payload.is_super_admin if actor_is_super else False,
        organization_id=organization_id,
        created_at=now,
        updated_at=now,
        deleted_at=None,
    )
    db.add(user)
    db.flush()

    if not user.is_super_admin:
        _assign_role(
            db,
            organization_id=organization_id,
            user_id=user.id,
            role_id=payload.role_id,
            assigned_by=context.user_id,
        )
    db.flush()
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
    db: Session = Depends(get_db),
    revoke_all_user_sessions: RevokeAllUserSessionsUseCase = Depends(
        get_revoke_all_user_sessions_use_case
    ),
) -> ManagedUserResponse:
    assert_organization_scope(organization_id, context)
    user = db.get(UserModel, user_id)
    if user is None or user.deleted_at is not None:
        raise AppException("User not found", status_code=status.HTTP_404_NOT_FOUND)

    actor_is_super = _actor_is_super_admin(db, context.user_id)
    was_super_admin = user.is_super_admin
    previous_email = user.email
    previous_status = user.status
    previous_organization_id = user.organization_id

    if not was_super_admin and user.organization_id != organization_id:
        raise AppException("User not found in this organization", status_code=status.HTTP_404_NOT_FOUND)
    if was_super_admin and not actor_is_super:
        raise AppException(
            "Only a Super Admin can modify a Super Admin",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    if payload.is_super_admin is not None:
        _assert_super_admin_change_allowed(db, context, payload.is_super_admin)
        if was_super_admin and not payload.is_super_admin and payload.role_id is None:
            raise AppException(
                "A role is required when removing Super Admin access",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

    if payload.email is not None:
        email = payload.email.strip().lower()
        duplicate = db.scalars(
            select(UserModel).where(
                func.lower(UserModel.email) == email,
                UserModel.id != user_id,
            )
        ).first()
        if duplicate is not None:
            raise AppException(
                "Email is already in use",
                status_code=status.HTTP_409_CONFLICT,
            )
        user.email = email
    if payload.password is not None:
        user.password_hash = _hash_password(payload.password)
    if payload.status is not None:
        user.status = payload.status.value
    if payload.is_super_admin is not None:
        user.is_super_admin = payload.is_super_admin

    if user.is_super_admin:
        if user.organization_id is None:
            user.organization_id = organization_id
    else:
        user.organization_id = organization_id
        if payload.role_id is not None:
            selected_role = _resolve_role(db, organization_id, payload.role_id)
            _assert_can_assign_role(db, context, selected_role)
            _assign_role(
                db,
                organization_id=organization_id,
                user_id=user_id,
                role_id=payload.role_id,
                assigned_by=context.user_id,
            )

    user.updated_at = _now()
    db.flush()

    # Credential, identity, access-state or privilege reductions invalidate every
    # existing session, matching self-service password change and reset.
    if (
        payload.password is not None
        or user.email != previous_email
        or (user.status != "active" and user.status != previous_status)
        or (was_super_admin and not user.is_super_admin)
        or user.organization_id != previous_organization_id
    ):
        revoke_all_user_sessions.execute(UserId(user.id))
        db.flush()
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
    db: Session = Depends(get_db),
    revoke_all_user_sessions: RevokeAllUserSessionsUseCase = Depends(
        get_revoke_all_user_sessions_use_case
    ),
) -> Response:
    assert_organization_scope(organization_id, context)
    user = db.get(UserModel, user_id)
    if user is None or user.deleted_at is not None:
        raise AppException("User not found", status_code=status.HTTP_404_NOT_FOUND)

    actor_is_super = _actor_is_super_admin(db, context.user_id)
    if user.is_super_admin:
        if not actor_is_super:
            raise AppException(
                "Only a Super Admin can remove a Super Admin",
                status_code=status.HTTP_403_FORBIDDEN,
            )
    elif user.organization_id != organization_id:
        raise AppException("User not found in this organization", status_code=status.HTTP_404_NOT_FOUND)

    now = _now()
    for item in db.scalars(
        select(UserRoleModel).where(
            UserRoleModel.user_id == user_id,
            UserRoleModel.status == "active",
            UserRoleModel.revoked_at.is_(None),
        )
    ).all():
        item.status = "revoked"
        item.revoked_at = now

    user.deleted_at = now
    user.status = "inactive"
    user.updated_at = now
    db.flush()
    revoke_all_user_sessions.execute(UserId(user.id))
    db.flush()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
