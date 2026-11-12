"""Organization user management: Super Admin rules, role assignment and user lifecycle.

The API layer (``api/user_management/routes.py``) only maps requests and responses;
queries, invariants and audit writes live here (BACKEND_ARCHITECTURE_STANDARDS §3.4, §4.2).
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from uuid import UUID

from http import HTTPStatus
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.exceptions import AppException
from app.modules.identity.application.authorization.context import AuthorizationContext
from app.modules.identity.infrastructure.user_management.audit import record_context_event
from app.modules.identity.application.authentication.password_policy import (
    DEFAULT_PASSWORD_POLICY,
    PasswordPolicyViolation,
)
from app.modules.identity.application.authentication.revoke_all_user_sessions import (
    RevokeAllUserSessionsUseCase,
)
from app.modules.identity.infrastructure.role_management.privilege import (
    assert_can_assign_role,
    assert_can_manage_user,
)
from app.modules.identity.domain.authentication.value_objects.identity.user_id import UserId
from app.modules.identity.infrastructure.authentication.security import Argon2idPasswordHasher
from app.modules.identity.infrastructure.authorization.persistence.models import (
    RoleModel,
    UserRoleModel,
)
from app.modules.identity.infrastructure.organization.persistence.models import OrganizationModel
from app.modules.identity.infrastructure.persistence.models import UserModel


@dataclass(frozen=True)
class ManagementContext:
    is_super_admin: bool
    organization_id: UUID | None
    organizations: list[OrganizationModel]


@dataclass(frozen=True)
class NewUser:
    email: str
    password: str
    role_id: UUID | None
    status: str
    is_super_admin: bool


@dataclass(frozen=True)
class UserChanges:
    email: str | None
    password: str | None
    role_id: UUID | None
    status: str | None
    is_super_admin: bool | None


def now() -> datetime:
    return datetime.now(tz=UTC)


def hash_password(password: str) -> str:
    try:
        DEFAULT_PASSWORD_POLICY.validate(password)
    except PasswordPolicyViolation as exc:
        raise AppException(
            str(exc),
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
        ) from exc
    return Argon2idPasswordHasher().hash(password).value


def assert_not_last_active_super_admin(db: Session, user: UserModel) -> None:
    """ADR-0003: the last active, non-deleted Super Admin cannot be removed.

    The database trigger trg_identity_users_protect_last_super_admin enforces
    the same invariant under concurrency; this check returns a clear 409.
    """
    if not (user.is_super_admin and user.status == "active" and user.deleted_at is None):
        return
    other_active = db.scalars(
        select(UserModel.id).where(
            UserModel.id != user.id,
            UserModel.is_super_admin.is_(True),
            UserModel.status == "active",
            UserModel.deleted_at.is_(None),
        )
    ).first()
    if other_active is None:
        raise AppException(
            "Cannot remove, demote, suspend, or delete the last active Super Admin",
            status_code=HTTPStatus.CONFLICT,
        )


def actor_is_super_admin(db: Session, user_id: UUID) -> bool:
    actor = db.get(UserModel, user_id)
    return bool(actor and actor.deleted_at is None and actor.status == "active" and actor.is_super_admin)


def assert_super_admin_change_allowed(
    db: Session,
    context: AuthorizationContext,
    requested: bool | None,
) -> bool:
    actor_is_super = actor_is_super_admin(db, context.user_id)
    if requested is not None and not actor_is_super:
        raise AppException(
            "Only a Super Admin can change Super Admin access",
            status_code=HTTPStatus.FORBIDDEN,
        )
    return actor_is_super


def resolve_role(db: Session, organization_id: UUID, role_id: UUID) -> RoleModel:
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
            status_code=HTTPStatus.BAD_REQUEST,
        )
    return role


def active_role_for_user(db: Session, organization_id: UUID, user_id: UUID) -> RoleModel | None:
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
    return db.scalars(stmt).first()


def organization_user(db: Session, organization_id: UUID, user_id: UUID) -> UserModel:
    user = db.get(UserModel, user_id)
    if (
        user is None
        or user.deleted_at is not None
        or user.organization_id != organization_id
    ):
        raise AppException(
            "User not found in this organization",
            status_code=HTTPStatus.NOT_FOUND,
        )
    return user


def assign_role(
    db: Session,
    *,
    organization_id: UUID,
    user_id: UUID,
    role_id: UUID,
    assigned_by: UUID,
) -> list[str] | None:
    """Make ``role_id`` the user's single active role.

    Returns the ids of the revoked previous roles, or ``None`` when the role was
    already active (no change).
    """
    role = resolve_role(db, organization_id, role_id)
    user = db.get(UserModel, user_id)
    if user is None or user.deleted_at is not None or user.organization_id != organization_id:
        raise AppException(
            "User does not belong to this organization",
            status_code=HTTPStatus.BAD_REQUEST,
        )

    current = now()
    active_roles = db.scalars(
        select(UserRoleModel).where(
            UserRoleModel.user_id == user_id,
            UserRoleModel.status == "active",
            UserRoleModel.revoked_at.is_(None),
        )
    ).all()
    if any(
        item.organization_id == organization_id and item.role_id == role.id
        for item in active_roles
    ):
        return None
    revoked_role_ids: list[str] = []
    for item in active_roles:
        item.status = "revoked"
        item.revoked_at = current
        revoked_role_ids.append(str(item.role_id))

    db.add(
        UserRoleModel(
            user_id=user_id,
            organization_id=organization_id,
            role_id=role.id,
            status="active",
            assigned_at=current,
            revoked_at=None,
            assigned_by=assigned_by,
        )
    )
    return revoked_role_ids


def _current_role_id(db: Session, organization_id: UUID, user_id: UUID) -> UUID | None:
    role = active_role_for_user(db, organization_id, user_id)
    return None if role is None else role.id


def _audit_role_assigned(
    db: Session,
    context: AuthorizationContext,
    *,
    organization_id: UUID,
    user_id: UUID,
    role_id: UUID,
    revoked_role_ids: list[str] | None,
) -> None:
    if revoked_role_ids is None:
        return
    record_context_event(
        db,
        context,
        action="identity.role.assigned",
        resource_type="user",
        resource_id=user_id,
        organization_id=organization_id,
        old_values={"role_ids": revoked_role_ids},
        new_values={"role_id": str(role_id)},
    )


def _effective_context(context: AuthorizationContext, actor_is_super: bool) -> AuthorizationContext:
    """Privilege checks use the DB-backed Super Admin flag, like the rest of this module."""
    if context.is_super_admin == actor_is_super:
        return context
    return replace(context, is_super_admin=actor_is_super)


def _audit_user_update(
    db: Session,
    context: AuthorizationContext,
    *,
    organization_id: UUID,
    user: UserModel,
    password_changed: bool,
    previous_email: str,
    previous_status: str,
    was_super_admin: bool,
) -> None:
    """Credential/identity, status and Super Admin changes; secrets are never recorded."""
    changed: list[str] = []
    old_values: dict[str, object] = {}
    new_values: dict[str, object] = {}
    if user.email != previous_email:
        changed.append("email")
        old_values["email"] = previous_email
        new_values["email"] = user.email
    if password_changed:
        changed.append("password")
        new_values["credential_replaced"] = True
    if changed:
        record_context_event(
            db,
            context,
            action="identity.user.updated",
            resource_type="user",
            resource_id=user.id,
            organization_id=organization_id,
            old_values=old_values or None,
            new_values=new_values,
            metadata={"changed_fields": changed},
        )
    if user.status != previous_status:
        record_context_event(
            db,
            context,
            action=(
                "identity.user.deactivated"
                if user.status != "active"
                else "identity.user.activated"
            ),
            resource_type="user",
            resource_id=user.id,
            organization_id=organization_id,
            old_values={"status": previous_status},
            new_values={"status": user.status},
        )
    if user.is_super_admin != was_super_admin:
        record_context_event(
            db,
            context,
            action=(
                "identity.user.super_admin_granted"
                if user.is_super_admin
                else "identity.user.super_admin_revoked"
            ),
            resource_type="user",
            resource_id=user.id,
            organization_id=organization_id,
            old_values={"is_super_admin": was_super_admin},
            new_values={"is_super_admin": user.is_super_admin},
        )


def management_context(db: Session, user_id: UUID) -> ManagementContext:
    user = db.get(UserModel, user_id)
    is_super_admin = actor_is_super_admin(db, user_id)

    if is_super_admin:
        organizations = list(db.scalars(
            select(OrganizationModel).where(
                OrganizationModel.deleted_at.is_(None),
                OrganizationModel.status == "active",
            ).order_by(OrganizationModel.name.asc())
        ).all())
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
    return ManagementContext(
        is_super_admin=is_super_admin,
        organization_id=owned_organization_id,
        organizations=organizations,
    )


def list_assignable_roles(db: Session, organization_id: UUID) -> list[RoleModel]:
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
    return list(db.scalars(stmt).all())


def list_organization_users(db: Session, organization_id: UUID) -> list[UserModel]:
    return list(db.scalars(
        select(UserModel)
        .where(
            UserModel.organization_id == organization_id,
            UserModel.deleted_at.is_(None),
        )
        .order_by(UserModel.email.asc())
    ).all())


def create_user(
    db: Session,
    context: AuthorizationContext,
    *,
    organization_id: UUID,
    new_user: NewUser,
) -> tuple[UserModel, bool]:
    """Returns the created user and whether the actor is an active Super Admin."""
    actor_is_super = actor_is_super_admin(db, context.user_id)
    context = _effective_context(context, actor_is_super)
    if new_user.is_super_admin:
        assert_super_admin_change_allowed(db, context, new_user.is_super_admin)

    email = new_user.email.strip().lower()
    existing = db.scalars(
        select(UserModel).where(func.lower(UserModel.email) == email)
    ).first()
    if existing is not None:
        raise AppException("User already exists", status_code=HTTPStatus.CONFLICT)

    if not new_user.is_super_admin:
        selected_role = resolve_role(db, organization_id, new_user.role_id)
        assert_can_assign_role(db, context, selected_role)

    current = now()
    user = UserModel(
        email=email,
        password_hash=hash_password(new_user.password),
        status=new_user.status,
        is_super_admin=new_user.is_super_admin if actor_is_super else False,
        organization_id=organization_id,
        created_at=current,
        updated_at=current,
        deleted_at=None,
    )
    db.add(user)
    db.flush()

    record_context_event(
        db,
        context,
        action="identity.user.created",
        resource_type="user",
        resource_id=user.id,
        organization_id=organization_id,
        new_values={
            "email": user.email,
            "status": user.status,
            "is_super_admin": user.is_super_admin,
            "role_id": None if user.is_super_admin else str(new_user.role_id),
        },
    )
    if user.is_super_admin:
        record_context_event(
            db,
            context,
            action="identity.user.super_admin_granted",
            resource_type="user",
            resource_id=user.id,
            organization_id=organization_id,
            old_values={"is_super_admin": False},
            new_values={"is_super_admin": True},
        )
    else:
        revoked = assign_role(
            db,
            organization_id=organization_id,
            user_id=user.id,
            role_id=new_user.role_id,
            assigned_by=context.user_id,
        )
        _audit_role_assigned(
            db,
            context,
            organization_id=organization_id,
            user_id=user.id,
            role_id=new_user.role_id,
            revoked_role_ids=revoked,
        )
    db.flush()
    return user, actor_is_super


def update_user(
    db: Session,
    context: AuthorizationContext,
    *,
    organization_id: UUID,
    user_id: UUID,
    changes: UserChanges,
    revoke_all_user_sessions: RevokeAllUserSessionsUseCase,
) -> tuple[UserModel, bool]:
    """Returns the updated user and whether the actor is an active Super Admin."""
    user = db.get(UserModel, user_id)
    if user is None or user.deleted_at is not None:
        raise AppException("User not found", status_code=HTTPStatus.NOT_FOUND)

    actor_is_super = actor_is_super_admin(db, context.user_id)
    context = _effective_context(context, actor_is_super)
    was_super_admin = user.is_super_admin
    previous_email = user.email
    previous_status = user.status
    previous_organization_id = user.organization_id

    if not was_super_admin and user.organization_id != organization_id:
        raise AppException("User not found in this organization", status_code=HTTPStatus.NOT_FOUND)
    # F-C1: credentials, email, status and role of a user holding permissions the
    # actor lacks (or of a Super Admin) cannot be changed by that actor.
    assert_can_manage_user(db, context, user)
    if changes.is_super_admin is not None:
        assert_super_admin_change_allowed(db, context, changes.is_super_admin)
        if was_super_admin and not changes.is_super_admin and changes.role_id is None:
            raise AppException(
                "A role is required when removing Super Admin access",
                status_code=HTTPStatus.BAD_REQUEST,
            )
    if (changes.is_super_admin is False and was_super_admin) or (
        changes.status is not None and changes.status != "active"
    ):
        assert_not_last_active_super_admin(db, user)

    if changes.email is not None:
        email = changes.email.strip().lower()
        duplicate = db.scalars(
            select(UserModel).where(
                func.lower(UserModel.email) == email,
                UserModel.id != user_id,
            )
        ).first()
        if duplicate is not None:
            raise AppException(
                "Email is already in use",
                status_code=HTTPStatus.CONFLICT,
            )
        user.email = email
    if changes.password is not None:
        user.password_hash = hash_password(changes.password)
    if changes.status is not None:
        user.status = changes.status
    if changes.is_super_admin is not None:
        user.is_super_admin = changes.is_super_admin

    role_change: tuple[UUID, list[str] | None] | None = None
    if user.is_super_admin:
        if user.organization_id is None:
            user.organization_id = organization_id
    else:
        user.organization_id = organization_id
        if changes.role_id is not None:
            selected_role = resolve_role(db, organization_id, changes.role_id)
            if _current_role_id(db, organization_id, user_id) != selected_role.id:
                assert_can_assign_role(db, context, selected_role)
            revoked = assign_role(
                db,
                organization_id=organization_id,
                user_id=user_id,
                role_id=changes.role_id,
                assigned_by=context.user_id,
            )
            role_change = (selected_role.id, revoked)

    user.updated_at = now()
    db.flush()

    _audit_user_update(
        db,
        context,
        organization_id=organization_id,
        user=user,
        password_changed=changes.password is not None,
        previous_email=previous_email,
        previous_status=previous_status,
        was_super_admin=was_super_admin,
    )
    if role_change is not None:
        _audit_role_assigned(
            db,
            context,
            organization_id=organization_id,
            user_id=user.id,
            role_id=role_change[0],
            revoked_role_ids=role_change[1],
        )

    # Credential, identity, access-state or privilege reductions invalidate every
    # existing session, matching self-service password change and reset.
    if (
        changes.password is not None
        or user.email != previous_email
        or (user.status != "active" and user.status != previous_status)
        or (was_super_admin and not user.is_super_admin)
        or user.organization_id != previous_organization_id
    ):
        revoke_all_user_sessions.execute(UserId(user.id))
        db.flush()
    return user, actor_is_super


def delete_user(
    db: Session,
    context: AuthorizationContext,
    *,
    organization_id: UUID,
    user_id: UUID,
    revoke_all_user_sessions: RevokeAllUserSessionsUseCase,
) -> None:
    user = db.get(UserModel, user_id)
    if user is None or user.deleted_at is not None:
        raise AppException("User not found", status_code=HTTPStatus.NOT_FOUND)

    actor_is_super = actor_is_super_admin(db, context.user_id)
    context = _effective_context(context, actor_is_super)
    if user.is_super_admin:
        if not actor_is_super:
            raise AppException(
                "Only a Super Admin can remove a Super Admin",
                status_code=HTTPStatus.FORBIDDEN,
            )
    elif user.organization_id != organization_id:
        raise AppException("User not found in this organization", status_code=HTTPStatus.NOT_FOUND)
    assert_can_manage_user(db, context, user)
    assert_not_last_active_super_admin(db, user)
    previous_status = user.status

    current = now()
    for item in db.scalars(
        select(UserRoleModel).where(
            UserRoleModel.user_id == user_id,
            UserRoleModel.status == "active",
            UserRoleModel.revoked_at.is_(None),
        )
    ).all():
        item.status = "revoked"
        item.revoked_at = current

    user.deleted_at = current
    user.status = "inactive"
    user.updated_at = current
    db.flush()
    record_context_event(
        db,
        context,
        action="identity.user.deleted",
        resource_type="user",
        resource_id=user.id,
        organization_id=organization_id,
        old_values={"email": user.email, "status": previous_status},
        new_values={"status": user.status},
    )
    revoke_all_user_sessions.execute(UserId(user.id))
    db.flush()
