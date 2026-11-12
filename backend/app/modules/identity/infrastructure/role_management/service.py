"""Role template, organization role and permission lifecycle operations.

The API layer (``api/role_management/routes.py``) only maps requests and responses;
queries, invariants and audit writes live here (BACKEND_ARCHITECTURE_STANDARDS §3.4, §4.2).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from http import HTTPStatus
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.exceptions import AppException
from app.modules.identity.application.authorization.context import AuthorizationContext
from app.modules.identity.infrastructure.user_management.audit import record_identity_event
from app.modules.identity.infrastructure.role_management.privilege import (
    assert_can_edit_role_permissions,
    assert_can_grant_permissions,
)
from app.modules.identity.infrastructure.authorization.persistence.models import (
    PermissionModel,
    RoleModel,
    RolePermissionModel,
    RoleTemplateExclusionModel,
    UserRoleModel,
)
from app.modules.identity.infrastructure.organization.persistence.models import OrganizationModel


@dataclass(frozen=True)
class Actor:
    user_id: UUID
    session_id: UUID | None


@dataclass(frozen=True)
class TemplateSyncPreview:
    role: RoleModel
    target_version: int
    add_count: int
    remove_count: int


@dataclass(frozen=True)
class PermissionLifecyclePreview:
    permission_id: UUID
    target_state: str
    affected_roles: int
    affected_users: int


def audit(
    db: Session,
    *,
    actor_id: UUID,
    session_id: UUID | None,
    action: str,
    resource_type: str,
    resource_id: UUID,
    organization_id: UUID | None = None,
    old_values: dict | None = None,
    new_values: dict | None = None,
) -> None:
    """ADR-0004 ``identity.<resource>.<verb>`` events through the audit service (F-C13)."""
    record_identity_event(
        db,
        actor_id=actor_id,
        session_id=session_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        organization_id=organization_id,
        old_values=old_values,
        new_values=new_values,
        metadata={"source": "role_management"},
    )


def audit_permission_changes(
    db: Session,
    context: AuthorizationContext,
    *,
    role: RoleModel,
    organization_id: UUID,
    old_ids: set[UUID],
    new_ids: set[UUID],
) -> None:
    granted = sorted(str(item) for item in new_ids - old_ids)
    revoked = sorted(str(item) for item in old_ids - new_ids)
    for action, ids in (
        ("identity.permission.granted", granted),
        ("identity.permission.revoked", revoked),
    ):
        if ids:
            audit(
                db,
                actor_id=context.user_id,
                session_id=context.session_id,
                action=action,
                resource_type="role",
                resource_id=role.id,
                organization_id=organization_id,
                new_values={"permission_ids": ids},
            )


def permission_ids(db: Session, role_id: UUID) -> list[UUID]:
    return list(db.scalars(select(RolePermissionModel.permission_id).where(RolePermissionModel.role_id == role_id)).all())


def get_role(db: Session, role_id: UUID) -> RoleModel:
    role = db.get(RoleModel, role_id)
    if role is None or role.deleted_at is not None:
        raise AppException("Role not found", status_code=HTTPStatus.NOT_FOUND)
    return role


def get_org_role(db: Session, organization_id: UUID, role_id: UUID) -> RoleModel:
    role = get_role(db, role_id)
    if role.organization_id != organization_id or role.role_kind != "organization":
        raise AppException("Role not found in organization", status_code=HTTPStatus.NOT_FOUND)
    return role


def validated_permissions(db: Session, ids: list[UUID], *, allow_restricted: bool) -> list[PermissionModel]:
    unique_ids = set(ids)
    permissions = list(db.scalars(select(PermissionModel).where(PermissionModel.id.in_(unique_ids))).all()) if unique_ids else []
    if len(permissions) != len(unique_ids):
        raise AppException("One or more permissions do not exist", status_code=HTTPStatus.BAD_REQUEST)
    if any(item.lifecycle_state != "active" for item in permissions):
        raise AppException("Locked or inactive permissions cannot be assigned", status_code=HTTPStatus.BAD_REQUEST)
    if any(item.permission_scope != "organization" for item in permissions):
        raise AppException("System permissions cannot be assigned to organization roles", status_code=HTTPStatus.FORBIDDEN)
    if not allow_restricted and any(not item.is_assignable for item in permissions):
        raise AppException("A platform-managed permission cannot be assigned", status_code=HTTPStatus.FORBIDDEN)
    return permissions


def permissions_for_propagation(db: Session, ids: list[UUID], *, allow_restricted: bool) -> list[PermissionModel]:
    """Propagate active grants plus locked grants kept for unlock restore. Drop inactive."""
    unique_ids = set(ids)
    if not unique_ids:
        return []
    permissions = list(db.scalars(select(PermissionModel).where(PermissionModel.id.in_(unique_ids))).all())
    if len(permissions) != len(unique_ids):
        raise AppException("One or more permissions do not exist", status_code=HTTPStatus.BAD_REQUEST)
    active_ids = [item.id for item in permissions if item.lifecycle_state == "active"]
    locked = [item for item in permissions if item.lifecycle_state == "locked"]
    if any(item.permission_scope != "organization" for item in locked):
        raise AppException("System permissions cannot be assigned to organization roles", status_code=HTTPStatus.FORBIDDEN)
    if not allow_restricted and any(not item.is_assignable for item in locked):
        raise AppException("A platform-managed permission cannot be assigned", status_code=HTTPStatus.FORBIDDEN)
    active = validated_permissions(db, active_ids, allow_restricted=allow_restricted) if active_ids else []
    return active + locked


def _locked_role_permissions(db: Session, role_id: UUID) -> list[PermissionModel]:
    return list(db.scalars(
        select(PermissionModel)
        .join(RolePermissionModel, RolePermissionModel.permission_id == PermissionModel.id)
        .where(
            RolePermissionModel.role_id == role_id,
            PermissionModel.lifecycle_state == "locked",
        )
    ).all())


def replace_permissions(db: Session, role: RoleModel, permissions: list[PermissionModel], *, customized: bool) -> None:
    # Locked grants stay on the role so unlock restores access without re-assignment.
    kept_locked = _locked_role_permissions(db, role.id)
    by_id = {item.id: item for item in permissions}
    for locked in kept_locked:
        by_id.setdefault(locked.id, locked)
    # Diff instead of delete-all + re-insert: an existing (locked) grant is never
    # re-inserted, so the PostgreSQL lifecycle trigger only sees new assignments.
    target_ids = set(by_id)
    current_ids = set(permission_ids(db, role.id))
    removed_ids = current_ids - target_ids
    if removed_ids:
        db.execute(delete(RolePermissionModel).where(
            RolePermissionModel.role_id == role.id,
            RolePermissionModel.permission_id.in_(removed_ids),
        ))
    for permission_id in target_ids - current_ids:
        db.add(RolePermissionModel(role_id=role.id, permission_id=permission_id))
    role.permissions_customized = customized
    role.updated_at = datetime.now(tz=UTC)
    db.flush()


def _get_template(db: Session, role_id: UUID) -> RoleModel:
    template = get_role(db, role_id)
    if template.role_kind != "template":
        raise AppException("Role is not a template", status_code=HTTPStatus.BAD_REQUEST)
    return template


def list_templates(db: Session) -> list[RoleModel]:
    return list(db.scalars(
        select(RoleModel).where(RoleModel.role_kind == "template", RoleModel.deleted_at.is_(None)).order_by(RoleModel.name)
    ).all())


def update_template(db: Session, actor: Actor, *, role_id: UUID, new_permission_ids: list[UUID]) -> RoleModel:
    role = _get_template(db, role_id)
    permissions = validated_permissions(db, new_permission_ids, allow_restricted=True)
    old_permission_ids = [str(item) for item in permission_ids(db, role.id)]
    replace_permissions(db, role, permissions, customized=False)
    role.template_version += 1
    audit(db, actor_id=actor.user_id, session_id=actor.session_id, action="identity.role_template.updated", resource_type="role_template", resource_id=role.id, old_values={"permission_ids": old_permission_ids}, new_values={"permission_ids": [str(item.id) for item in permissions], "version": role.template_version})
    db.flush()
    return role


def derive_template(db: Session, actor: Actor, *, role_id: UUID, organization_id: UUID, name: str, slug: str) -> RoleModel:
    template = get_role(db, role_id)
    organization = db.get(OrganizationModel, organization_id)
    if template.role_kind != "template" or organization is None or organization.deleted_at is not None:
        raise AppException("Template or organization not found", status_code=HTTPStatus.NOT_FOUND)
    role = RoleModel(
        name=name.strip(), slug=slug, scope="organization", is_system=False,
        role_kind="organization", organization_id=organization_id,
        source_template_role_id=template.id, template_version=1,
        source_template_version=template.template_version, permissions_customized=False,
        is_assignable=True, is_protected=False, auto_include_new_permissions=False,
    )
    db.add(role)
    try:
        db.flush()
    except IntegrityError as exc:
        raise AppException("Role slug already exists in organization", status_code=HTTPStatus.CONFLICT) from exc
    permissions = permissions_for_propagation(db, permission_ids(db, template.id), allow_restricted=True)
    replace_permissions(db, role, permissions, customized=False)
    audit(db, actor_id=actor.user_id, session_id=actor.session_id, action="identity.role_template.derived", resource_type="role", resource_id=role.id, organization_id=organization_id, new_values={"source_template_role_id": str(template.id), "permission_count": len(permissions)})
    return role


def sync_targets(db: Session, template: RoleModel, *, role_ids: list[UUID] | None, organization_id: UUID | None) -> list[RoleModel]:
    stmt = select(RoleModel).where(RoleModel.source_template_role_id == template.id, RoleModel.deleted_at.is_(None))
    if role_ids:
        stmt = stmt.where(RoleModel.id.in_(set(role_ids)))
    if organization_id:
        stmt = stmt.where(RoleModel.organization_id == organization_id)
    return list(db.scalars(stmt.order_by(RoleModel.name)).all())


def preview_template_sync(
    db: Session, *, role_id: UUID, role_ids: list[UUID] | None, organization_id: UUID | None
) -> list[TemplateSyncPreview]:
    template = _get_template(db, role_id)
    template_permissions = set(permission_ids(db, template.id))
    return [TemplateSyncPreview(
        role=role,
        target_version=template.template_version,
        add_count=len(template_permissions - set(permission_ids(db, role.id))),
        remove_count=len(set(permission_ids(db, role.id)) - template_permissions),
    ) for role in sync_targets(db, template, role_ids=role_ids, organization_id=organization_id)]


def sync_template(
    db: Session, actor: Actor, *, role_id: UUID, role_ids: list[UUID] | None, organization_id: UUID | None
) -> list[RoleModel]:
    template = _get_template(db, role_id)
    permissions = permissions_for_propagation(db, permission_ids(db, template.id), allow_restricted=True)
    targets = sync_targets(db, template, role_ids=role_ids, organization_id=organization_id)
    for role in targets:
        previous_count = len(permission_ids(db, role.id))
        replace_permissions(db, role, permissions, customized=False)
        role.source_template_version = template.template_version
        db.execute(delete(RoleTemplateExclusionModel).where(RoleTemplateExclusionModel.role_id == role.id))
        audit(db, actor_id=actor.user_id, session_id=actor.session_id, action="identity.role_template.synced", resource_type="role", resource_id=role.id, organization_id=role.organization_id, old_values={"permission_count": previous_count}, new_values={"permission_count": len(permissions), "source_template_version": template.template_version})
    db.flush()
    return targets


def create_organization_role(
    db: Session,
    context: AuthorizationContext,
    *,
    organization_id: UUID,
    name: str,
    slug: str,
    new_permission_ids: list[UUID],
) -> RoleModel:
    permissions = validated_permissions(db, new_permission_ids, allow_restricted=context.is_super_admin)
    # F-C2: no escalation - a role can only receive permissions the actor holds.
    assert_can_grant_permissions(db, context, [item.id for item in permissions])
    role = RoleModel(
        name=name.strip(), slug=slug, scope="organization", is_system=False,
        role_kind="organization", organization_id=organization_id, template_version=1,
        permissions_customized=True, is_assignable=True, is_protected=False,
        auto_include_new_permissions=False,
    )
    db.add(role)
    try:
        db.flush()
    except IntegrityError as exc:
        raise AppException("Role slug already exists in organization", status_code=HTTPStatus.CONFLICT) from exc
    replace_permissions(db, role, permissions, customized=True)
    audit(db, actor_id=context.user_id, session_id=context.session_id, action="identity.role.created", resource_type="role", resource_id=role.id, organization_id=organization_id, new_values={"name": role.name, "slug": role.slug, "permission_count": len(permissions)})
    audit_permission_changes(db, context, role=role, organization_id=organization_id, old_ids=set(), new_ids={item.id for item in permissions})
    return role


def list_managed_organization_roles(db: Session, organization_id: UUID) -> list[RoleModel]:
    return list(db.scalars(
        select(RoleModel).where(
            RoleModel.deleted_at.is_(None),
            RoleModel.is_assignable.is_(True),
            (RoleModel.organization_id == organization_id) | (RoleModel.role_kind == "protected_global"),
        ).order_by(RoleModel.name)
    ).all())


def list_assignable_organization_permissions(db: Session) -> list[PermissionModel]:
    return list(db.scalars(
        select(PermissionModel).where(
            PermissionModel.lifecycle_state == "active",
            PermissionModel.is_assignable.is_(True),
            PermissionModel.permission_scope == "organization",
        ).order_by(PermissionModel.code)
    ).all())


def update_organization_role(
    db: Session,
    context: AuthorizationContext,
    *,
    organization_id: UUID,
    role_id: UUID,
    name: str | None,
    slug: str | None,
) -> RoleModel:
    role = get_org_role(db, organization_id, role_id)
    if name is not None:
        role.name = name.strip()
    if slug is not None:
        role.slug = slug
    role.updated_at = datetime.now(tz=UTC)
    try:
        db.flush()
    except IntegrityError as exc:
        raise AppException("Role slug already exists in organization", status_code=HTTPStatus.CONFLICT) from exc
    audit(db, actor_id=context.user_id, session_id=context.session_id, action="identity.role.updated", resource_type="role", resource_id=role.id, organization_id=organization_id, new_values={"name": role.name, "slug": role.slug})
    return role


def update_organization_role_permissions(
    db: Session,
    context: AuthorizationContext,
    *,
    organization_id: UUID,
    role_id: UUID,
    new_permission_ids: list[UUID],
) -> RoleModel:
    role = get_org_role(db, organization_id, role_id)
    permissions = validated_permissions(db, new_permission_ids, allow_restricted=context.is_super_admin)
    # F-C2: the actor can neither grant a permission it lacks nor reshape a role
    # that already holds permissions it lacks (no escalation, own role included).
    assert_can_edit_role_permissions(db, context, role)
    assert_can_grant_permissions(db, context, [item.id for item in permissions])
    old_ids = set(permission_ids(db, role.id))
    replace_permissions(db, role, permissions, customized=True)
    if role.source_template_role_id:
        template_ids = set(permission_ids(db, role.source_template_role_id))
        # Locked grants are hidden from editors but still on the role; do not treat as exclusions.
        locked_kept_ids = {item.id for item in _locked_role_permissions(db, role.id)}
        db.execute(delete(RoleTemplateExclusionModel).where(RoleTemplateExclusionModel.role_id == role.id))
        for permission_id in template_ids - set(new_permission_ids) - locked_kept_ids:
            db.add(RoleTemplateExclusionModel(role_id=role.id, permission_id=permission_id))
    db.flush()
    audit_permission_changes(db, context, role=role, organization_id=organization_id, old_ids=old_ids, new_ids=set(permission_ids(db, role.id)))
    return role


def delete_organization_role(db: Session, context: AuthorizationContext, *, organization_id: UUID, role_id: UUID) -> None:
    role = get_org_role(db, organization_id, role_id)
    if db.scalar(select(func.count(UserRoleModel.id)).where(UserRoleModel.role_id == role.id, UserRoleModel.status == "active")):
        raise AppException("Role is assigned to active users", status_code=HTTPStatus.CONFLICT)
    role.deleted_at = datetime.now(tz=UTC)
    role.is_assignable = False
    audit(db, actor_id=context.user_id, session_id=context.session_id, action="identity.role.deleted", resource_type="role", resource_id=role.id, organization_id=organization_id, old_values={"name": role.name, "slug": role.slug})
    db.flush()


def list_permissions(db: Session) -> list[PermissionModel]:
    return list(db.scalars(select(PermissionModel).order_by(PermissionModel.code)).all())


def _get_permission(db: Session, permission_id: UUID) -> PermissionModel:
    permission = db.get(PermissionModel, permission_id)
    if permission is None:
        raise AppException("Permission not found", status_code=HTTPStatus.NOT_FOUND)
    return permission


def _lifecycle_preview(db: Session, permission: PermissionModel, state: str) -> PermissionLifecyclePreview:
    affected_roles = db.scalar(select(func.count(RolePermissionModel.role_id)).where(RolePermissionModel.permission_id == permission.id)) or 0
    affected_users = db.scalar(select(func.count(func.distinct(UserRoleModel.user_id))).join(RolePermissionModel, RolePermissionModel.role_id == UserRoleModel.role_id).where(RolePermissionModel.permission_id == permission.id, UserRoleModel.status == "active")) or 0
    return PermissionLifecyclePreview(permission_id=permission.id, target_state=state, affected_roles=affected_roles, affected_users=affected_users)


def preview_permission_lifecycle(db: Session, *, permission_id: UUID, state: str) -> PermissionLifecyclePreview:
    return _lifecycle_preview(db, _get_permission(db, permission_id), state)


def update_permission_lifecycle(
    db: Session, actor: Actor, *, permission_id: UUID, state: str, reason: str | None
) -> PermissionLifecyclePreview:
    permission = _get_permission(db, permission_id)
    preview = _lifecycle_preview(db, permission, state)
    old_state = permission.lifecycle_state
    permission.lifecycle_state = state
    permission.lifecycle_reason = reason
    permission.lifecycle_changed_at = datetime.now(tz=UTC)
    permission.lifecycle_changed_by = actor.user_id
    # Lock suspends authorization only (grants kept). Inactive strips role grants permanently.
    if state == "inactive":
        db.execute(delete(RolePermissionModel).where(RolePermissionModel.permission_id == permission.id))
    audit(db, actor_id=actor.user_id, session_id=actor.session_id, action="identity.permission.lifecycle_changed", resource_type="permission", resource_id=permission.id, old_values={"state": old_state}, new_values={"state": state, "reason": reason})
    db.flush()
    return preview
