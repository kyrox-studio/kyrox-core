from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.exceptions import AppException
from app.db.session import get_db
from app.modules.identity.api.authorization.context import AuthorizationContext
from app.modules.identity.api.authorization.guards import require_permission, require_super_admin
from app.modules.identity.api.authorization.scope import assert_organization_scope
from app.modules.identity.api.role_management.privilege import (
    assert_can_edit_role_permissions,
    assert_can_grant_permissions,
)
from app.modules.identity.api.role_management.schemas import (
    DeriveRoleRequest,
    PermissionLifecyclePreviewResponse,
    PermissionLifecycleRequest,
    PermissionResponse,
    RoleCreateRequest,
    RolePermissionsRequest,
    RoleResponse,
    RoleUpdateRequest,
    TemplateSyncPreviewResponse,
    TemplateSyncRequest,
)
from app.modules.identity.api.user_management.audit import record_identity_event
from app.modules.identity.domain.authentication.value_objects.security.access_token import AccessTokenClaims
from app.modules.identity.infrastructure.authorization.persistence.models import (
    PermissionModel,
    RoleModel,
    RolePermissionModel,
    RoleTemplateExclusionModel,
    UserRoleModel,
)
from app.modules.identity.infrastructure.organization.persistence.models import OrganizationModel

router = APIRouter(tags=["role-management"])


def _audit(
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


def _audit_permission_changes(
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
            _audit(
                db,
                actor_id=context.user_id,
                session_id=context.session_id,
                action=action,
                resource_type="role",
                resource_id=role.id,
                organization_id=organization_id,
                new_values={"permission_ids": ids},
            )


def _permission_ids(db: Session, role_id: UUID) -> list[UUID]:
    return list(db.scalars(select(RolePermissionModel.permission_id).where(RolePermissionModel.role_id == role_id)).all())


def _role_response(db: Session, role: RoleModel) -> RoleResponse:
    return RoleResponse(
        id=role.id,
        name=role.name,
        slug=role.slug,
        role_kind=role.role_kind,
        organization_id=role.organization_id,
        source_template_role_id=role.source_template_role_id,
        template_version=role.template_version,
        source_template_version=role.source_template_version,
        permissions_customized=role.permissions_customized,
        is_assignable=role.is_assignable,
        is_protected=role.is_protected,
        permission_ids=_permission_ids(db, role.id),
    )


def _get_role(db: Session, role_id: UUID) -> RoleModel:
    role = db.get(RoleModel, role_id)
    if role is None or role.deleted_at is not None:
        raise AppException("Role not found", status_code=status.HTTP_404_NOT_FOUND)
    return role


def _get_org_role(db: Session, organization_id: UUID, role_id: UUID) -> RoleModel:
    role = _get_role(db, role_id)
    if role.organization_id != organization_id or role.role_kind != "organization":
        raise AppException("Role not found in organization", status_code=status.HTTP_404_NOT_FOUND)
    return role


def _validated_permissions(db: Session, permission_ids: list[UUID], *, allow_restricted: bool) -> list[PermissionModel]:
    unique_ids = set(permission_ids)
    permissions = list(db.scalars(select(PermissionModel).where(PermissionModel.id.in_(unique_ids))).all()) if unique_ids else []
    if len(permissions) != len(unique_ids):
        raise AppException("One or more permissions do not exist", status_code=status.HTTP_400_BAD_REQUEST)
    if any(item.lifecycle_state != "active" for item in permissions):
        raise AppException("Locked or inactive permissions cannot be assigned", status_code=status.HTTP_400_BAD_REQUEST)
    if any(item.permission_scope != "organization" for item in permissions):
        raise AppException("System permissions cannot be assigned to organization roles", status_code=status.HTTP_403_FORBIDDEN)
    if not allow_restricted and any(not item.is_assignable for item in permissions):
        raise AppException("A platform-managed permission cannot be assigned", status_code=status.HTTP_403_FORBIDDEN)
    return permissions


def _permissions_for_propagation(
    db: Session, permission_ids: list[UUID], *, allow_restricted: bool
) -> list[PermissionModel]:
    """Propagate active grants plus locked grants kept for unlock restore. Drop inactive."""
    unique_ids = set(permission_ids)
    if not unique_ids:
        return []
    permissions = list(db.scalars(select(PermissionModel).where(PermissionModel.id.in_(unique_ids))).all())
    if len(permissions) != len(unique_ids):
        raise AppException("One or more permissions do not exist", status_code=status.HTTP_400_BAD_REQUEST)
    active_ids = [item.id for item in permissions if item.lifecycle_state == "active"]
    locked = [item for item in permissions if item.lifecycle_state == "locked"]
    if any(item.permission_scope != "organization" for item in locked):
        raise AppException("System permissions cannot be assigned to organization roles", status_code=status.HTTP_403_FORBIDDEN)
    if not allow_restricted and any(not item.is_assignable for item in locked):
        raise AppException("A platform-managed permission cannot be assigned", status_code=status.HTTP_403_FORBIDDEN)
    active = _validated_permissions(db, active_ids, allow_restricted=allow_restricted) if active_ids else []
    return active + locked


def _replace_permissions(db: Session, role: RoleModel, permissions: list[PermissionModel], *, customized: bool) -> None:
    # Locked grants stay on the role so unlock restores access without re-assignment.
    kept_locked = list(db.scalars(
        select(PermissionModel)
        .join(RolePermissionModel, RolePermissionModel.permission_id == PermissionModel.id)
        .where(
            RolePermissionModel.role_id == role.id,
            PermissionModel.lifecycle_state == "locked",
        )
    ).all())
    by_id = {item.id: item for item in permissions}
    for locked in kept_locked:
        by_id.setdefault(locked.id, locked)
    # Diff instead of delete-all + re-insert: an existing (locked) grant is never
    # re-inserted, so the PostgreSQL lifecycle trigger only sees new assignments.
    target_ids = set(by_id)
    current_ids = set(_permission_ids(db, role.id))
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


@router.get("/role-templates", response_model=list[RoleResponse])
def list_templates(
    _: AccessTokenClaims = Depends(require_super_admin),
    db: Session = Depends(get_db),
) -> list[RoleResponse]:
    roles = db.scalars(select(RoleModel).where(RoleModel.role_kind == "template", RoleModel.deleted_at.is_(None)).order_by(RoleModel.name)).all()
    return [_role_response(db, role) for role in roles]


@router.patch("/role-templates/{role_id}", response_model=RoleResponse)
def update_template(
    role_id: UUID,
    payload: RolePermissionsRequest,
    claims: AccessTokenClaims = Depends(require_super_admin),
    db: Session = Depends(get_db),
) -> RoleResponse:
    role = _get_role(db, role_id)
    if role.role_kind != "template":
        raise AppException("Role is not a template", status_code=status.HTTP_400_BAD_REQUEST)
    permissions = _validated_permissions(db, payload.permission_ids, allow_restricted=True)
    old_permission_ids = [str(item) for item in _permission_ids(db, role.id)]
    _replace_permissions(db, role, permissions, customized=False)
    role.template_version += 1
    _audit(db, actor_id=claims.sub.value, session_id=claims.sid.value, action="identity.role_template.updated", resource_type="role_template", resource_id=role.id, old_values={"permission_ids": old_permission_ids}, new_values={"permission_ids": [str(item.id) for item in permissions], "version": role.template_version})
    db.flush()
    return _role_response(db, role)


@router.post("/role-templates/{role_id}/derive", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
def derive_template(
    role_id: UUID,
    payload: DeriveRoleRequest,
    claims: AccessTokenClaims = Depends(require_super_admin),
    db: Session = Depends(get_db),
) -> RoleResponse:
    template = _get_role(db, role_id)
    organization = db.get(OrganizationModel, payload.organization_id)
    if template.role_kind != "template" or organization is None or organization.deleted_at is not None:
        raise AppException("Template or organization not found", status_code=status.HTTP_404_NOT_FOUND)
    role = RoleModel(
        name=payload.name.strip(), slug=payload.slug, scope="organization", is_system=False,
        role_kind="organization", organization_id=payload.organization_id,
        source_template_role_id=template.id, template_version=1,
        source_template_version=template.template_version, permissions_customized=False,
        is_assignable=True, is_protected=False, auto_include_new_permissions=False,
    )
    db.add(role)
    try:
        db.flush()
    except IntegrityError as exc:
        raise AppException("Role slug already exists in organization", status_code=status.HTTP_409_CONFLICT) from exc
    permissions = _permissions_for_propagation(db, _permission_ids(db, template.id), allow_restricted=True)
    _replace_permissions(db, role, permissions, customized=False)
    _audit(db, actor_id=claims.sub.value, session_id=claims.sid.value, action="identity.role_template.derived", resource_type="role", resource_id=role.id, organization_id=payload.organization_id, new_values={"source_template_role_id": str(template.id), "permission_count": len(permissions)})
    return _role_response(db, role)


def _sync_targets(db: Session, template: RoleModel, payload: TemplateSyncRequest) -> list[RoleModel]:
    stmt = select(RoleModel).where(RoleModel.source_template_role_id == template.id, RoleModel.deleted_at.is_(None))
    if payload.role_ids:
        stmt = stmt.where(RoleModel.id.in_(set(payload.role_ids)))
    if payload.organization_id:
        stmt = stmt.where(RoleModel.organization_id == payload.organization_id)
    return list(db.scalars(stmt.order_by(RoleModel.name)).all())


@router.post("/role-templates/{role_id}/sync/preview", response_model=list[TemplateSyncPreviewResponse])
def preview_template_sync(
    role_id: UUID,
    payload: TemplateSyncRequest,
    _: AccessTokenClaims = Depends(require_super_admin),
    db: Session = Depends(get_db),
) -> list[TemplateSyncPreviewResponse]:
    template = _get_role(db, role_id)
    if template.role_kind != "template":
        raise AppException("Role is not a template", status_code=status.HTTP_400_BAD_REQUEST)
    template_permissions = set(_permission_ids(db, template.id))
    return [TemplateSyncPreviewResponse(
        role_id=role.id, role_name=role.name, organization_id=role.organization_id,
        current_version=role.source_template_version, target_version=template.template_version,
        add_count=len(template_permissions - set(_permission_ids(db, role.id))),
        remove_count=len(set(_permission_ids(db, role.id)) - template_permissions),
    ) for role in _sync_targets(db, template, payload)]


@router.post("/role-templates/{role_id}/sync", response_model=list[RoleResponse])
def sync_template(
    role_id: UUID,
    payload: TemplateSyncRequest,
    claims: AccessTokenClaims = Depends(require_super_admin),
    db: Session = Depends(get_db),
) -> list[RoleResponse]:
    template = _get_role(db, role_id)
    if template.role_kind != "template":
        raise AppException("Role is not a template", status_code=status.HTTP_400_BAD_REQUEST)
    permissions = _permissions_for_propagation(db, _permission_ids(db, template.id), allow_restricted=True)
    targets = _sync_targets(db, template, payload)
    for role in targets:
        previous_count = len(_permission_ids(db, role.id))
        _replace_permissions(db, role, permissions, customized=False)
        role.source_template_version = template.template_version
        db.execute(delete(RoleTemplateExclusionModel).where(RoleTemplateExclusionModel.role_id == role.id))
        _audit(db, actor_id=claims.sub.value, session_id=claims.sid.value, action="identity.role_template.synced", resource_type="role", resource_id=role.id, organization_id=role.organization_id, old_values={"permission_count": previous_count}, new_values={"permission_count": len(permissions), "source_template_version": template.template_version})
    db.flush()
    return [_role_response(db, role) for role in targets]


@router.post("/organizations/{organization_id}/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
def create_organization_role(
    organization_id: UUID,
    payload: RoleCreateRequest,
    context: AuthorizationContext = Depends(require_permission("identity.roles.create")),
    db: Session = Depends(get_db),
) -> RoleResponse:
    assert_organization_scope(organization_id, context)
    permissions = _validated_permissions(db, payload.permission_ids, allow_restricted=context.is_super_admin)
    # F-C2: no escalation - a role can only receive permissions the actor holds.
    assert_can_grant_permissions(db, context, [item.id for item in permissions])
    role = RoleModel(
        name=payload.name.strip(), slug=payload.slug, scope="organization", is_system=False,
        role_kind="organization", organization_id=organization_id, template_version=1,
        permissions_customized=True, is_assignable=True, is_protected=False,
        auto_include_new_permissions=False,
    )
    db.add(role)
    try:
        db.flush()
    except IntegrityError as exc:
        raise AppException("Role slug already exists in organization", status_code=status.HTTP_409_CONFLICT) from exc
    _replace_permissions(db, role, permissions, customized=True)
    _audit(db, actor_id=context.user_id, session_id=context.session_id, action="identity.role.created", resource_type="role", resource_id=role.id, organization_id=organization_id, new_values={"name": role.name, "slug": role.slug, "permission_count": len(permissions)})
    _audit_permission_changes(db, context, role=role, organization_id=organization_id, old_ids=set(), new_ids={item.id for item in permissions})
    return _role_response(db, role)


@router.get("/organizations/{organization_id}/managed-roles", response_model=list[RoleResponse])
def list_managed_organization_roles(
    organization_id: UUID,
    context: AuthorizationContext = Depends(require_permission("identity.roles.read")),
    db: Session = Depends(get_db),
) -> list[RoleResponse]:
    assert_organization_scope(organization_id, context)
    roles = db.scalars(
        select(RoleModel).where(
            RoleModel.deleted_at.is_(None),
            RoleModel.is_assignable.is_(True),
            (RoleModel.organization_id == organization_id) | (RoleModel.role_kind == "protected_global"),
        ).order_by(RoleModel.name)
    ).all()
    return [_role_response(db, role) for role in roles]


@router.get("/organizations/{organization_id}/role-permissions", response_model=list[PermissionResponse])
def list_organization_role_permissions(
    organization_id: UUID,
    context: AuthorizationContext = Depends(require_permission("identity.permissions.read")),
    db: Session = Depends(get_db),
) -> list[PermissionResponse]:
    assert_organization_scope(organization_id, context)
    permissions = db.scalars(
        select(PermissionModel).where(
            PermissionModel.lifecycle_state == "active",
            PermissionModel.is_assignable.is_(True),
            PermissionModel.permission_scope == "organization",
        ).order_by(PermissionModel.code)
    ).all()
    return [PermissionResponse(
        id=item.id, code=item.code, description=item.description,
        lifecycle_state=item.lifecycle_state, is_assignable=item.is_assignable,
        permission_scope=item.permission_scope,
    ) for item in permissions]


@router.get("/organizations/{organization_id}/roles/{role_id}", response_model=RoleResponse)
def get_organization_role(
    organization_id: UUID,
    role_id: UUID,
    context: AuthorizationContext = Depends(require_permission("identity.roles.read")),
    db: Session = Depends(get_db),
) -> RoleResponse:
    assert_organization_scope(organization_id, context)
    return _role_response(db, _get_org_role(db, organization_id, role_id))


@router.patch("/organizations/{organization_id}/roles/{role_id}", response_model=RoleResponse)
def update_organization_role(
    organization_id: UUID,
    role_id: UUID,
    payload: RoleUpdateRequest,
    context: AuthorizationContext = Depends(require_permission("identity.roles.update")),
    db: Session = Depends(get_db),
) -> RoleResponse:
    assert_organization_scope(organization_id, context)
    role = _get_org_role(db, organization_id, role_id)
    if payload.name is not None:
        role.name = payload.name.strip()
    if payload.slug is not None:
        role.slug = payload.slug
    role.updated_at = datetime.now(tz=UTC)
    try:
        db.flush()
    except IntegrityError as exc:
        raise AppException("Role slug already exists in organization", status_code=status.HTTP_409_CONFLICT) from exc
    _audit(db, actor_id=context.user_id, session_id=context.session_id, action="identity.role.updated", resource_type="role", resource_id=role.id, organization_id=organization_id, new_values={"name": role.name, "slug": role.slug})
    return _role_response(db, role)


@router.put("/organizations/{organization_id}/roles/{role_id}/permissions", response_model=RoleResponse)
def update_organization_role_permissions(
    organization_id: UUID,
    role_id: UUID,
    payload: RolePermissionsRequest,
    context: AuthorizationContext = Depends(require_permission("identity.roles.update")),
    db: Session = Depends(get_db),
) -> RoleResponse:
    assert_organization_scope(organization_id, context)
    role = _get_org_role(db, organization_id, role_id)
    permissions = _validated_permissions(db, payload.permission_ids, allow_restricted=context.is_super_admin)
    # F-C2: the actor can neither grant a permission it lacks nor reshape a role
    # that already holds permissions it lacks (no escalation, own role included).
    assert_can_edit_role_permissions(db, context, role)
    assert_can_grant_permissions(db, context, [item.id for item in permissions])
    old_ids = set(_permission_ids(db, role.id))
    _replace_permissions(db, role, permissions, customized=True)
    if role.source_template_role_id:
        template_ids = set(_permission_ids(db, role.source_template_role_id))
        # Locked grants are hidden from editors but still on the role; do not treat as exclusions.
        locked_kept_ids = {
            item.id
            for item in db.scalars(
                select(PermissionModel)
                .join(RolePermissionModel, RolePermissionModel.permission_id == PermissionModel.id)
                .where(
                    RolePermissionModel.role_id == role.id,
                    PermissionModel.lifecycle_state == "locked",
                )
            ).all()
        }
        db.execute(delete(RoleTemplateExclusionModel).where(RoleTemplateExclusionModel.role_id == role.id))
        for permission_id in template_ids - set(payload.permission_ids) - locked_kept_ids:
            db.add(RoleTemplateExclusionModel(role_id=role.id, permission_id=permission_id))
    db.flush()
    _audit_permission_changes(db, context, role=role, organization_id=organization_id, old_ids=old_ids, new_ids=set(_permission_ids(db, role.id)))
    return _role_response(db, role)


@router.delete("/organizations/{organization_id}/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_organization_role(
    organization_id: UUID,
    role_id: UUID,
    context: AuthorizationContext = Depends(require_permission("identity.roles.delete")),
    db: Session = Depends(get_db),
) -> Response:
    assert_organization_scope(organization_id, context)
    role = _get_org_role(db, organization_id, role_id)
    if db.scalar(select(func.count(UserRoleModel.id)).where(UserRoleModel.role_id == role.id, UserRoleModel.status == "active")):
        raise AppException("Role is assigned to active users", status_code=status.HTTP_409_CONFLICT)
    role.deleted_at = datetime.now(tz=UTC)
    role.is_assignable = False
    _audit(db, actor_id=context.user_id, session_id=context.session_id, action="identity.role.deleted", resource_type="role", resource_id=role.id, organization_id=organization_id, old_values={"name": role.name, "slug": role.slug})
    db.flush()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/permissions", response_model=list[PermissionResponse])
def list_permissions(
    _: AccessTokenClaims = Depends(require_super_admin),
    db: Session = Depends(get_db),
) -> list[PermissionResponse]:
    return [PermissionResponse.model_validate({
        "id": item.id, "code": item.code, "description": item.description,
        "lifecycle_state": item.lifecycle_state, "is_assignable": item.is_assignable,
        "permission_scope": item.permission_scope,
    }) for item in db.scalars(select(PermissionModel).order_by(PermissionModel.code)).all()]


def _lifecycle_preview(db: Session, permission: PermissionModel, state: str) -> PermissionLifecyclePreviewResponse:
    affected_roles = db.scalar(select(func.count(RolePermissionModel.role_id)).where(RolePermissionModel.permission_id == permission.id)) or 0
    affected_users = db.scalar(select(func.count(func.distinct(UserRoleModel.user_id))).join(RolePermissionModel, RolePermissionModel.role_id == UserRoleModel.role_id).where(RolePermissionModel.permission_id == permission.id, UserRoleModel.status == "active")) or 0
    return PermissionLifecyclePreviewResponse(permission_id=permission.id, target_state=state, affected_roles=affected_roles, affected_users=affected_users)


@router.post("/permissions/{permission_id}/lifecycle/preview", response_model=PermissionLifecyclePreviewResponse)
def preview_permission_lifecycle(
    permission_id: UUID,
    payload: PermissionLifecycleRequest,
    _: AccessTokenClaims = Depends(require_super_admin),
    db: Session = Depends(get_db),
) -> PermissionLifecyclePreviewResponse:
    permission = db.get(PermissionModel, permission_id)
    if permission is None:
        raise AppException("Permission not found", status_code=status.HTTP_404_NOT_FOUND)
    return _lifecycle_preview(db, permission, payload.state)


@router.post("/permissions/{permission_id}/lifecycle", response_model=PermissionLifecyclePreviewResponse)
def update_permission_lifecycle(
    permission_id: UUID,
    payload: PermissionLifecycleRequest,
    claims: AccessTokenClaims = Depends(require_super_admin),
    db: Session = Depends(get_db),
) -> PermissionLifecyclePreviewResponse:
    permission = db.get(PermissionModel, permission_id)
    if permission is None:
        raise AppException("Permission not found", status_code=status.HTTP_404_NOT_FOUND)
    preview = _lifecycle_preview(db, permission, payload.state)
    old_state = permission.lifecycle_state
    permission.lifecycle_state = payload.state
    permission.lifecycle_reason = payload.reason
    permission.lifecycle_changed_at = datetime.now(tz=UTC)
    permission.lifecycle_changed_by = claims.sub.value
    # Lock suspends authorization only (grants kept). Inactive strips role grants permanently.
    if payload.state == "inactive":
        db.execute(delete(RolePermissionModel).where(RolePermissionModel.permission_id == permission.id))
    _audit(db, actor_id=claims.sub.value, session_id=claims.sid.value, action="identity.permission.lifecycle_changed", resource_type="permission", resource_id=permission.id, old_values={"state": old_state}, new_values={"state": payload.state, "reason": payload.reason})
    db.flush()
    return preview
