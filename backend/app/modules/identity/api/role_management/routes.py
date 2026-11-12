from uuid import UUID

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.modules.identity.api.authorization.context import AuthorizationContext
from app.modules.identity.api.authorization.guards import require_permission, require_super_admin
from app.modules.identity.api.authorization.scope import assert_organization_scope
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
from app.modules.identity.infrastructure.role_management import service
from app.modules.identity.infrastructure.role_management.service import Actor, PermissionLifecyclePreview
from app.modules.identity.domain.authentication.value_objects.security.access_token import AccessTokenClaims

router = APIRouter(tags=["role-management"])


def _actor(claims: AccessTokenClaims) -> Actor:
    return Actor(user_id=claims.sub.value, session_id=claims.sid.value)


def _role_response(db: Session, role) -> RoleResponse:
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
        permission_ids=service.permission_ids(db, role.id),
    )


def _permission_response(item) -> PermissionResponse:
    return PermissionResponse(
        id=item.id, code=item.code, description=item.description,
        lifecycle_state=item.lifecycle_state, is_assignable=item.is_assignable,
        permission_scope=item.permission_scope,
    )


def _lifecycle_response(preview: PermissionLifecyclePreview) -> PermissionLifecyclePreviewResponse:
    return PermissionLifecyclePreviewResponse(
        permission_id=preview.permission_id,
        target_state=preview.target_state,
        affected_roles=preview.affected_roles,
        affected_users=preview.affected_users,
    )


@router.get("/role-templates", response_model=list[RoleResponse])
def list_templates(
    _: AccessTokenClaims = Depends(require_super_admin),
    db: Session = Depends(get_db, scope="function"),
) -> list[RoleResponse]:
    return [_role_response(db, role) for role in service.list_templates(db)]


@router.patch("/role-templates/{role_id}", response_model=RoleResponse)
def update_template(
    role_id: UUID,
    payload: RolePermissionsRequest,
    claims: AccessTokenClaims = Depends(require_super_admin),
    db: Session = Depends(get_db, scope="function"),
) -> RoleResponse:
    role = service.update_template(db, _actor(claims), role_id=role_id, new_permission_ids=payload.permission_ids)
    return _role_response(db, role)


@router.post("/role-templates/{role_id}/derive", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
def derive_template(
    role_id: UUID,
    payload: DeriveRoleRequest,
    claims: AccessTokenClaims = Depends(require_super_admin),
    db: Session = Depends(get_db, scope="function"),
) -> RoleResponse:
    role = service.derive_template(
        db, _actor(claims), role_id=role_id,
        organization_id=payload.organization_id, name=payload.name, slug=payload.slug,
    )
    return _role_response(db, role)


@router.post("/role-templates/{role_id}/sync/preview", response_model=list[TemplateSyncPreviewResponse])
def preview_template_sync(
    role_id: UUID,
    payload: TemplateSyncRequest,
    _: AccessTokenClaims = Depends(require_super_admin),
    db: Session = Depends(get_db, scope="function"),
) -> list[TemplateSyncPreviewResponse]:
    previews = service.preview_template_sync(
        db, role_id=role_id, role_ids=payload.role_ids, organization_id=payload.organization_id,
    )
    return [TemplateSyncPreviewResponse(
        role_id=item.role.id, role_name=item.role.name, organization_id=item.role.organization_id,
        current_version=item.role.source_template_version, target_version=item.target_version,
        add_count=item.add_count, remove_count=item.remove_count,
    ) for item in previews]


@router.post("/role-templates/{role_id}/sync", response_model=list[RoleResponse])
def sync_template(
    role_id: UUID,
    payload: TemplateSyncRequest,
    claims: AccessTokenClaims = Depends(require_super_admin),
    db: Session = Depends(get_db, scope="function"),
) -> list[RoleResponse]:
    targets = service.sync_template(
        db, _actor(claims), role_id=role_id, role_ids=payload.role_ids, organization_id=payload.organization_id,
    )
    return [_role_response(db, role) for role in targets]


@router.post("/organizations/{organization_id}/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
def create_organization_role(
    organization_id: UUID,
    payload: RoleCreateRequest,
    context: AuthorizationContext = Depends(require_permission("identity.roles.create")),
    db: Session = Depends(get_db, scope="function"),
) -> RoleResponse:
    assert_organization_scope(organization_id, context)
    role = service.create_organization_role(
        db, context, organization_id=organization_id,
        name=payload.name, slug=payload.slug, new_permission_ids=payload.permission_ids,
    )
    return _role_response(db, role)


@router.get("/organizations/{organization_id}/managed-roles", response_model=list[RoleResponse])
def list_managed_organization_roles(
    organization_id: UUID,
    context: AuthorizationContext = Depends(require_permission("identity.roles.read")),
    db: Session = Depends(get_db, scope="function"),
) -> list[RoleResponse]:
    assert_organization_scope(organization_id, context)
    return [_role_response(db, role) for role in service.list_managed_organization_roles(db, organization_id)]


@router.get("/organizations/{organization_id}/role-permissions", response_model=list[PermissionResponse])
def list_organization_role_permissions(
    organization_id: UUID,
    context: AuthorizationContext = Depends(require_permission("identity.permissions.read")),
    db: Session = Depends(get_db, scope="function"),
) -> list[PermissionResponse]:
    assert_organization_scope(organization_id, context)
    return [_permission_response(item) for item in service.list_assignable_organization_permissions(db)]


@router.get("/organizations/{organization_id}/roles/{role_id}", response_model=RoleResponse)
def get_organization_role(
    organization_id: UUID,
    role_id: UUID,
    context: AuthorizationContext = Depends(require_permission("identity.roles.read")),
    db: Session = Depends(get_db, scope="function"),
) -> RoleResponse:
    assert_organization_scope(organization_id, context)
    return _role_response(db, service.get_org_role(db, organization_id, role_id))


@router.patch("/organizations/{organization_id}/roles/{role_id}", response_model=RoleResponse)
def update_organization_role(
    organization_id: UUID,
    role_id: UUID,
    payload: RoleUpdateRequest,
    context: AuthorizationContext = Depends(require_permission("identity.roles.update")),
    db: Session = Depends(get_db, scope="function"),
) -> RoleResponse:
    assert_organization_scope(organization_id, context)
    role = service.update_organization_role(
        db, context, organization_id=organization_id, role_id=role_id, name=payload.name, slug=payload.slug,
    )
    return _role_response(db, role)


@router.put("/organizations/{organization_id}/roles/{role_id}/permissions", response_model=RoleResponse)
def update_organization_role_permissions(
    organization_id: UUID,
    role_id: UUID,
    payload: RolePermissionsRequest,
    context: AuthorizationContext = Depends(require_permission("identity.roles.update")),
    db: Session = Depends(get_db, scope="function"),
) -> RoleResponse:
    assert_organization_scope(organization_id, context)
    role = service.update_organization_role_permissions(
        db, context, organization_id=organization_id, role_id=role_id, new_permission_ids=payload.permission_ids,
    )
    return _role_response(db, role)


@router.delete("/organizations/{organization_id}/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_organization_role(
    organization_id: UUID,
    role_id: UUID,
    context: AuthorizationContext = Depends(require_permission("identity.roles.delete")),
    db: Session = Depends(get_db, scope="function"),
) -> Response:
    assert_organization_scope(organization_id, context)
    service.delete_organization_role(db, context, organization_id=organization_id, role_id=role_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/permissions", response_model=list[PermissionResponse])
def list_permissions(
    _: AccessTokenClaims = Depends(require_super_admin),
    db: Session = Depends(get_db, scope="function"),
) -> list[PermissionResponse]:
    return [_permission_response(item) for item in service.list_permissions(db)]


@router.post("/permissions/{permission_id}/lifecycle/preview", response_model=PermissionLifecyclePreviewResponse)
def preview_permission_lifecycle(
    permission_id: UUID,
    payload: PermissionLifecycleRequest,
    _: AccessTokenClaims = Depends(require_super_admin),
    db: Session = Depends(get_db, scope="function"),
) -> PermissionLifecyclePreviewResponse:
    return _lifecycle_response(service.preview_permission_lifecycle(db, permission_id=permission_id, state=payload.state))


@router.post("/permissions/{permission_id}/lifecycle", response_model=PermissionLifecyclePreviewResponse)
def update_permission_lifecycle(
    permission_id: UUID,
    payload: PermissionLifecycleRequest,
    claims: AccessTokenClaims = Depends(require_super_admin),
    db: Session = Depends(get_db, scope="function"),
) -> PermissionLifecyclePreviewResponse:
    preview = service.update_permission_lifecycle(
        db, _actor(claims), permission_id=permission_id, state=payload.state, reason=payload.reason,
    )
    return _lifecycle_response(preview)
