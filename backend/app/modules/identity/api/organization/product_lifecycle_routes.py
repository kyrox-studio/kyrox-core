from datetime import datetime
from secrets import compare_digest
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel

from app.core.config import settings
from app.modules.identity.api.organization.dependencies import get_organization_repository
from app.modules.identity.domain.organization.enums.organization_status import OrganizationStatus
from app.modules.identity.domain.organization.ports.organization_repository import OrganizationRepository
from app.modules.identity.domain.organization.value_objects.identity.organization_id import OrganizationId

router = APIRouter(prefix="/organizations", tags=["organizations"])


class ProductOrganizationLifecycleSnapshot(BaseModel):
    organization_id: UUID
    status: OrganizationStatus
    work_allowed: bool
    is_deleted: bool
    deleted_at: datetime | None
    updated_at: datetime


PRODUCT_LIFECYCLE_TOKEN_MIN_LENGTH = 32
_INSECURE_TOKEN_PREFIX = "dev-insecure"


def require_product_lifecycle_credential(
    token: str | None = Header(default=None, alias="X-Kyrox-Product-Lifecycle-Token"),
) -> None:
    configured = settings.CORE_PRODUCT_LIFECYCLE_TOKEN
    if (
        not configured
        or len(configured) < PRODUCT_LIFECYCLE_TOKEN_MIN_LENGTH
        or configured.startswith(_INSECURE_TOKEN_PREFIX)
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Product lifecycle credential is not configured",
        )
    if token is None or not compare_digest(token, configured):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid product lifecycle credential",
        )


@router.get(
    "/{organization_id}/lifecycle-snapshot",
    response_model=ProductOrganizationLifecycleSnapshot,
    dependencies=[Depends(require_product_lifecycle_credential)],
    responses={
        401: {"description": "Invalid product lifecycle credential"},
        404: {"description": "Organization not found"},
        503: {"description": "Product lifecycle credential is not configured"},
    },
)
def get_product_organization_lifecycle_snapshot(
    organization_id: UUID,
    repository: OrganizationRepository = Depends(get_organization_repository),
) -> ProductOrganizationLifecycleSnapshot:
    organization = repository.get_by_id_including_deleted(OrganizationId(organization_id))
    if organization is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    return ProductOrganizationLifecycleSnapshot(
        organization_id=organization_id,
        status=organization.status,
        work_allowed=organization.is_active(),
        is_deleted=organization.is_deleted(),
        deleted_at=organization.deleted_at,
        updated_at=organization.updated_at,
    )