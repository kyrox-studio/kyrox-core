from dataclasses import dataclass
from datetime import datetime

from app.modules.identity.domain.organization.enums.organization_status import OrganizationStatus
from app.modules.identity.domain.organization.exceptions import InactiveOrganizationError
from app.modules.identity.domain.organization.value_objects.identity.organization_id import OrganizationId
from app.modules.identity.domain.organization.value_objects.profile.organization_name import OrganizationName
from app.modules.identity.domain.organization.value_objects.profile.organization_slug import OrganizationSlug


@dataclass
class Organization:
    id: OrganizationId
    name: OrganizationName
    slug: OrganizationSlug
    status: OrganizationStatus
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None = None

    def is_deleted(self) -> bool:
        return self.deleted_at is not None

    def is_active(self) -> bool:
        return not self.is_deleted() and self.status is OrganizationStatus.ACTIVE


    def suspend(self, at: datetime) -> None:
        if self.status is not OrganizationStatus.ACTIVE:
            raise InactiveOrganizationError("Only active organizations can be suspended")
        self.status = OrganizationStatus.SUSPENDED
        self.updated_at = at

    def reactivate(self, at: datetime) -> None:
        if self.status is not OrganizationStatus.SUSPENDED:
            raise InactiveOrganizationError("Only suspended organizations can be reactivated")
        self.status = OrganizationStatus.ACTIVE
        self.updated_at = at

    def archive(self, at: datetime) -> None:
        if self.status is OrganizationStatus.ARCHIVED:
            raise InactiveOrganizationError("Organization is already archived")
        self.status = OrganizationStatus.ARCHIVED
        self.updated_at = at

    def assert_can_operate(self) -> None:
        if self.is_deleted() or self.status is not OrganizationStatus.ACTIVE:
            raise InactiveOrganizationError("Organization is not active")
