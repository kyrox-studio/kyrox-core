import uuid
from datetime import UTC, datetime

import pytest

from app.modules.identity.domain.organization.entities import Organization
from app.modules.identity.domain.organization.enums import OrganizationStatus
from app.modules.identity.domain.organization.exceptions import InactiveOrganizationError
from app.modules.identity.domain.organization.value_objects import (
    OrganizationId,
    OrganizationName,
    OrganizationSlug,
)


def _now() -> datetime:
    return datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)


def test_organization_lifecycle() -> None:
    organization = Organization(
        id=OrganizationId(uuid.uuid4()),
        name=OrganizationName.create("Acme"),
        slug=OrganizationSlug.create("acme"),
        status=OrganizationStatus.ACTIVE,
        created_at=_now(),
        updated_at=_now(),
    )

    assert organization.is_active() is True

    organization.suspend(_now())
    assert organization.status is OrganizationStatus.SUSPENDED

    organization.reactivate(_now())
    assert organization.status is OrganizationStatus.ACTIVE

    organization.archive(_now())
    assert organization.status is OrganizationStatus.ARCHIVED

    with pytest.raises(InactiveOrganizationError):
        organization.assert_can_operate()


def test_organization_reactivate_requires_suspended_state() -> None:
    organization = Organization(
        id=OrganizationId(uuid.uuid4()),
        name=OrganizationName.create("Acme"),
        slug=OrganizationSlug.create("acme"),
        status=OrganizationStatus.ACTIVE,
        created_at=_now(),
        updated_at=_now(),
    )

    with pytest.raises(InactiveOrganizationError):
        organization.reactivate(_now())
