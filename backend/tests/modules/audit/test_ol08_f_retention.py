from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.modules.audit.api.routes import _terminal_safe_body
from app.modules.audit.api.schemas import RecordAuditEventRequest
from app.modules.audit.application.purge_retained_organization_audit import (
    add_calendar_months,
    as_utc,
)
from app.modules.audit.domain.retention_policy import AUDIT_RETENTION_POLICY_VERSION
from app.modules.audit.infrastructure.persistence.models import AuditLogModel
from app.modules.identity.api.authentication.dependencies import get_clock
from app.modules.identity.infrastructure.organization.persistence.models.organization import OrganizationModel


CONFIGURED_LIFECYCLE_TOKEN = "lifecycle-test-credential-" + "r" * 32


@pytest.fixture(autouse=True)
def _configured_lifecycle_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "CORE_PRODUCT_LIFECYCLE_TOKEN", CONFIGURED_LIFECYCLE_TOKEN)


class FixedClock:
    def __init__(self, now: datetime) -> None:
        self.value = now

    def now(self) -> datetime:
        return self.value


def _headers() -> dict[str, str]:
    return {
        "X-Kyrox-Product-Lifecycle-Token": settings.CORE_PRODUCT_LIFECYCLE_TOKEN,
        "X-Kyrox-Retention-Policy-Version": AUDIT_RETENTION_POLICY_VERSION,
    }


def _seed_deleted_organization(
    db_session: Session,
    *,
    deleted_at: datetime,
):
    organization_id = uuid4()
    db_session.add(
        OrganizationModel(
            id=organization_id,
            name=f"Deleted {organization_id}",
            slug=f"deleted-{organization_id}",
            status="suspended",
            deleted_at=deleted_at,
        )
    )
    db_session.flush()
    return organization_id


def _seed_audit(db_session: Session, organization_id, *, action: str) -> None:
    db_session.add(
        AuditLogModel(
            organization_id=organization_id,
            user_id=None,
            session_id=None,
            action=action,
            resource_type="organization_closure",
            resource_id=str(organization_id),
            old_values=None,
            new_values=None,
            event_metadata={"result": "bounded"},
            ip_address=None,
            user_agent=None,
        )
    )
    db_session.flush()


def _count(db_session: Session, organization_id) -> int:
    return int(
        db_session.scalar(
            select(func.count())
            .select_from(AuditLogModel)
            .where(AuditLogModel.organization_id == organization_id)
        )
        or 0
    )


def _set_clock(client: TestClient, at: datetime) -> None:
    app: FastAPI = client.app  # type: ignore[assignment]
    app.dependency_overrides[get_clock] = lambda: FixedClock(at)


def test_calendar_retention_maps_leap_day_to_last_valid_day() -> None:
    assert add_calendar_months(datetime(2024, 2, 29, 10, 30, tzinfo=UTC), 12) == datetime(
        2025,
        2,
        28,
        10,
        30,
        tzinfo=UTC,
    )


def test_naive_tombstone_is_interpreted_as_utc_not_process_local_time() -> None:
    naive = datetime(2025, 6, 15, 12, 30, 45)
    aware = datetime(2025, 6, 15, 12, 30, 45, tzinfo=UTC)
    assert as_utc(naive) == aware
    assert as_utc(aware) == aware
    deadline = add_calendar_months(as_utc(naive), 12)
    assert deadline == datetime(2026, 6, 15, 12, 30, 45, tzinfo=UTC)
    assert as_utc(datetime(2026, 6, 15, 12, 30, 44, 999999, tzinfo=UTC)) < deadline


def test_retention_purge_requires_product_lifecycle_credential(
    client: TestClient,
    db_session: Session,
) -> None:
    deleted_at = datetime(2025, 1, 1, tzinfo=UTC)
    organization_id = _seed_deleted_organization(db_session, deleted_at=deleted_at)
    _seed_audit(db_session, organization_id, action="identity.organization.deleted")
    _set_clock(client, datetime(2026, 1, 1, tzinfo=UTC))

    path = f"/api/v1/organizations/{organization_id}/retained-audit-evidence/purge"
    assert client.post(path).status_code == 401
    wrong = _headers()
    wrong["X-Kyrox-Product-Lifecycle-Token"] = "wrong"
    assert client.post(path, headers=wrong).status_code == 401
    assert _count(db_session, organization_id) == 1


@pytest.mark.parametrize(
    "configured",
    [
        None,
        "",
        "short-lifecycle-token",
        "dev-insecure-product-lifecycle-token-change-me",
    ],
)
def test_retention_purge_fails_closed_without_secure_credential(
    client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    configured: str | None,
) -> None:
    deleted_at = datetime(2025, 1, 1, tzinfo=UTC)
    organization_id = _seed_deleted_organization(db_session, deleted_at=deleted_at)
    _seed_audit(db_session, organization_id, action="identity.organization.deleted")
    _set_clock(client, datetime(2026, 1, 1, tzinfo=UTC))
    monkeypatch.setattr(settings, "CORE_PRODUCT_LIFECYCLE_TOKEN", configured)

    path = f"/api/v1/organizations/{organization_id}/retained-audit-evidence/purge"
    headers = _headers()
    headers["X-Kyrox-Product-Lifecycle-Token"] = "dev-insecure-product-lifecycle-token-change-me"

    assert client.post(path, headers=headers).status_code == 503
    assert client.post(path).status_code == 503
    assert _count(db_session, organization_id) == 1


def test_retention_purge_requires_exact_policy_version(
    client: TestClient,
    db_session: Session,
) -> None:
    deleted_at = datetime(2025, 1, 1, tzinfo=UTC)
    organization_id = _seed_deleted_organization(db_session, deleted_at=deleted_at)
    _seed_audit(db_session, organization_id, action="identity.organization.deleted")
    _set_clock(client, datetime(2026, 1, 1, tzinfo=UTC))
    path = f"/api/v1/organizations/{organization_id}/retained-audit-evidence/purge"

    lifecycle_only = {
        "X-Kyrox-Product-Lifecycle-Token": settings.CORE_PRODUCT_LIFECYCLE_TOKEN,
    }
    wrong_policy = {**lifecycle_only, "X-Kyrox-Retention-Policy-Version": "wrong"}

    assert client.post(path, headers=lifecycle_only).status_code == 409
    assert client.post(path, headers=wrong_policy).status_code == 409
    assert _count(db_session, organization_id) == 1


def test_retention_purge_fails_closed_before_terminal_tombstone(
    client: TestClient,
    db_session: Session,
) -> None:
    organization_id = uuid4()
    db_session.add(
        OrganizationModel(
            id=organization_id,
            name="Not deleted",
            slug=f"not-deleted-{organization_id}",
            status="suspended",
            deleted_at=None,
        )
    )
    _seed_audit(db_session, organization_id, action="identity.organization.suspended")
    _set_clock(client, datetime(2030, 1, 1, tzinfo=UTC))

    response = client.post(
        f"/api/v1/organizations/{organization_id}/retained-audit-evidence/purge",
        headers=_headers(),
    )

    assert response.status_code == 409
    assert _count(db_session, organization_id) == 1


def test_retention_purge_fails_closed_before_exact_12_month_deadline(
    client: TestClient,
    db_session: Session,
) -> None:
    deleted_at = datetime(2025, 6, 15, 12, 30, 45, tzinfo=UTC)
    organization_id = _seed_deleted_organization(db_session, deleted_at=deleted_at)
    _seed_audit(db_session, organization_id, action="identity.organization.deleted")
    _set_clock(client, datetime(2026, 6, 15, 12, 30, 44, 999999, tzinfo=UTC))

    response = client.post(
        f"/api/v1/organizations/{organization_id}/retained-audit-evidence/purge",
        headers=_headers(),
    )

    assert response.status_code == 409
    assert _count(db_session, organization_id) == 1


def test_retention_purge_uses_terminal_clock_purges_all_org_audit_and_is_idempotent(
    client: TestClient,
    db_session: Session,
) -> None:
    deleted_at = datetime(2025, 6, 15, 12, 30, 45, tzinfo=UTC)
    deadline = datetime(2026, 6, 15, 12, 30, 45, tzinfo=UTC)
    organization_id = _seed_deleted_organization(db_session, deleted_at=deleted_at)
    other_organization_id = uuid4()
    _seed_audit(db_session, organization_id, action="identity.organization.deleted")
    _seed_audit(db_session, organization_id, action="identity.organization.retained_after_terminal")
    _seed_audit(db_session, other_organization_id, action="other.organization.audit")
    _set_clock(client, deadline)

    path = f"/api/v1/organizations/{organization_id}/retained-audit-evidence/purge"
    first = client.post(path, headers=_headers())
    second = client.post(path, headers=_headers())

    assert first.status_code == 200, first.text
    assert first.json()["organization_id"] == str(organization_id)
    assert first.json()["policy_version"] == AUDIT_RETENTION_POLICY_VERSION
    assert first.json()["purged_count"] == 2
    assert first.json()["already_purged_verified"] is False
    assert datetime.fromisoformat(first.json()["terminal_deleted_at"].replace("Z", "+00:00")) == deleted_at
    assert datetime.fromisoformat(first.json()["retention_deadline"].replace("Z", "+00:00")) == deadline
    assert second.status_code == 200, second.text
    assert second.json()["purged_count"] == 0
    assert second.json()["already_purged_verified"] is False
    assert _count(db_session, organization_id) == 0
    assert _count(db_session, other_organization_id) == 1


def test_verification_only_mode_never_performs_first_destructive_purge(
    client: TestClient,
    db_session: Session,
) -> None:
    deleted_at = datetime(2025, 6, 15, tzinfo=UTC)
    organization_id = _seed_deleted_organization(db_session, deleted_at=deleted_at)
    _seed_audit(db_session, organization_id, action="identity.organization.deleted")
    _set_clock(client, datetime(2026, 6, 15, tzinfo=UTC))
    path = f"/api/v1/organizations/{organization_id}/retained-audit-evidence/purge"
    verify_headers = {
        **_headers(),
        "X-Kyrox-Retention-Require-Already-Purged": "true",
    }

    blocked = client.post(path, headers=verify_headers)
    assert blocked.status_code == 409
    assert _count(db_session, organization_id) == 1

    purged = client.post(path, headers=_headers())
    assert purged.status_code == 200, purged.text
    verified = client.post(path, headers=verify_headers)
    assert verified.status_code == 200, verified.text
    assert verified.json()["purged_count"] == 0
    assert verified.json()["already_purged_verified"] is True


def test_later_audit_activity_does_not_restart_terminal_retention_clock(
    client: TestClient,
    db_session: Session,
) -> None:
    deleted_at = datetime(2025, 3, 1, tzinfo=UTC)
    organization_id = _seed_deleted_organization(db_session, deleted_at=deleted_at)
    _seed_audit(db_session, organization_id, action="identity.organization.deleted")
    late = AuditLogModel(
        organization_id=organization_id,
        user_id=None,
        session_id=None,
        action="identity.organization.restore_reconciliation_observed",
        resource_type="organization",
        resource_id=str(organization_id),
        old_values=None,
        new_values=None,
        event_metadata=None,
        ip_address=None,
        user_agent=None,
        created_at=deleted_at + timedelta(days=300),
    )
    db_session.add(late)
    db_session.flush()
    _set_clock(client, datetime(2026, 3, 1, tzinfo=UTC))

    response = client.post(
        f"/api/v1/organizations/{organization_id}/retained-audit-evidence/purge",
        headers=_headers(),
    )

    assert response.status_code == 200, response.text
    assert response.json()["purged_count"] == 2
    assert _count(db_session, organization_id) == 0


def test_terminal_safe_audit_body_strips_payload_and_requires_control_identity() -> None:
    organization_id = uuid4()
    closure_execution_id = uuid4()
    body = RecordAuditEventRequest(
        action="fair_crm.organization_closure.completed",
        resource_type="organization_closure_execution",
        resource_id=str(closure_execution_id),
        old_values={"secret": "old"},
        new_values={"customer_name": "payload"},
        metadata={"provider_body": "payload"},
        ip_address="127.0.0.1",
        user_agent="sensitive-agent",
    )

    sanitized = _terminal_safe_body(organization_id, body)
    assert sanitized.resource_id == str(closure_execution_id)
    assert sanitized.old_values is None
    assert sanitized.new_values is None
    assert sanitized.metadata is None
    assert sanitized.ip_address is None
    assert sanitized.user_agent is None

    with pytest.raises(HTTPException) as exc_info:
        _terminal_safe_body(
            organization_id,
            RecordAuditEventRequest(
                action="fair_crm.customer.updated",
                resource_type="customer",
                resource_id=str(uuid4()),
                new_values={"display_name": "must-not-survive"},
            ),
        )
    assert exc_info.value.status_code == 409
