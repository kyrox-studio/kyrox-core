import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.modules.identity.infrastructure.organization.persistence.models.organization import OrganizationModel
from app.modules.identity.infrastructure.persistence.models import UserModel

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from identity_api_test_helpers import seed_authenticated_user, seed_user_with_org_permission


CONFIGURED_LIFECYCLE_TOKEN = "lifecycle-test-credential-" + "s" * 32
PUBLIC_DEFAULT_LIFECYCLE_TOKEN = "dev-insecure-product-lifecycle-token-change-me"


@pytest.fixture(autouse=True)
def _configured_lifecycle_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "CORE_PRODUCT_LIFECYCLE_TOKEN", CONFIGURED_LIFECYCLE_TOKEN)


def _login(client: TestClient, email: str) -> str:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "Password123!"},
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def _login_super_admin(client: TestClient, db_session: Session) -> str:
    user = seed_authenticated_user(db_session)
    user_model = db_session.get(UserModel, user.id.value)
    assert user_model is not None
    user_model.is_super_admin = True
    db_session.commit()
    return _login(client, user.email.value)


def _lifecycle_headers() -> dict[str, str]:
    return {"X-Kyrox-Product-Lifecycle-Token": settings.CORE_PRODUCT_LIFECYCLE_TOKEN}


def _pop_updated_at(snapshot: dict[str, object]) -> datetime:
    raw = snapshot.pop("updated_at")
    assert isinstance(raw, str)
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


def test_product_lifecycle_snapshot_requires_dedicated_credential(
    client: TestClient,
    db_session: Session,
) -> None:
    seed = seed_user_with_org_permission(
        db_session,
        permission_code="identity.organizations.read",
    )
    path = f"/api/v1/organizations/{seed.org.id.value}/lifecycle-snapshot"

    missing_response = client.get(path)
    wrong_response = client.get(
        path,
        headers={"X-Kyrox-Product-Lifecycle-Token": "wrong-lifecycle-token"},
    )

    assert missing_response.status_code == 401
    assert wrong_response.status_code == 401


def test_product_lifecycle_settings_have_no_default_secret() -> None:
    from app.core.config import Settings

    assert Settings.model_fields["CORE_PRODUCT_LIFECYCLE_TOKEN"].default is None


@pytest.mark.parametrize(
    "configured",
    [None, "", "short-lifecycle-token", PUBLIC_DEFAULT_LIFECYCLE_TOKEN],
)
def test_product_lifecycle_snapshot_fails_closed_without_secure_credential(
    client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    configured: str | None,
) -> None:
    seed = seed_user_with_org_permission(
        db_session,
        permission_code="identity.organizations.read",
    )
    monkeypatch.setattr(settings, "CORE_PRODUCT_LIFECYCLE_TOKEN", configured)
    path = f"/api/v1/organizations/{seed.org.id.value}/lifecycle-snapshot"

    public_default_response = client.get(
        path,
        headers={"X-Kyrox-Product-Lifecycle-Token": PUBLIC_DEFAULT_LIFECYCLE_TOKEN},
    )
    missing_response = client.get(path)

    assert public_default_response.status_code == 503
    assert missing_response.status_code == 503
    assert "status" not in public_default_response.json()


def test_product_lifecycle_snapshot_reports_active_and_suspended_state(
    client: TestClient,
    db_session: Session,
) -> None:
    seed = seed_user_with_org_permission(
        db_session,
        permission_code="identity.organizations.read",
    )

    active_response = client.get(
        f"/api/v1/organizations/{seed.org.id.value}/lifecycle-snapshot",
        headers=_lifecycle_headers(),
    )
    assert active_response.status_code == 200, active_response.text
    active_snapshot = active_response.json()
    active_updated_at = _pop_updated_at(active_snapshot)
    assert active_snapshot == {
        "organization_id": str(seed.org.id.value),
        "status": "active",
        "work_allowed": True,
        "is_deleted": False,
        "deleted_at": None,
    }

    super_admin_token = _login_super_admin(client, db_session)
    suspend_response = client.post(
        f"/api/v1/organizations/{seed.org.id.value}/suspend",
        headers={
            "Authorization": f"Bearer {super_admin_token}",
            "X-Organization-Id": str(seed.org.id.value),
        },
    )
    assert suspend_response.status_code == 200, suspend_response.text

    suspended_response = client.get(
        f"/api/v1/organizations/{seed.org.id.value}/lifecycle-snapshot",
        headers=_lifecycle_headers(),
    )
    assert suspended_response.status_code == 200, suspended_response.text
    suspended_snapshot = suspended_response.json()
    suspended_updated_at = _pop_updated_at(suspended_snapshot)
    assert suspended_snapshot == {
        "organization_id": str(seed.org.id.value),
        "status": "suspended",
        "work_allowed": False,
        "is_deleted": False,
        "deleted_at": None,
    }
    assert suspended_updated_at >= active_updated_at


def test_product_lifecycle_snapshot_distinguishes_soft_deleted_from_unknown(
    client: TestClient,
    db_session: Session,
) -> None:
    seed = seed_user_with_org_permission(
        db_session,
        permission_code="identity.organizations.read",
    )
    deleted_at = datetime.now(timezone.utc)
    organization_model = db_session.get(OrganizationModel, seed.org.id.value)
    assert organization_model is not None
    organization_model.deleted_at = deleted_at
    db_session.commit()

    deleted_response = client.get(
        f"/api/v1/organizations/{seed.org.id.value}/lifecycle-snapshot",
        headers=_lifecycle_headers(),
    )
    assert deleted_response.status_code == 200, deleted_response.text
    deleted_snapshot = deleted_response.json()
    _pop_updated_at(deleted_snapshot)
    assert deleted_snapshot["organization_id"] == str(seed.org.id.value)
    assert deleted_snapshot["status"] == "active"
    assert deleted_snapshot["work_allowed"] is False
    assert deleted_snapshot["is_deleted"] is True
    assert deleted_snapshot["deleted_at"] is not None

    unknown_response = client.get(
        f"/api/v1/organizations/{uuid4()}/lifecycle-snapshot",
        headers=_lifecycle_headers(),
    )
    assert unknown_response.status_code == 404