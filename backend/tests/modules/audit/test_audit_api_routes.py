import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "identity"))
from identity_api_test_helpers import login, seed_user_with_org_permission

from app.modules.audit.domain.entities import AuditLog
from app.modules.audit.infrastructure.repositories import SqlAlchemyAuditLogRepository


def _seed_audit_log(db_session: Session, organization_id: uuid.UUID, action: str) -> None:
    repository = SqlAlchemyAuditLogRepository(db_session)
    repository.append(
        AuditLog(
            id=uuid.uuid4(),
            organization_id=organization_id,
            user_id=uuid.uuid4(),
            session_id=uuid.uuid4(),
            action=action,
            resource_type="organization",
            resource_id=str(uuid.uuid4()),
            old_values=None,
            new_values=None,
            metadata={"source": "test"},
            ip_address="127.0.0.1",
            user_agent="pytest",
            created_at=datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC),
        )
    )
    db_session.commit()


def test_list_organization_audit_logs_requires_permission(
    client: TestClient,
    db_session: Session,
) -> None:
    seed = seed_user_with_org_permission(db_session, permission_code="audit.logs.read")
    _seed_audit_log(db_session, seed.org.id.value, "identity.organization.create")
    token = login(client, seed.user.email)

    response = client.get(
        f"/api/v1/organizations/{seed.org.id.value}/audit-logs",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Organization-Id": str(seed.org.id.value),
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    # The reader's own sign-in is audited too (F-C13); newest first.
    assert [item["action"] for item in body["items"]] == [
        "identity.user.login",
        "identity.organization.create",
    ]


def test_list_organization_audit_logs_scope_mismatch_returns_400(
    client: TestClient,
    db_session: Session,
) -> None:
    seed = seed_user_with_org_permission(db_session, permission_code="audit.logs.read")
    token = login(client, seed.user.email)

    response = client.get(
        f"/api/v1/organizations/{uuid.uuid4()}/audit-logs",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Organization-Id": str(seed.org.id.value),
        },
    )

    assert response.status_code == 400


def test_list_organization_audit_logs_rejects_invalid_filter(
    client: TestClient,
    db_session: Session,
) -> None:
    seed = seed_user_with_org_permission(db_session, permission_code="audit.logs.read")
    token = login(client, seed.user.email)

    response = client.get(
        f"/api/v1/organizations/{seed.org.id.value}/audit-logs",
        params={"action": "identity.organization.create", "action_prefix": "identity"},
        headers={
            "Authorization": f"Bearer {token}",
            "X-Organization-Id": str(seed.org.id.value),
        },
    )

    assert response.status_code == 400
