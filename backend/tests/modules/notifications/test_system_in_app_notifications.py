from uuid import uuid4

from app.modules.identity.infrastructure.persistence.models import UserModel
from app.modules.notifications.infrastructure.persistence.models import PlatformNotificationModel
from app.modules.notifications.application.policy import NotificationPolicy
from app.modules.notifications.domain.exceptions import InvalidNotificationRequestError
from app.modules.notifications.domain.value_objects.notification_channel import NotificationChannel
from identity_api_test_helpers import login
from notifications_test_helpers import seed_user_with_notification_permissions
import pytest


def test_system_inbox_uses_real_super_admin_flag_and_no_org_context(client, db_session):
    user, _ = seed_user_with_notification_permissions(db_session)
    token = login(client, user.email)
    headers = {"Authorization": f"Bearer {token}"}
    proposal = {
        "subject": "Çalışma tamamlandı", "body": "Sonuçları inceleyin",
        "variables": {"path": "/fairs", "run_id": str(uuid4())},
        "idempotency_key": "completion-1",
    }
    assert client.post("/api/v1/system/notifications/in-app", headers=headers, json=proposal).status_code == 403
    assert client.get("/api/v1/system/notifications/in-app", headers=headers).status_code == 403
    db_session.get(UserModel, user.id.value).is_super_admin = True
    db_session.commit()
    sent = client.post("/api/v1/system/notifications/in-app", headers=headers, json=proposal)
    assert sent.status_code == 200, sent.text
    payload = sent.json()
    assert payload["created"] is True
    assert payload["notification"]["status"] == "sent"
    assert payload["notification"]["job_id"] is None
    assert payload["notification"]["organization_id"] is None
    replay = client.post("/api/v1/system/notifications/in-app", headers=headers, json=proposal)
    assert replay.json()["created"] is False
    changed = {**proposal, "body": "Different content"}
    assert client.post("/api/v1/system/notifications/in-app", headers=headers, json=changed).status_code == 409
    changed_navigation = {**proposal, "variables": {"path": "/other"}}
    assert client.post("/api/v1/system/notifications/in-app", headers=headers, json=changed_navigation).status_code == 409
    foreign = {**proposal, "recipient": str(uuid4()), "idempotency_key": "other-user"}
    assert client.post("/api/v1/system/notifications/in-app", headers=headers, json=foreign).status_code == 200
    inbox = client.get("/api/v1/system/notifications/in-app", headers=headers)
    assert inbox.status_code == 200
    assert len(inbox.json()) == 1
    assert inbox.json()[0]["variables"] == proposal["variables"]
    assert db_session.query(PlatformNotificationModel).count() == 2


def test_in_app_recipient_must_be_a_user_or_super_admin():
    with pytest.raises(InvalidNotificationRequestError):
        NotificationPolicy().normalize_recipient("someone@example.com", NotificationChannel.IN_APP)


def test_worker_delivery_has_purpose_separated_fail_closed_credential(client, monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "CORE_PRODUCT_NOTIFICATION_TOKEN", "x" * 32)
    proposal = {"subject": "Completed", "body": "Open results", "idempotency_key": "worker-1"}
    assert client.post("/api/v1/internal/notifications/in-app", json=proposal).status_code == 401
    assert client.post("/api/v1/internal/notifications/in-app", headers={"X-Kyrox-Notification-Token": "incorrect"}, json=proposal).status_code == 401
    response = client.post("/api/v1/internal/notifications/in-app", headers={"X-Kyrox-Notification-Token": "x" * 32}, json=proposal)
    assert response.status_code == 200
    assert response.json()["notification"]["organization_id"] is None
    assert response.json()["notification"]["channel"] == "in_app"
    monkeypatch.setattr(settings, "CORE_PRODUCT_NOTIFICATION_TOKEN", None)
    assert client.post("/api/v1/internal/notifications/in-app", json=proposal).status_code == 503


def test_organization_notification_endpoint_cannot_target_system_inbox(client, db_session):
    user, org = seed_user_with_notification_permissions(db_session)
    token = login(client, user.email)
    response = client.post(f"/api/v1/organizations/{org.id.value}/notifications/send",
        headers={"Authorization": f"Bearer {token}", "X-Organization-Id": str(org.id.value)},
        json={"channel": "in_app", "recipient": "super_admin", "subject": "Forbidden", "body": "Forbidden"})
    assert response.status_code == 400
    assert db_session.query(PlatformNotificationModel).count() == 0


def test_announcement_delivery_and_read_state_are_per_authenticated_user(client, db_session):
    from datetime import UTC, datetime

    from app.modules.audit.infrastructure.persistence.models import AuditLogModel
    from app.modules.identity.infrastructure.persistence.models import OrganizationModel

    sender, org = seed_user_with_notification_permissions(db_session)
    sender_row = db_session.get(UserModel, sender.id.value)
    sender_row.is_super_admin = True
    other_org = OrganizationModel(name="Another organization", slug=uuid4().hex, status="active")
    db_session.add(other_org)
    db_session.flush()
    recipient = UserModel(email="inbox-recipient@example.com", password_hash=sender_row.password_hash,
                          organization_id=other_org.id, status="active")
    inactive = UserModel(email="inbox-inactive@example.com", password_hash=sender_row.password_hash,
                         organization_id=org.id.value, status="active", deleted_at=datetime.now(UTC))
    db_session.add_all([recipient, inactive])
    db_session.commit()
    admin_headers = {"Authorization": f"Bearer {login(client, sender.email)}"}
    user_headers = {"Authorization": f"Bearer {login(client, recipient.email)}",
                    "X-Organization-Id": str(org.id.value)}
    endpoint = "/api/v1/system/notifications/announcements"
    inbox = "/api/v1/notifications/inbox"
    payload = {"subject": "Yeni özellik", "body": "Bildirim kutusu açıldı", "idempotency_key": str(uuid4())}

    assert client.get(inbox).status_code == 401
    assert client.get(endpoint).status_code == 401
    assert client.get(endpoint, headers=user_headers).status_code == 403
    assert client.post(endpoint, json=payload, headers=user_headers).status_code == 403
    assert client.post(endpoint, json={**payload, "subject": " "}, headers=admin_headers).status_code == 400
    sent = client.post(endpoint, json=payload, headers=admin_headers)
    assert sent.status_code == 200, sent.text
    assert sent.json()["recipient_count"] == 2
    assert sent.json()["created"] is True
    replay = client.post(endpoint, json=payload, headers=admin_headers)
    assert replay.json() == {**sent.json(), "created": False}
    assert client.post(endpoint, json={**payload, "body": "Changed"}, headers=admin_headers).status_code == 409
    audit = db_session.query(AuditLogModel).filter_by(action="notifications.announcement.sent").one()
    assert audit.resource_id == sent.json()["id"]
    assert audit.user_id == sender.id.value
    assert audit.event_metadata == {"recipient_count": 2}
    history = client.get(f"{endpoint}?limit=1", headers=admin_headers)
    assert history.status_code == 200, history.text
    assert history.json()["total"] == 1
    announcement, = history.json()["items"]
    assert announcement["id"] == sent.json()["id"]
    assert announcement["subject"] == payload["subject"]
    assert announcement["body"] == payload["body"]
    assert announcement["recipient_count"] == 2
    assert announcement["created_at"]
    assert client.get(f"{endpoint}?offset=1", headers=admin_headers).json() == {
        "total": 1, "items": [],
    }

    user_messages = client.get(inbox, headers=user_headers).json()
    admin_messages = client.get(inbox, headers=admin_headers).json()
    assert user_messages["unread_count"] == admin_messages["unread_count"] == 1
    user_message, = user_messages["items"]
    admin_message, = admin_messages["items"]
    assert user_message["subject"] == payload["subject"]
    assert user_message["body"] == payload["body"]
    assert user_message["is_announcement"] is True
    assert client.put(f"{inbox}/{admin_message['id']}/read", headers=user_headers).status_code == 404
    assert client.put(f"{inbox}/{user_message['id']}/read", headers=user_headers).status_code == 204
    assert client.put(f"{inbox}/{user_message['id']}/read", headers=user_headers).status_code == 204
    after = client.get(inbox, headers=user_headers).json()
    assert after["unread_count"] == 0
    assert after["items"][0]["read_at"] is not None
    assert client.get(inbox, headers=admin_headers).json()["unread_count"] == 1

    db_session.add_all([
        PlatformNotificationModel(
            id=uuid4(), channel="in_app", recipient=str(recipient.id), status="sent",
            subject=f"Bildirim {index}", body="Mesaj", created_at=datetime(2026, 11, 15, 9, index, tzinfo=UTC),
        )
        for index in range(7)
    ])
    db_session.commit()
    preview = client.get(f"{inbox}?read_state=unread&limit=5", headers=user_headers).json()
    assert [item["subject"] for item in preview["items"]] == [f"Bildirim {i}" for i in range(6, 1, -1)]
    assert preview["total"] == preview["unread_count"] == 7
    next_page = client.get(f"{inbox}?read_state=unread&limit=5&offset=5", headers=user_headers).json()
    assert [item["subject"] for item in next_page["items"]] == ["Bildirim 1", "Bildirim 0"]
    read_history = client.get(f"{inbox}?read_state=read", headers=user_headers).json()
    assert read_history["total"] == 1
    assert read_history["unread_count"] == 7
    assert read_history["items"][0]["id"] == user_message["id"]
    assert client.get(inbox, headers=user_headers).json()["total"] == 8
    assert client.get(f"{inbox}?read_state=read", headers=admin_headers).json()["total"] == 0
    assert client.get(f"{inbox}?read_state=invalid", headers=user_headers).status_code == 422
