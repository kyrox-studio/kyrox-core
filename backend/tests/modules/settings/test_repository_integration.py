import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.modules.settings.application.commands import UpsertSettingCommand
from app.modules.settings.application.upsert_setting import UpsertSettingUseCase
from app.modules.settings.domain.entities import Setting
from app.modules.settings.domain.value_objects.setting_key import SettingKey
from app.modules.settings.domain.value_objects.setting_scope import SettingScope
from app.modules.settings.infrastructure.repositories import SqlAlchemySettingRepository


def test_repository_upsert_and_get_roundtrip(db_session: Session) -> None:
    repository = SqlAlchemySettingRepository(db_session)
    org_id = uuid.uuid4()
    now = datetime.now(UTC)
    setting = Setting(
        id=uuid.uuid4(),
        scope=SettingScope.ORGANIZATION,
        organization_id=org_id,
        key=SettingKey.create("fair_crm.pipeline.default_stage"),
        value={"enabled": True},
        created_at=now,
        updated_at=now,
    )

    saved = repository.upsert(setting)
    db_session.commit()

    loaded = repository.get(
        SettingScope.ORGANIZATION,
        org_id,
        SettingKey.create("fair_crm.pipeline.default_stage"),
    )
    assert loaded is not None
    assert loaded.id == saved.id
    assert loaded.value == {"enabled": True}


def test_repository_isolates_organization_settings(db_session: Session) -> None:
    repository = SqlAlchemySettingRepository(db_session)
    org_a = uuid.uuid4()
    org_b = uuid.uuid4()
    now = datetime.now(UTC)
    key = SettingKey.create("fair_crm.pipeline.default_stage")

    repository.upsert(
        Setting(
            id=uuid.uuid4(),
            scope=SettingScope.ORGANIZATION,
            organization_id=org_a,
            key=key,
            value={"org": "a"},
            created_at=now,
            updated_at=now,
        )
    )
    repository.upsert(
        Setting(
            id=uuid.uuid4(),
            scope=SettingScope.ORGANIZATION,
            organization_id=org_b,
            key=key,
            value={"org": "b"},
            created_at=now,
            updated_at=now,
        )
    )
    db_session.commit()

    org_a_settings = repository.list_by_scope(SettingScope.ORGANIZATION, org_a)
    assert len(org_a_settings) == 1
    assert org_a_settings[0].value == {"org": "a"}


def test_repository_stores_system_settings_with_null_organization_id(db_session: Session) -> None:
    repository = SqlAlchemySettingRepository(db_session)
    now = datetime.now(UTC)
    use_case = UpsertSettingUseCase(repository)

    result = use_case.execute(
        UpsertSettingCommand(
            scope=SettingScope.SYSTEM,
            organization_id=None,
            key="kyrox.platform.maintenance_mode",
            value={"enabled": False},
        )
    )
    db_session.commit()

    loaded = repository.get(
        SettingScope.SYSTEM,
        None,
        SettingKey.create("kyrox.platform.maintenance_mode"),
    )
    assert loaded is not None
    assert loaded.organization_id is None
    assert loaded.value == {"enabled": False}
    assert result.key == "kyrox.platform.maintenance_mode"


def test_repository_delete_returns_false_when_missing(db_session: Session) -> None:
    repository = SqlAlchemySettingRepository(db_session)
    deleted = repository.delete(
        SettingScope.SYSTEM,
        None,
        SettingKey.create("kyrox.platform.maintenance_mode"),
    )
    assert deleted is False
