from fastapi import Depends
from sqlalchemy.orm import Session as DbSession

from app.db.session import get_db
from app.modules.settings.application.delete_setting import DeleteSettingUseCase
from app.modules.settings.application.get_setting import GetSettingUseCase
from app.modules.settings.application.list_settings import ListSettingsUseCase
from app.modules.settings.application.policy import SettingPolicy
from app.modules.settings.application.upsert_setting import UpsertSettingUseCase
from app.modules.settings.domain.ports import SettingRepository
from app.modules.settings.infrastructure.repositories import SqlAlchemySettingRepository


def get_setting_repository(db: DbSession = Depends(get_db, scope="function")) -> SettingRepository:
    return SqlAlchemySettingRepository(db)


def get_setting_policy() -> SettingPolicy:
    return SettingPolicy()


def get_get_setting_use_case(
    setting_repository: SettingRepository = Depends(get_setting_repository),
    setting_policy: SettingPolicy = Depends(get_setting_policy),
) -> GetSettingUseCase:
    return GetSettingUseCase(
        setting_repository=setting_repository,
        setting_policy=setting_policy,
    )


def get_list_settings_use_case(
    setting_repository: SettingRepository = Depends(get_setting_repository),
    setting_policy: SettingPolicy = Depends(get_setting_policy),
) -> ListSettingsUseCase:
    return ListSettingsUseCase(
        setting_repository=setting_repository,
        setting_policy=setting_policy,
    )


def get_upsert_setting_use_case(
    setting_repository: SettingRepository = Depends(get_setting_repository),
    setting_policy: SettingPolicy = Depends(get_setting_policy),
) -> UpsertSettingUseCase:
    return UpsertSettingUseCase(
        setting_repository=setting_repository,
        setting_policy=setting_policy,
    )


def get_delete_setting_use_case(
    setting_repository: SettingRepository = Depends(get_setting_repository),
    setting_policy: SettingPolicy = Depends(get_setting_policy),
) -> DeleteSettingUseCase:
    return DeleteSettingUseCase(
        setting_repository=setting_repository,
        setting_policy=setting_policy,
    )
