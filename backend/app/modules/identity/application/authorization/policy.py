from dataclasses import dataclass

from app.modules.identity.domain.authorization.exceptions import InvalidPermissionError
from app.modules.identity.domain.authorization.value_objects.rbac.permission_code import PermissionCode


@dataclass(frozen=True, slots=True)
class PermissionPolicy:
    def normalize(self, raw: str) -> PermissionCode:
        try:
            return PermissionCode.create(raw)
        except ValueError as exc:
            raise InvalidPermissionError("Invalid permission code") from exc

    def validate(self, raw: str) -> None:
        self.normalize(raw)


