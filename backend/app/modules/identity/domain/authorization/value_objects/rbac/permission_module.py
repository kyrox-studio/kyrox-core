import re
from dataclasses import dataclass

_MODULE_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")

# Documented platform modules; product modules (e.g. fair_crm) use the same validation rules.
_PLATFORM_MODULES = frozenset({"audit", "core", "identity", "jobs", "notifications", "settings"})


@dataclass(frozen=True, slots=True)
class PermissionModule:
    value: str

    @classmethod
    def create(cls, raw: str) -> "PermissionModule":
        normalized = raw.strip().lower()
        if not normalized or not _MODULE_PATTERN.match(normalized):
            raise ValueError("Invalid permission module")
        return cls(value=normalized)


    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not self.value:
            raise ValueError("Permission module cannot be empty")
