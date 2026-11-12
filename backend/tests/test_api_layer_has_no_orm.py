"""BACKEND_ARCHITECTURE_STANDARDS §3.4, §4.2, §8: layer boundaries.

- ``api``: route and dependency modules must not import ORM persistence models or
  build/execute SQL. Dependency modules may still wire SQLAlchemy repositories
  (composition root).
- ``application`` and ``domain``: no ORM models, no SQLAlchemy, no ``api`` imports.
- ``infrastructure``: no ``api`` imports. Only infrastructure performs queries (§8).
"""

from __future__ import annotations

import re
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[1] / "app"

FORBIDDEN = (
    (re.compile(r"persistence\.models\s+import"), "imports ORM persistence models"),
    (re.compile(r"from sqlalchemy import[^\n]*\b(select|delete|update|insert|func|or_|and_)\b"), "imports SQL builders"),
    (re.compile(r"\b(db|session|self\._db|self\._session)\.(get|scalars|scalar|execute|query)\("), "runs a query"),
)


def _api_files() -> list[Path]:
    return sorted(
        path
        for path in APP_ROOT.glob("modules/*/api/**/*.py")
        if "__pycache__" not in path.parts
    )


def test_api_layer_has_no_orm_models_or_queries() -> None:
    violations: list[str] = []
    for path in _api_files():
        source = path.read_text(encoding="utf-8")
        for pattern, reason in FORBIDDEN:
            for match in pattern.finditer(source):
                line = source.count("\n", 0, match.start()) + 1
                violations.append(f"{path.relative_to(APP_ROOT.parent).as_posix()}:{line} {reason}")
    assert not violations, "API layer must stay thin:\n - " + "\n - ".join(violations)


def test_api_scan_covers_route_modules() -> None:
    names = {path.relative_to(APP_ROOT).as_posix() for path in _api_files()}
    assert "modules/identity/api/role_management/routes.py" in names
    assert "modules/identity/api/user_management/routes.py" in names


LAYER_FORBIDDEN = {
    "application": (
        (re.compile(r"persistence\.models\s+import"), "imports ORM persistence models"),
        (re.compile(r"^from sqlalchemy", re.M), "imports SQLAlchemy"),
        (re.compile(r"from app\.modules\.[a-z_]+\.api"), "imports the api layer"),
    ),
    "domain": (
        (re.compile(r"persistence\.models\s+import"), "imports ORM persistence models"),
        (re.compile(r"^from sqlalchemy", re.M), "imports SQLAlchemy"),
        (re.compile(r"from app\.modules\.[a-z_]+\.api"), "imports the api layer"),
    ),
    "infrastructure": (
        (re.compile(r"from app\.modules\.[a-z_]+\.api"), "imports the api layer"),
    ),
}


def test_application_domain_and_infrastructure_respect_layer_imports() -> None:
    violations: list[str] = []
    for layer, rules in LAYER_FORBIDDEN.items():
        for path in sorted(APP_ROOT.glob(f"modules/*/{layer}/**/*.py")):
            if "__pycache__" in path.parts:
                continue
            source = path.read_text(encoding="utf-8")
            for pattern, reason in rules:
                for match in pattern.finditer(source):
                    line = source.count("\n", 0, match.start()) + 1
                    violations.append(f"{path.relative_to(APP_ROOT.parent).as_posix()}:{line} {reason}")
    assert not violations, "Layer boundary violations:\n - " + "\n - ".join(violations)
