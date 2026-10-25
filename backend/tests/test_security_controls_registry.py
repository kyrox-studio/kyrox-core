"""Gate: Core security control registry (.kyrox/security-controls.json).

Rules and evidence live in kyrox-platform/standards/security/SECURITY_PROGRAM.md.
This test proves only that every SEC-01..SEC-22 control is classified, that N/A
has a concrete reason, that referenced tests exist, that open gaps are explicit,
and that every backend/app surface is registered. Whether the referenced tests
pass is proven by this same pytest run; it is not evidence that Core is secure.
"""

from __future__ import annotations

import json
import re
import warnings
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = REPO_ROOT / ".kyrox" / "security-controls.json"
APP_ROOT = REPO_ROOT / "backend" / "app"

SECURITY_CONTROLS = tuple(f"SEC-{index:02d}" for index in range(1, 23))
NA_MIN_REASON = 20
GAP_MIN_TEXT = 20
# SECURITY_PROGRAM.md §1.5: these are explicitly not N/A rationales.
REJECTED_NA_RE = re.compile(
    r"\b(?:ui\s+gizli|hidden\s+in\s+(?:the\s+)?ui|ui\s+hidden|admin\s+kullan[ıi]yor|"
    r"only\s+admins?\s+use|testler\s+ye[şs]il|tests?\s+(?:are\s+)?(?:green|pass(?:ing)?)|"
    r"sonra\s+bakar[ıi]z|check\s+later|tbd|todo)\b",
    re.IGNORECASE,
)
PY_TEST_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def app_surfaces(app_root: Path) -> set[str]:
    """Top-level backend/app packages/files plus each module package."""
    surfaces: set[str] = set()
    for entry in app_root.iterdir():
        if entry.name.startswith(("_", ".")):
            continue
        if entry.is_dir() and entry.name != "modules":
            surfaces.add(entry.relative_to(REPO_ROOT).as_posix())
        elif entry.is_file() and entry.suffix == ".py":
            surfaces.add(entry.relative_to(REPO_ROOT).as_posix())
    modules = app_root / "modules"
    if modules.is_dir():
        for entry in modules.iterdir():
            if entry.is_dir() and not entry.name.startswith(("_", ".")):
                surfaces.add(entry.relative_to(REPO_ROOT).as_posix())
    return surfaces


def reference_error(reference: Any, root: Path) -> str | None:
    if not isinstance(reference, str) or not reference.strip():
        return "must be a non-empty string"
    file_part, _, symbol_part = reference.partition("::")
    relative = Path(file_part)
    if relative.is_absolute() or ".." in relative.parts:
        return "path must be repository-relative"
    target = root / relative
    if not target.is_file():
        return f"file '{file_part}' does not exist"
    if not symbol_part:
        return None
    symbol = symbol_part.split("::")[-1].split("[", 1)[0]
    if not PY_TEST_NAME_RE.fullmatch(symbol):
        return f"'{symbol}' is not a valid Python test name"
    text = target.read_text(encoding="utf-8")
    if not re.search(rf"^\s*(?:async\s+)?def\s+{re.escape(symbol)}\s*\(", text, re.MULTILINE):
        return f"test '{symbol}' is not defined in '{file_part}'"
    return None




def validate_registry(data: Any, *, root: Path, surfaces: set[str]) -> tuple[list[str], list[str]]:
    """Return (errors, open_gaps)."""
    errors: list[str] = []
    gaps: list[str] = []
    if not isinstance(data, dict):
        return ["registry root must be an object"], gaps
    if data.get("version") != 1:
        errors.append("version must be 1")
    if data.get("project") != "kyrox-core":
        errors.append("project must be kyrox-core")

    registered = data.get("surfaces")
    if not isinstance(registered, list) or not all(isinstance(item, str) for item in registered):
        errors.append("surfaces must be an array of paths")
        registered = []
    for surface in sorted(surfaces - set(registered)):
        errors.append(
            f"surface '{surface}' is not registered; classify its SEC impact and add it to surfaces"
        )
    for surface in sorted(set(registered) - surfaces):
        errors.append(f"registered surface '{surface}' no longer exists")

    controls = data.get("controls")
    if not isinstance(controls, dict):
        return [*errors, "controls must be an object"], gaps
    missing = [control for control in SECURITY_CONTROLS if control not in controls]
    if missing:
        errors.append(f"controls missing: {', '.join(missing)}")
    unknown = sorted(set(controls) - set(SECURITY_CONTROLS))
    if unknown:
        errors.append(f"controls has unknown ids: {', '.join(unknown)}")

    for control in SECURITY_CONTROLS:
        entry = controls.get(control)
        if entry is None:
            continue
        if not isinstance(entry, dict):
            errors.append(f"{control} must be an object")
            continue
        status = entry.get("status")
        tests = entry.get("tests", [])
        gap = entry.get("gap")
        if status == "na":
            reason = entry.get("reason")
            if not isinstance(reason, str) or len(reason.strip()) < NA_MIN_REASON:
                errors.append(f"{control}=na requires a concrete architectural reason (>= {NA_MIN_REASON} chars)")
            elif REJECTED_NA_RE.search(reason):
                errors.append(f"{control}=na reason is not an accepted N/A rationale")
            if tests or gap:
                errors.append(f"{control}=na must not list tests or gap")
        elif status == "required":
            if not isinstance(tests, list):
                errors.append(f"{control}.tests must be an array")
                continue
            if gap is not None and (not isinstance(gap, str) or len(gap.strip()) < GAP_MIN_TEXT):
                errors.append(f"{control}.gap must describe the missing evidence (>= {GAP_MIN_TEXT} chars)")
            if not tests and gap is None:
                errors.append(f"{control}=required needs test references or an explicit gap")
            if gap is not None:
                gaps.append(control)
            for index, reference in enumerate(tests):
                problem = reference_error(reference, root)
                if problem:
                    errors.append(f"{control}.tests[{index}] {problem}")
        else:
            errors.append(f"{control}.status must be 'required' or 'na'")
    return errors, gaps


def _registry() -> dict:
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def _errors(data: dict, surfaces: set[str] | None = None) -> list[str]:
    errors, _ = validate_registry(
        data, root=REPO_ROOT, surfaces=app_surfaces(APP_ROOT) if surfaces is None else surfaces
    )
    return errors


def test_core_security_registry_is_complete_and_resolves() -> None:
    errors, gaps = validate_registry(_registry(), root=REPO_ROOT, surfaces=app_surfaces(APP_ROOT))
    assert errors == [], "\n".join(errors)
    if gaps:
        warnings.warn(
            "Open Core security evidence gaps (SECURITY_PROGRAM.md): " + ", ".join(gaps),
            stacklevel=1,
        )


def test_unregistered_new_module_fails() -> None:
    surfaces = app_surfaces(APP_ROOT) | {"backend/app/modules/billing"}
    assert any("'backend/app/modules/billing' is not registered" in e for e in _errors(_registry(), surfaces))


def test_removed_surface_fails() -> None:
    data = _registry()
    data["surfaces"].append("backend/app/modules/ghost")
    assert any("'backend/app/modules/ghost' no longer exists" in e for e in _errors(data))


def test_missing_control_fails() -> None:
    data = _registry()
    del data["controls"]["SEC-07"]
    assert any("controls missing: SEC-07" in e for e in _errors(data))


def test_unknown_control_fails() -> None:
    data = _registry()
    data["controls"]["SEC-99"] = {"status": "na", "reason": "x" * 30}
    assert any("unknown ids: SEC-99" in e for e in _errors(data))


@pytest.mark.parametrize("reason", [None, "", "No upload."])
def test_na_without_concrete_reason_fails(reason: str | None) -> None:
    data = _registry()
    entry: dict = {"status": "na"}
    if reason is not None:
        entry["reason"] = reason
    data["controls"]["SEC-07"] = entry
    assert any("SEC-07=na requires a concrete" in e for e in _errors(data))


@pytest.mark.parametrize(
    "reason",
    [
        "UI gizli olduğu için bu kontrol gerekmez.",
        "Testler yeşil, ek kontrol gerekmiyor.",
        "Sonra bakarız, şimdilik kapsam dışı.",
        "TBD after the release is finished.",
    ],
)
def test_na_with_rejected_rationale_fails(reason: str) -> None:
    data = _registry()
    data["controls"]["SEC-07"] = {"status": "na", "reason": reason}
    assert any("SEC-07=na reason is not an accepted" in e for e in _errors(data))


def test_required_without_tests_or_gap_fails() -> None:
    data = _registry()
    data["controls"]["SEC-05"] = {"status": "required", "tests": []}
    assert any("SEC-05=required needs test references or an explicit gap" in e for e in _errors(data))


def test_vague_gap_fails() -> None:
    data = _registry()
    data["controls"]["SEC-05"] = {"status": "required", "tests": [], "gap": "later"}
    assert any("SEC-05.gap must describe" in e for e in _errors(data))


@pytest.mark.parametrize(
    ("reference", "expected"),
    [
        ("backend/tests/does_not_exist.py::test_x", "does not exist"),
        ("backend/tests/test_health.py::test_health_gone", "is not defined"),
        ("../outside.py", "repository-relative"),
        ("backend/tests/test_health.py::not-a-name", "not a valid Python test name"),
    ],
)
def test_broken_test_reference_fails(reference: str, expected: str) -> None:
    data = _registry()
    data["controls"]["SEC-01"]["tests"] = [reference]
    errors = _errors(data)
    assert any("SEC-01.tests[0]" in e and expected in e for e in errors), errors


def test_valid_minimal_registry_passes() -> None:
    data = deepcopy(_registry())
    for control in SECURITY_CONTROLS:
        data["controls"][control] = {
            "status": "required",
            "tests": ["backend/tests/test_security_controls_registry.py::test_missing_control_fails"],
        }
    assert _errors(data) == []
