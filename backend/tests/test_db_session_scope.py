"""get_db must commit before the response is sent.

FastAPI's default ("request") scope runs the code after ``yield`` once the
response has already gone out. ``get_db`` commits there, so a fast client could
send its next request (activation, password reset, a call with a fresh access
token) before the row was committed and get 400/401. ``scope="function"`` ends
the dependency, and so the commit, before the response.
"""

import re
from pathlib import Path

APP_DIR = Path(__file__).resolve().parents[1] / "app"
GET_DB_DEPENDS = re.compile(r"Depends\(\s*get_db\b(?P<args>[^)]*)\)")


def test_every_get_db_dependency_commits_before_response() -> None:
    offenders: list[str] = []
    found = 0
    for path in sorted(APP_DIR.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for match in GET_DB_DEPENDS.finditer(text):
            found += 1
            if 'scope="function"' not in match.group("args"):
                line = text.count("\n", 0, match.start()) + 1
                offenders.append(f"{path.relative_to(APP_DIR.parent)}:{line}")
    assert found > 0
    assert offenders == []
