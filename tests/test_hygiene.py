"""Guard rails: the design promises no security stubs and no stray SQL DDL."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parent.parent / "fairvote"
FORBIDDEN_MARKERS = ("TODO", "FIXME", "XXX", "HACK")


def _python_files() -> list[Path]:
    return sorted(PACKAGE_ROOT.rglob("*.py"))


def test_no_placeholder_markers_in_the_package() -> None:
    offenders: list[str] = []
    for path in _python_files():
        text = path.read_text(encoding="utf-8")
        for marker in FORBIDDEN_MARKERS:
            if marker in text:
                offenders.append(f"{path.relative_to(PACKAGE_ROOT.parent)}: {marker}")
    assert not offenders, "unfinished security work must be an explicit refusal: " + str(
        offenders
    )


@pytest.mark.parametrize(
    "store_name", ["registry", "polls", "ballot_box", "audit_log"]
)
def test_packaged_ddl_executes(store_name: str) -> None:
    """Every packaged .sql file must run cleanly against an empty database."""
    path = PACKAGE_ROOT / "ddl" / "sqlite" / f"{store_name}.sql"
    connection = sqlite3.connect(":memory:")
    connection.execute("PRAGMA foreign_keys=ON")
    try:
        connection.executescript(path.read_text(encoding="utf-8"))
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'"
            )
        }
    finally:
        connection.close()
    assert tables, f"{store_name}.sql created no tables"


def test_no_sql_text_in_python_modules() -> None:
    """Schema lives in .sql files; Python code must not carry CREATE TABLE."""
    offenders = [
        str(path)
        for path in _python_files()
        if "CREATE TABLE" in path.read_text(encoding="utf-8")
    ]
    assert not offenders, f"schema must stay in fairvote/ddl: {offenders}"
