"""SQLAlchemy table definitions must mirror the packaged DDL."""

from __future__ import annotations

import pytest

from fairvote.audit.models import checkpoint_table, entry_table


@pytest.mark.parametrize(
    ("table", "sql_name"),
    [(entry_table, "entry"), (checkpoint_table, "checkpoint")],
)
def test_table_columns_match_ddl(stores, table, sql_name: str) -> None:
    with stores["audit_log"].engine.connect() as connection:
        declared = [
            row[1] for row in connection.exec_driver_sql(f"PRAGMA table_info({sql_name})")
        ]
    assert [column.name for column in table.columns] == declared


def test_primary_keys_match_ddl(stores) -> None:
    with stores["audit_log"].engine.connect() as connection:
        rows = connection.exec_driver_sql("PRAGMA table_info(entry)").all()
    primary_keys = [row[1] for row in rows if row[5]]
    assert primary_keys == ["seq"]
