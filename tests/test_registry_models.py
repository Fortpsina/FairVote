"""The registry table definitions must mirror the packaged DDL."""

from __future__ import annotations

import pytest

from fairvote.registry import models

TABLES = [
    (models.district_table, "district"),
    (models.app_user_table, "app_user"),
    (models.recovery_code_table, "recovery_code"),
    (models.session_table, "session"),
    (models.verification_request_table, "verification_request"),
    (models.participation_table, "participation"),
    (models.rate_counter_table, "rate_counter"),
    (models.auth_event_table, "auth_event"),
]


@pytest.mark.parametrize(("table", "sql_name"), TABLES)
def test_table_columns_match_ddl(stores, table, sql_name: str) -> None:
    with stores["registry"].engine.connect() as connection:
        declared = [
            row[1] for row in connection.exec_driver_sql(f"PRAGMA table_info({sql_name})")
        ]
    assert [column.name for column in table.columns] == declared


def test_role_column_exists_and_defaults_to_voter(stores) -> None:
    with stores["registry"].engine.connect() as connection:
        defaults = {
            row[1]: row[4]
            for row in connection.exec_driver_sql("PRAGMA table_info(app_user)")
        }
    assert defaults["role"] == "'voter'"
