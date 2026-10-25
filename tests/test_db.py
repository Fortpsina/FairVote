"""Stores: PRAGMAs, transactions, and the schema invariants the design promises."""

from __future__ import annotations

import pytest
from sqlalchemy.exc import DatabaseError as SADatabaseError

from fairvote.db import STORE_NAMES, apply_ddl, read_tx, table_names, write_tx


def test_pragmas_are_applied(stores) -> None:
    for store in stores.values():
        with store.engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA journal_mode").scalar() == "wal"
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
            assert connection.exec_driver_sql("PRAGMA busy_timeout").scalar() == 5000


def test_all_four_stores_have_their_tables(stores) -> None:
    expected = {
        "registry": {
            "district",
            "app_user",
            "recovery_code",
            "session",
            "verification_request",
            "participation",
            "rate_counter",
            "auth_event",
        },
        "polls": {
            "poll",
            "contest",
            "option",
            "poll_district",
            "eligibility_commitment",
            "poll_revision",
            "admin_action",
        },
        "ballot_box": {"ballot_queue", "ballot", "ballot_batch", "published_key"},
        "audit_log": {"entry", "checkpoint"},
    }
    for name in STORE_NAMES:
        assert expected[name] <= set(table_names(stores[name]))


def test_ddl_is_idempotent(stores) -> None:
    for store in stores.values():
        before = table_names(store)
        assert apply_ddl(store) == before


def test_write_tx_commits(stores) -> None:
    store = stores["audit_log"]
    with write_tx(store) as connection:
        connection.exec_driver_sql(
            "INSERT INTO entry (ts, kind, payload, prev_hash, hash) "
            "VALUES ('2026-01-01T00:00:00Z','poll.create','{}',x'00',x'aa')"
        )
    with read_tx(store) as connection:
        assert connection.exec_driver_sql("SELECT COUNT(*) FROM entry").scalar() == 1


def test_write_tx_rolls_back(stores) -> None:
    store = stores["audit_log"]
    with pytest.raises(RuntimeError):
        with write_tx(store) as connection:
            connection.exec_driver_sql(
                "INSERT INTO entry (ts, kind, payload, prev_hash, hash) "
                "VALUES ('2026-01-01T00:00:00Z','poll.create','{}',x'00',x'bb')"
            )
            raise RuntimeError("boom")
    with read_tx(store) as connection:
        assert connection.exec_driver_sql("SELECT COUNT(*) FROM entry").scalar() == 0


def test_audit_log_is_append_only(stores) -> None:
    store = stores["audit_log"]
    with write_tx(store) as connection:
        connection.exec_driver_sql(
            "INSERT INTO entry (ts, kind, payload, prev_hash, hash) "
            "VALUES ('2026-01-01T00:00:00Z','poll.create','{}',x'00',x'cc')"
        )
    with pytest.raises(SADatabaseError, match="append-only"):
        with write_tx(store) as connection:
            connection.exec_driver_sql("UPDATE entry SET payload='{}'")
    with pytest.raises(SADatabaseError, match="append-only"):
        with write_tx(store) as connection:
            connection.exec_driver_sql("DELETE FROM entry")


def _insert_poll(connection, *, status: str) -> None:
    connection.exec_driver_sql(
        "INSERT INTO poll (id, slug, title, summary, description_md, description_html,"
        " system, status, starts_at, ends_at, created_at, updated_at)"
        " VALUES ('p1','p1','t','s','md','<p>s</p>','list',?,"
        "'2026-01-01T00:00:00Z','2026-02-01T00:00:00Z','x','x')",
        (status,),
    )


def test_poll_content_is_immutable_after_start(stores) -> None:
    store = stores["polls"]
    with write_tx(store) as connection:
        _insert_poll(connection, status="scheduled")
    # Before the start, editing is allowed.
    with write_tx(store) as connection:
        connection.exec_driver_sql("UPDATE poll SET title='новое' WHERE id='p1'")
    # Entering the open state requires the crypto commitments.
    with write_tx(store) as connection:
        connection.exec_driver_sql(
            "UPDATE poll SET status='open', public_key=x'aa', eligibility_root=x'bb'"
            " WHERE id='p1'"
        )
    with pytest.raises(SADatabaseError, match="immutable"):
        with write_tx(store) as connection:
            connection.exec_driver_sql("UPDATE poll SET description_md='new' WHERE id='p1'")
    with pytest.raises(SADatabaseError, match="immutable"):
        with write_tx(store) as connection:
            connection.exec_driver_sql("UPDATE poll SET k_threshold=1 WHERE id='p1'")


def test_ballot_box_is_append_only(stores) -> None:
    store = stores["ballot_box"]
    with write_tx(store) as connection:
        connection.exec_driver_sql(
            "INSERT INTO ballot (poll_id, ballot_id, district_code, ciphertext, slot,"
            " batch_id) VALUES ('p1','abc','d',x'00','2026-01-01T00:00Z',1)"
        )
    with pytest.raises(SADatabaseError, match="append-only"):
        with write_tx(store) as connection:
            connection.exec_driver_sql("DELETE FROM ballot")


# --- Schema invariants: the core privacy promise of the design -----------------


def test_no_table_links_a_person_to_a_ballot(stores) -> None:
    """docs/05 D-2: no live_vote / superseded_ballot, nothing similar."""
    registry_tables = {name.lower() for name in table_names(stores["registry"])}
    forbidden = {"live_vote", "superseded_ballot", "ballot", "ballot_box", "vote_link"}
    assert not (registry_tables & forbidden)


@pytest.mark.parametrize("table", ["ballot", "ballot_queue", "ballot_batch"])
def test_ballot_tables_have_no_person_columns(stores, table: str) -> None:
    with stores["ballot_box"].engine.connect() as connection:
        columns = [
            row[1].lower()
            for row in connection.exec_driver_sql(f"PRAGMA table_info({table})")
        ]
    forbidden = {
        "user_id",
        "session_id",
        "ip",
        "ip_address",
        "user_agent",
        "login",
        "account_id",
        "voter_id",
        "voter_key",
    }
    assert not (set(columns) & forbidden)


def test_registry_has_no_direct_identifiers(stores) -> None:
    with stores["registry"].engine.connect() as connection:
        columns = {
            row[1].lower()
            for row in connection.exec_driver_sql("PRAGMA table_info(app_user)")
        }
    forbidden = ("fio", "name", "surname", "passport", "address", "email", "phone", "birth")
    assert not [column for column in columns if any(f in column for f in forbidden)]
