"""Rate limiting storage: counters in the database, never in process memory."""

from __future__ import annotations

import time

import pytest

from fairvote.db import read_tx
from fairvote.registry.models import rate_counter_table
from fairvote.security.ratelimit import DBStorage, purge_expired_counters


@pytest.fixture()
def storage(stores) -> DBStorage:
    return DBStorage("fairvote-db://", store=stores["registry"])


def test_incr_starts_at_amount(storage: DBStorage) -> None:
    assert storage.incr("k", 60) == 1
    assert storage.incr("k", 60) == 2
    assert storage.incr("k", 60, amount=3) == 5
    assert storage.get("k") == 5


def test_counters_are_independent(storage: DBStorage) -> None:
    storage.incr("a", 60)
    storage.incr("a", 60)
    storage.incr("b", 60)
    assert storage.get("a") == 2
    assert storage.get("b") == 1
    assert storage.get("missing") == 0


def test_expiry_is_absolute_and_reported(storage: DBStorage) -> None:
    now = time.time()
    storage.incr("k", 60)
    expiry = storage.get_expiry("k")
    assert now + 50 <= expiry <= now + 70


def test_window_expiry_resets_the_counter(
    storage: DBStorage, stores
) -> None:
    storage.incr("k", 60)
    storage.incr("k", 60)
    with read_tx(stores["registry"]) as connection:
        connection.exec_driver_sql("UPDATE rate_counter SET expires_at = 1")
    assert storage.get("k") == 0
    assert storage.incr("k", 60) == 1


def test_clear_and_reset(storage: DBStorage, stores) -> None:
    storage.incr("a", 60)
    storage.incr("b", 60)
    storage.clear("a")
    assert storage.get("a") == 0
    assert storage.get("b") == 1
    assert storage.reset() == 1
    with read_tx(stores["registry"]) as connection:
        assert connection.execute(rate_counter_table.select()).first() is None


def test_check_reports_health(storage: DBStorage) -> None:
    assert storage.check() is True


def test_purge_expired_counters(storage: DBStorage, stores) -> None:
    storage.incr("a", 60)
    with read_tx(stores["registry"]) as connection:
        connection.exec_driver_sql("UPDATE rate_counter SET expires_at = 1")
    assert purge_expired_counters(stores["registry"]) == 1


def test_raw_ip_is_never_stored(client, districts, stores) -> None:
    client.get("/auth/login")
    with read_tx(stores["registry"]) as connection:
        rows = [dict(row) for row in connection.execute(rate_counter_table.select()).mappings()]
    for row in rows:
        assert "127.0.0.1" not in str(row)
        assert "localhost" not in str(row)
