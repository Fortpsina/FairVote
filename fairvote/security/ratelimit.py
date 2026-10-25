"""Database-backed rate limiting for Flask-Limiter.

``limits`` ships memory/redis/memcached/mongo backends but no SQLite one, and a
memory backend is forbidden here: on PythonAnywhere several workers would each keep
their own counters, so an attacker gets one budget per worker (docs/04 C9).

This module registers a small ``limits.storage.Storage`` implementation over the
``rate_counter`` table and hands it to Flask-Limiter through the library's public
storage-scheme registry. The counter is keyed by ``HMAC(k_ip_hash, IP)`` so the raw
address is never stored; rows expire with the window (≤ 24 h, docs/01 T10).
"""

from __future__ import annotations

import time

from flask import Flask, request
from flask_limiter import Limiter
from limits.storage import Storage
from limits.storage import SCHEMES
from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError

from ..db import Store, read_tx, write_tx
from ..registry.models import rate_counter_table
from ..security import crypto

RATE_SCOPE = "rate"
SCHEME = "fairvote-db"


class DBStorage(Storage):
    """Fixed-window counters in the registry database."""

    STORAGE_SCHEME = SCHEME
    base_exceptions = (SQLAlchemyError,)

    def __init__(self, uri: str | None = None, *, store: Store | None = None, **_: object) -> None:
        if store is None:
            raise ValueError("DBStorage requires the registry store")
        self.store = store

    # -- limits interface --------------------------------------------------------

    def incr(self, key: str, expiry: float, amount: int = 1) -> int:
        now = int(time.time())
        deadline = now + int(expiry)
        with write_tx(self.store) as connection:
            row = connection.execute(
                select(rate_counter_table.c.counter, rate_counter_table.c.expires_at).where(
                    rate_counter_table.c.scope == RATE_SCOPE,
                    rate_counter_table.c.key == key,
                    rate_counter_table.c.window_start == 0,
                )
            ).first()
            if row is None:
                connection.execute(
                    rate_counter_table.insert().values(
                        scope=RATE_SCOPE,
                        key=key,
                        window_start=0,
                        counter=amount,
                        expires_at=deadline,
                    )
                )
                return amount
            counter, expires_at = int(row[0]), int(row[1])
            if expires_at <= now:
                connection.execute(
                    rate_counter_table.update()
                    .where(
                        rate_counter_table.c.scope == RATE_SCOPE,
                        rate_counter_table.c.key == key,
                        rate_counter_table.c.window_start == 0,
                    )
                    .values(counter=amount, expires_at=deadline)
                )
                return amount
            counter += amount
            connection.execute(
                rate_counter_table.update()
                .where(
                    rate_counter_table.c.scope == RATE_SCOPE,
                    rate_counter_table.c.key == key,
                    rate_counter_table.c.window_start == 0,
                )
                .values(counter=counter)
            )
            return counter

    def get(self, key: str) -> int:
        now = int(time.time())
        with read_tx(self.store) as connection:
            row = connection.execute(
                select(rate_counter_table.c.counter, rate_counter_table.c.expires_at).where(
                    rate_counter_table.c.scope == RATE_SCOPE,
                    rate_counter_table.c.key == key,
                    rate_counter_table.c.window_start == 0,
                )
            ).first()
        if row is None or int(row[1]) <= now:
            return 0
        return int(row[0])

    def get_expiry(self, key: str) -> float:
        with read_tx(self.store) as connection:
            row = connection.execute(
                select(rate_counter_table.c.expires_at).where(
                    rate_counter_table.c.scope == RATE_SCOPE,
                    rate_counter_table.c.key == key,
                    rate_counter_table.c.window_start == 0,
                )
            ).first()
        return float(row[0]) if row else float(time.time())

    def clear(self, key: str) -> None:
        with write_tx(self.store) as connection:
            connection.execute(
                delete(rate_counter_table).where(
                    rate_counter_table.c.scope == RATE_SCOPE,
                    rate_counter_table.c.key == key,
                )
            )

    def reset(self) -> int | None:
        with write_tx(self.store) as connection:
            result = connection.execute(
                delete(rate_counter_table).where(rate_counter_table.c.scope == RATE_SCOPE)
            )
        return int(result.rowcount or 0)

    def check(self) -> bool:
        try:
            with read_tx(self.store) as connection:
                connection.exec_driver_sql("SELECT 1")
        except SQLAlchemyError:
            return False
        return True


def _ip_key(master_key: bytes):
    """Limiter key: HMAC of the client address, never the address itself."""
    hmac_key = crypto.derive_key(master_key, "fairvote/ip/v1")

    def key() -> str:
        address = (request.remote_addr or "unknown").encode("utf-8")
        return crypto.hmac_sha256(hmac_key, address).hex()

    return key


def init_limiter(app: Flask, store: Store, *, master_key: bytes) -> Limiter:
    if SCHEME not in SCHEMES:
        SCHEMES[SCHEME] = DBStorage
    limiter = Limiter(
        key_func=_ip_key(master_key),
        storage_uri=f"{SCHEME}://",
        storage_options={"store": store},
        default_limits=["120 per minute"],
        headers_enabled=True,
        strategy="fixed-window",
    )
    limiter.init_app(app)
    return limiter


def purge_expired_counters(store: Store) -> int:
    """Housekeeping: counters older than their window are useless."""
    now = int(time.time())
    with write_tx(store) as connection:
        result = connection.execute(
            delete(rate_counter_table).where(rate_counter_table.c.expires_at <= now)
        )
    return int(result.rowcount or 0)
