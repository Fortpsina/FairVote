"""Engines for the four independent SQLite stores.

Layout and rationale: docs/02 §2.3. Each store is a separate file with its own
engine, its own schema and its own module; there are no foreign keys across files,
and cross-store integrity is provided by the audit log.

Concurrency notes (relevant on PythonAnywhere with several workers):

* ``journal_mode=WAL`` allows concurrent readers with one writer.
* ``BEGIN IMMEDIATE`` acquires the write lock up front, so concurrent writers
  serialise on ``busy_timeout`` instead of failing with ``SQLITE_BUSY`` on a lock
  upgrade. To issue it ourselves, the DBAPI connection is put in autocommit mode
  (``isolation_level = None``) and SQLAlchemy's own BEGIN is suppressed.
* ``busy_timeout=5000`` gives a writer up to five seconds to wait for the lock.
"""

from __future__ import annotations

import random
import time
from contextlib import contextmanager
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.pool import NullPool

from .config import Settings

STORE_NAMES: tuple[str, ...] = ("registry", "polls", "ballot_box", "audit_log")

PRAGMA_STATEMENTS: tuple[str, ...] = (
    "PRAGMA journal_mode=WAL",
    "PRAGMA foreign_keys=ON",
    "PRAGMA busy_timeout=5000",
    "PRAGMA synchronous=NORMAL",
    "PRAGMA trusted_schema=OFF",
)


@dataclass(frozen=True)
class Store:
    """One SQLite file plus its engine."""

    name: str
    path: Path
    engine: Engine

    def dispose(self) -> None:
        self.engine.dispose()


def _on_connect(dbapi_connection, _record) -> None:  # noqa: ANN001 - driver types
    dbapi_connection.isolation_level = None
    cursor = dbapi_connection.cursor()
    try:
        for statement in PRAGMA_STATEMENTS:
            cursor.execute(statement)
    finally:
        cursor.close()


def open_store(name: str, path: Path) -> Store:
    engine = create_engine(
        f"sqlite:///{path}",
        future=True,
        poolclass=NullPool,
        connect_args={"timeout": 5, "check_same_thread": False},
    )
    event.listen(engine, "connect", _on_connect)
    return Store(name=name, path=path, engine=engine)


def open_stores(settings: Settings) -> dict[str, Store]:
    settings.db_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    return {name: open_store(name, settings.store_path(name)) for name in STORE_NAMES}


@contextmanager
def write_tx(store: Store) -> Iterator[Connection]:
    """Write transaction: ``BEGIN IMMEDIATE`` ... ``COMMIT`` (or ``ROLLBACK``).

    ``BEGIN IMMEDIATE`` takes the write lock up front, so a second worker waits on
    ``busy_timeout`` instead of failing on a lock upgrade. If the wait itself times
    out (a long-running writer), the *begin* is retried with jitter; the body is
    never re-executed, because a retried body could apply side effects twice.
    """
    connection = store.engine.connect()
    try:
        _begin_immediate(connection)
        try:
            yield connection
        except BaseException:
            connection.exec_driver_sql("ROLLBACK")
            raise
        else:
            connection.exec_driver_sql("COMMIT")
    finally:
        connection.close()


def _begin_immediate(connection: Connection, attempts: int = 6) -> None:
    delay = 0.02
    for attempt in range(attempts):
        try:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            return
        except OperationalError as exc:
            if "locked" not in str(exc).lower() or attempt == attempts - 1:
                raise
            time.sleep(delay + random.random() * delay)
            delay = min(delay * 2, 0.5)


@contextmanager
def read_tx(store: Store) -> Iterator[Connection]:
    """Read transaction with a consistent snapshot."""
    connection = store.engine.connect()
    try:
        connection.exec_driver_sql("BEGIN")
        try:
            yield connection
        finally:
            connection.exec_driver_sql("COMMIT")
    finally:
        connection.close()


def ddl_text(store_name: str) -> str:
    """Return the DDL for a store from the packaged ``ddl/sqlite`` directory."""
    resource = resources.files("fairvote").joinpath(f"ddl/sqlite/{store_name}.sql")
    return resource.read_text(encoding="utf-8")


def apply_ddl(store: Store) -> list[str]:
    """Execute the store's DDL; the statements are idempotent (``IF NOT EXISTS``)."""
    sql = ddl_text(store.name)
    raw = store.engine.raw_connection()
    try:
        raw.driver_connection.executescript(sql)
        raw.commit()
    finally:
        raw.close()
    return table_names(store)


def table_names(store: Store) -> list[str]:
    with store.engine.connect() as connection:
        rows = connection.exec_driver_sql(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
        return [row[0] for row in rows]
