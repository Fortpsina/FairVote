"""SQLAlchemy Core definitions for the audit store.

The authoritative DDL lives in ``fairvote/ddl/sqlite/audit_log.sql``; these tables
mirror it so that queries are parameterised instead of hand-built. A parity test
(``tests/test_audit_models.py``) keeps the two in sync.
"""

from __future__ import annotations

from sqlalchemy import BLOB, Column, Integer, MetaData, Table, Text

metadata = MetaData()

entry_table = Table(
    "entry",
    metadata,
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column("ts", Text, nullable=False),
    Column("kind", Text, nullable=False),
    Column("poll_id", Text, nullable=True),
    Column("payload", Text, nullable=False),
    Column("prev_hash", BLOB, nullable=False),
    Column("hash", BLOB, nullable=False, unique=True),
    Column("sig", BLOB, nullable=True),
)

checkpoint_table = Table(
    "checkpoint",
    metadata,
    Column("seq", Integer, primary_key=True, autoincrement=False),
    Column("hash", BLOB, nullable=False),
    Column("signature", BLOB, nullable=False),
    Column("anchor_note", Text, nullable=True),
    Column("created_at", Text, nullable=False),
)
