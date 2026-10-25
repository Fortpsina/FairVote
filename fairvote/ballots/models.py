"""SQLAlchemy Core tables for the ballot box store.

Mirrors ``fairvote/ddl/sqlite/ballot_box.sql``. Nothing here identifies a person:
no user id, no IP, no session (docs/01 T10/T11, docs/05 D-2).
"""

from __future__ import annotations

from sqlalchemy import BLOB, Column, Integer, MetaData, Table, Text, UniqueConstraint

metadata = MetaData()

ballot_queue_table = Table(
    "ballot_queue",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("poll_id", Text, nullable=False),
    Column("ballot_id", Text, nullable=False),
    Column("district_code", Text, nullable=False),
    Column("client_nonce", BLOB, nullable=False),
    Column("ciphertext", BLOB, nullable=False),
    Column("received_slot", Text, nullable=False),
    Column("confirmed", Integer, nullable=False, server_default="0"),
    Column("created_at", Text, nullable=False),
    UniqueConstraint("poll_id", "client_nonce", name="uq_queue_nonce"),
    UniqueConstraint("poll_id", "ballot_id", name="uq_queue_ballot"),
)

ballot_table = Table(
    "ballot",
    metadata,
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column("poll_id", Text, nullable=False),
    Column("ballot_id", Text, nullable=False),
    Column("district_code", Text, nullable=False),
    Column("ciphertext", BLOB, nullable=False),
    Column("slot", Text, nullable=False),
    Column("batch_id", Integer, nullable=False),
    UniqueConstraint("poll_id", "ballot_id", name="uq_ballot_id"),
)

ballot_batch_table = Table(
    "ballot_batch",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("poll_id", Text, nullable=False),
    Column("size", Integer, nullable=False),
    Column("merkle_root", BLOB, nullable=False),
    Column("slot", Text, nullable=False),
    Column("audit_seq", Integer, nullable=False),
    Column("created_at", Text, nullable=False),
)

published_key_table = Table(
    "published_key",
    metadata,
    Column("poll_id", Text, primary_key=True),
    Column("public_key", BLOB, nullable=False),
    Column("private_key", BLOB, nullable=True),
    Column("fingerprint", Text, nullable=False),
    Column("published_at", Text, nullable=False),
)
