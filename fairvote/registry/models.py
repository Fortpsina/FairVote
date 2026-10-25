"""SQLAlchemy Core tables for the registry store.

Mirrors ``fairvote/ddl/sqlite/registry.sql``; a parity test keeps them in sync.
There is deliberately no table that references a ballot (docs/05 D-2).
"""

from __future__ import annotations

from sqlalchemy import BLOB, Column, ForeignKey, Integer, MetaData, Table, Text, UniqueConstraint

metadata = MetaData()

district_table = Table(
    "district",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("code", Text, nullable=False, unique=True),
    Column("level", Text, nullable=False),
    Column("parent_id", Integer, ForeignKey("district.id"), nullable=True),
    Column("name", Text, nullable=False),
    Column("path", Text, nullable=False),
    Column("is_active", Integer, nullable=False, server_default="1"),
)

app_user_table = Table(
    "app_user",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("login", Text, nullable=False, unique=True),
    Column("login_display", Text, nullable=False),
    Column("password_hash", Text, nullable=False),
    Column("totp_secret_enc", BLOB, nullable=True),
    Column("totp_confirmed_at", Text, nullable=True),
    Column("totp_last_step", Integer, nullable=True),
    Column("totp_fail_count", Integer, nullable=False, server_default="0"),
    Column("recovery_seen_at", Text, nullable=True),
    Column("district_id", Integer, ForeignKey("district.id"), nullable=False),
    Column("status", Text, nullable=False),
    Column("role", Text, nullable=False, server_default="voter"),
    Column("verify_method", Text, nullable=True),
    Column("verify_decided_at", Text, nullable=True),
    Column("verify_reason_code", Text, nullable=True),
    Column("voter_key", BLOB, nullable=True),
    Column("voter_key_version", Integer, nullable=False, server_default="1"),
    Column("failed_login_count", Integer, nullable=False, server_default="0"),
    Column("locked_until", Text, nullable=True),
    Column("last_login_at", Text, nullable=True),
    Column("created_at", Text, nullable=False),
    Column("updated_at", Text, nullable=False),
    Column("deletion_requested_at", Text, nullable=True),
    Column("deleted_at", Text, nullable=True),
)

recovery_code_table = Table(
    "recovery_code",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", Integer, ForeignKey("app_user.id"), nullable=False),
    Column("idx", Integer, nullable=False),
    Column("code_hash", Text, nullable=False),
    Column("used_at", Text, nullable=True),
    Column("created_at", Text, nullable=False),
    UniqueConstraint("user_id", "idx", name="uq_recovery_code_user_idx"),
)

session_table = Table(
    "session",
    metadata,
    Column("id", BLOB, primary_key=True),
    Column("user_id", Integer, ForeignKey("app_user.id"), nullable=True),
    Column("pending_user_id", Integer, ForeignKey("app_user.id"), nullable=True),
    Column("auth_level", Text, nullable=False),
    Column("data", BLOB, nullable=False),
    Column("csrf_token", BLOB, nullable=False),
    Column("created_at", Text, nullable=False),
    Column("last_seen_at", Text, nullable=False),
    Column("expires_at", Text, nullable=False),
)

verification_request_table = Table(
    "verification_request",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", Integer, ForeignKey("app_user.id"), nullable=False),
    Column("method", Text, nullable=False),
    Column("code_hash", BLOB, nullable=False, unique=True),
    Column("code_attempts", Integer, nullable=False, server_default="0"),
    Column("created_at", Text, nullable=False),
    Column("expires_at", Text, nullable=False),
    Column("decided_at", Text, nullable=True),
    Column("decision", Text, nullable=True),
    Column("reason_code", Text, nullable=True),
    Column("decided_by", Text, nullable=True),
)

participation_table = Table(
    "participation",
    metadata,
    Column("poll_id", Text, nullable=False, primary_key=True),
    Column("user_id", Integer, ForeignKey("app_user.id"), nullable=False, primary_key=True),
    Column("voted_on", Text, nullable=False),
)

rate_counter_table = Table(
    "rate_counter",
    metadata,
    Column("scope", Text, nullable=False, primary_key=True),
    Column("key", Text, nullable=False, primary_key=True),
    Column("window_start", Integer, nullable=False, primary_key=True),
    Column("counter", Integer, nullable=False),
    Column("expires_at", Integer, nullable=False),
)

auth_event_table = Table(
    "auth_event",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("ts", Text, nullable=False),
    Column("user_id", Integer, nullable=True),
    Column("event", Text, nullable=False),
    Column("detail", Text, nullable=True),
)
