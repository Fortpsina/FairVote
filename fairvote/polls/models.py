"""SQLAlchemy Core tables for the polls store.

Mirrors ``fairvote/ddl/sqlite/polls.sql``. Poll content is public; the only
sensitive value here is the eligibility commitment, which is a one-way aggregate.
"""

from __future__ import annotations

from sqlalchemy import BLOB, Column, ForeignKey, Integer, MetaData, Table, Text

metadata = MetaData()

poll_table = Table(
    "poll",
    metadata,
    Column("id", Text, primary_key=True),
    Column("slug", Text, nullable=False, unique=True),
    Column("title", Text, nullable=False),
    Column("summary", Text, nullable=False),
    Column("description_md", Text, nullable=False),
    Column("description_html", Text, nullable=False),
    Column("system", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("starts_at", Text, nullable=False),
    Column("ends_at", Text, nullable=False),
    Column("k_threshold", Integer, nullable=False),
    Column("revote_policy", Text, nullable=False),
    Column("ballot_plaintext_bytes", Integer, nullable=False),
    Column("key_publish_after", Text, nullable=True),
    Column("public_key", BLOB, nullable=True),
    Column("key_fingerprint", Text, nullable=True),
    Column("eligibility_root", BLOB, nullable=True),
    Column("eligible_total", Integer, nullable=True),
    Column("started_committed_at", Text, nullable=True),
    Column("closed_at", Text, nullable=True),
    Column("private_key_published_at", Text, nullable=True),
    Column("js_manifest_hash", Text, nullable=True),
    Column("created_by", Integer, nullable=True),
    Column("created_at", Text, nullable=False),
    Column("updated_at", Text, nullable=False),
)

contest_table = Table(
    "contest",
    metadata,
    Column("id", Text, primary_key=True),
    Column("poll_id", Text, ForeignKey("poll.id"), nullable=False),
    Column("scope", Text, nullable=False),
    Column("district_code", Text, nullable=True),
    Column("kind", Text, nullable=False),
    Column("title", Text, nullable=False),
    Column("description_html", Text, nullable=False),
    Column("allow_against_all", Integer, nullable=False),
    Column("display_order", Integer, nullable=False),
)

option_table = Table(
    "option",
    metadata,
    Column("id", Text, primary_key=True),
    Column("contest_id", Text, ForeignKey("contest.id"), nullable=False),
    Column("kind", Text, nullable=False),
    Column("name", Text, nullable=False),
    Column("bio_html", Text, nullable=True),
    Column("link_url", Text, nullable=True),
    Column("display_order", Integer, nullable=False),
)

poll_district_table = Table(
    "poll_district",
    metadata,
    Column("poll_id", Text, ForeignKey("poll.id"), nullable=False, primary_key=True),
    Column("district_code", Text, nullable=False, primary_key=True),
    Column("display_name", Text, nullable=False),
)

eligibility_commitment_table = Table(
    "eligibility_commitment",
    metadata,
    Column("poll_id", Text, ForeignKey("poll.id"), nullable=False, primary_key=True),
    Column("district_code", Text, nullable=False, primary_key=True),
    Column("eligible_count", Integer, nullable=False),
    Column("subtree_root", BLOB, nullable=False),
)

poll_revision_table = Table(
    "poll_revision",
    metadata,
    Column("poll_id", Text, ForeignKey("poll.id"), nullable=False, primary_key=True),
    Column("revision", Integer, nullable=False, primary_key=True),
    Column("snapshot_json", Text, nullable=False),
    Column("content_hash", BLOB, nullable=False),
    Column("created_at", Text, nullable=False),
)

admin_action_table = Table(
    "admin_action",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("ts", Text, nullable=False),
    Column("admin_id", Integer, nullable=False),
    Column("action", Text, nullable=False),
    Column("poll_id", Text, nullable=True),
    Column("audit_seq", Integer, nullable=False),
)
