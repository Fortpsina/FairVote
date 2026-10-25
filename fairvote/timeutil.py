"""Time helpers: one format for the whole system.

All timestamps are UTC ISO-8601 strings with second precision and a trailing ``Z``.
Storing text (instead of a database timestamp type) keeps the semantics identical
on SQLite, MySQL and PostgreSQL and makes the value that is hashed into the audit
chain exactly the value that is stored.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(moment: datetime) -> str:
    if moment.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return moment.astimezone(timezone.utc).strftime(ISO_FORMAT)


def from_iso(value: str) -> datetime:
    parsed = datetime.strptime(value, ISO_FORMAT)
    return parsed.replace(tzinfo=timezone.utc)


def iso_now() -> str:
    return to_iso(utc_now())


def iso_after(seconds: float = 0, *, minutes: float = 0, hours: float = 0) -> str:
    delta = timedelta(seconds=seconds, minutes=minutes, hours=hours)
    return to_iso(utc_now() + delta)


def date_today() -> str:
    """Calendar date (no time) — the only precision participation keeps."""
    return utc_now().strftime("%Y-%m-%d")
