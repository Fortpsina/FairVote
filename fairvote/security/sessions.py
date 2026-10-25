"""Server-side sessions stored in the registry database.

Why not the default signed-cookie session: the cookie would carry the identity, and
a stolen cookie could not be revoked. Here the cookie carries only a 256-bit token;
the database stores ``SHA-256(token)``, so a database dump does not yield usable
cookies either (docs/02 §2.6.1, docs/01 T21).

Timeouts: idle (default 20 min) and absolute (default 8 h). The row is deleted on
expiry, on logout and on password change. Session identifiers are rotated when the
authentication level changes (password → full), which kills fixation attacks.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import timedelta

from flask import Flask, Request, Response, has_request_context, request
from flask.sessions import SessionInterface, SessionMixin
from sqlalchemy import delete, select
from werkzeug.datastructures import CallbackDict

from ..db import Store, read_tx, write_tx
from ..registry.models import session_table
from ..timeutil import from_iso, to_iso, utc_now

_TOUCH_INTERVAL_SECONDS = 60


def _b64encode(token: bytes) -> str:
    return base64.urlsafe_b64encode(token).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes | None:
    try:
        padded = value + "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        return None


class DBSession(CallbackDict, SessionMixin):
    """A dict-like session bound to one database row.

    ``created_at`` is an attribute, not a key: writing it through ``__setitem__``
    would mark the session dirty on every request and turn every page view into a
    database write.
    """

    def __init__(
        self,
        initial: dict | None = None,
        *,
        sid: bytes | None = None,
        token: bytes | None = None,
        created_at: str | None = None,
    ) -> None:
        def on_update(_self) -> None:
            _self.modified = True

        super().__init__(initial or {}, on_update)
        self.sid = sid
        self.token = token
        self.stored_sid = sid
        self.created_at = created_at
        self.new = sid is None

    def rotate(self) -> None:
        """Issue a new token for the same row contents (anti-fixation)."""
        self.token = secrets.token_bytes(32)
        self.sid = hashlib.sha256(self.token).digest()
        self.modified = True


class DBSessionInterface(SessionInterface):
    session_class = DBSession

    def __init__(self, store: Store, *, idle_minutes: int, absolute_hours: int) -> None:
        self.store = store
        self.idle = timedelta(minutes=idle_minutes)
        self.absolute = timedelta(hours=absolute_hours)

    # --- read -------------------------------------------------------------------

    def open_session(self, app: Flask, request: Request) -> DBSession:
        name = self.get_cookie_name(app)
        raw = request.cookies.get(name)
        if not raw:
            return self.session_class()

        token = _b64decode(raw)
        if token is None or len(token) != 32:
            return self.session_class()
        sid = hashlib.sha256(token).digest()

        with read_tx(self.store) as connection:
            row = (
                connection.execute(select(session_table).where(session_table.c.id == sid))
                .mappings()
                .first()
            )
        if row is None:
            return self.session_class()

        now = utc_now()
        if from_iso(row["expires_at"]) <= now:
            self._delete(sid)
            return self.session_class()

        try:
            data = json.loads(bytes(row["data"]).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._delete(sid)
            return self.session_class()
        if not isinstance(data, dict):
            self._delete(sid)
            return self.session_class()

        session = self.session_class(data, sid=sid, token=token, created_at=row["created_at"])
        session.new = False
        if now - from_iso(row["last_seen_at"]) >= timedelta(seconds=_TOUCH_INTERVAL_SECONDS):
            self._touch(sid, row["created_at"], now)
        return session

    # --- write ------------------------------------------------------------------

    def save_session(self, app: Flask, session: DBSession, response: Response) -> None:
        name = self.get_cookie_name(app)
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)

        if not dict(session):
            self._delete(getattr(session, "stored_sid", None))
            if has_request_context() and name in request.cookies:
                response.delete_cookie(name, domain=domain, path=path)
            return

        if not session.modified and not session.new:
            return

        token = session.token or secrets.token_bytes(32)
        sid = session.sid or hashlib.sha256(token).digest()
        session.token, session.sid = token, sid

        created_at = session.created_at or to_iso(utc_now())
        session.created_at = created_at
        now = utc_now()
        expires_at = min(now + self.idle, from_iso(created_at) + self.absolute)

        payload = dict(session)
        csrf = str(payload.get("csrf_token", "")).encode("utf-8")
        data = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")

        stored_sid = getattr(session, "stored_sid", None)
        with write_tx(self.store) as connection:
            if stored_sid is not None and stored_sid != sid:
                connection.execute(delete(session_table).where(session_table.c.id == stored_sid))
            existing = connection.execute(
                select(session_table.c.id).where(session_table.c.id == sid)
            ).first()
            values = dict(
                user_id=_as_int(payload.get("user_id")),
                pending_user_id=_as_int(payload.get("pending_user_id")),
                auth_level=str(payload.get("auth_level", "anon")),
                data=data,
                csrf_token=csrf,
                created_at=created_at,
                last_seen_at=to_iso(now),
                expires_at=to_iso(expires_at),
            )
            if existing is None:
                connection.execute(session_table.insert().values(id=sid, **values))
            else:
                connection.execute(
                    session_table.update().where(session_table.c.id == sid).values(**values)
                )
        session.stored_sid = sid
        session.new = False
        session.modified = False

        response.set_cookie(
            name,
            _b64encode(token),
            expires=expires_at,
            httponly=app.config["SESSION_COOKIE_HTTPONLY"],
            secure=app.config["SESSION_COOKIE_SECURE"],
            samesite=app.config["SESSION_COOKIE_SAMESITE"],
            path=path,
            domain=domain,
        )

    # --- helpers ----------------------------------------------------------------

    def _touch(self, sid: bytes, created_at: str, now) -> None:
        expires_at = min(now + self.idle, from_iso(created_at) + self.absolute)
        with write_tx(self.store) as connection:
            connection.execute(
                session_table.update()
                .where(session_table.c.id == sid)
                .values(last_seen_at=to_iso(now), expires_at=to_iso(expires_at))
            )

    def _delete(self, sid: bytes | None) -> None:
        if not sid:
            return
        with write_tx(self.store) as connection:
            connection.execute(delete(session_table).where(session_table.c.id == sid))


def _as_int(value) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def purge_expired_sessions(store: Store) -> int:
    """Housekeeping, called from the daily task and probabilistically on requests."""
    now = to_iso(utc_now())
    with write_tx(store) as connection:
        result = connection.execute(delete(session_table).where(session_table.c.expires_at <= now))
    return int(result.rowcount or 0)


def revoke_all_sessions(store: Store, user_id: int) -> int:
    """Used after a password change or recovery (docs/01 T21)."""
    with write_tx(store) as connection:
        result = connection.execute(delete(session_table).where(session_table.c.user_id == user_id))
    return int(result.rowcount or 0)


def list_sessions(store: Store, user_id: int) -> list[dict]:
    """Active sessions for the account page (no IP, no user agent — we do not store them)."""
    with read_tx(store) as connection:
        rows = connection.execute(
            select(
                session_table.c.id,
                session_table.c.created_at,
                session_table.c.last_seen_at,
                session_table.c.expires_at,
            )
            .where(session_table.c.user_id == user_id)
            .order_by(session_table.c.last_seen_at.desc())
        ).all()
    return [
        {
            "fingerprint": bytes(row[0]).hex()[:12],
            "created_at": row[1],
            "last_seen_at": row[2],
            "expires_at": row[3],
        }
        for row in rows
    ]
