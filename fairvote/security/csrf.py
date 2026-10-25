"""CSRF protection: Flask-WTF tokens plus an Origin/Sec-Fetch-Site guard.

The token lives in the server-side session, so a token from another browser (or a
cookie-only attacker) is useless. The header checks are a second, independent
barrier: they stop a cross-site form post even if a token ever leaked into an
attacker-controlled page (docs/01 T18).
"""

from __future__ import annotations

from urllib.parse import urlsplit

from flask import Flask, abort, request
from flask_wtf.csrf import CSRFProtect

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
ALLOWED_FETCH_SITES = frozenset({"same-origin", "none"})


def _same_origin(value: str, host: str) -> bool:
    parts = urlsplit(value)
    return bool(parts.netloc) and parts.netloc == host


def init_csrf(app: Flask) -> CSRFProtect:
    app.config.setdefault("WTF_CSRF_TIME_LIMIT", 7200)
    # Flask-WTF's "SSL strict" mode requires a matching Referer header on HTTPS
    # requests. We send ``Referrer-Policy: no-referrer`` (docs/03 §3.11), so browsers
    # legitimately omit it — leaving the check on would reject every real form post.
    # The Origin / Sec-Fetch-Site guard below covers the same attack surface without
    # depending on a header the user's browser is told not to send.
    app.config.setdefault("WTF_CSRF_SSL_STRICT", False)

    csrf = CSRFProtect()
    csrf.init_app(app)

    @app.before_request
    def _origin_guard() -> None:
        if request.method in SAFE_METHODS:
            return
        fetch_site = request.headers.get("Sec-Fetch-Site")
        if fetch_site is not None and fetch_site not in ALLOWED_FETCH_SITES:
            abort(403)
        origin = request.headers.get("Origin")
        if origin is not None and not _same_origin(origin, request.host):
            abort(403)
        referer = request.headers.get("Referer")
        if origin is None and referer is not None and not _same_origin(referer, request.host):
            abort(403)

    return csrf
