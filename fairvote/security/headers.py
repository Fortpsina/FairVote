"""HTTP security headers applied to every response (docs/03 §3.11).

The CSP is deliberately strict and has no ``unsafe-inline``: all scripts and styles
are separate files served from our own origin, which is also what makes the
published asset hashes meaningful (docs/02 §2.8).
"""

from __future__ import annotations

from flask import Flask, Response, request

CSP = "; ".join(
    (
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "form-action 'self'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
        "object-src 'none'",
        "manifest-src 'self'",
    )
)

HSTS = "max-age=63072000; includeSubDomains"
PERMISSIONS_POLICY = (
    "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=(), usb=()"
)


def apply_headers(response: Response) -> Response:
    headers = response.headers
    headers.setdefault("Content-Security-Policy", CSP)
    headers.setdefault("X-Content-Type-Options", "nosniff")
    headers.setdefault("Referrer-Policy", "no-referrer")
    headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    headers.setdefault("Permissions-Policy", PERMISSIONS_POLICY)
    headers.setdefault("X-Frame-Options", "DENY")
    if request.is_secure:
        headers.setdefault("Strict-Transport-Security", HSTS)
    # Authenticated pages must never be cached by a shared proxy or the browser's
    # back button cache; public pages opt in explicitly in their view.
    headers.setdefault("Cache-Control", "no-store")
    return response


def init_headers(app: Flask) -> None:
    app.after_request(apply_headers)
