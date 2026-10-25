"""HTTP behaviour of the skeleton: headers on every response, no leaks."""

from __future__ import annotations

from fairvote.security.headers import CSP


def test_healthz_is_minimal(client) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.get_json() == {"ok": True}


def test_security_headers_are_present(client) -> None:
    response = client.get("/healthz")
    assert response.headers["Content-Security-Policy"] == CSP
    assert "unsafe-inline" not in CSP
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Cache-Control"] == "no-store"


def test_error_pages_keep_the_headers(client) -> None:
    response = client.get("/no-such-page")
    assert response.status_code == 404
    assert response.headers["Content-Security-Policy"] == CSP
    assert b"404" in response.data


def test_static_assets_are_served_from_this_origin(client) -> None:
    response = client.get("/static/app.css")
    assert response.status_code == 200
    assert b"--accent" in response.data


def test_hsts_only_over_https(client) -> None:
    # Flask's test client follows PREFERRED_URL_SCHEME=https, so request the plain
    # scheme explicitly: HSTS must not be sent over cleartext.
    plain = client.get("/healthz", base_url="http://localhost")
    assert "Strict-Transport-Security" not in plain.headers
    secure = client.get("/healthz", base_url="https://localhost")
    assert "Strict-Transport-Security" in secure.headers
