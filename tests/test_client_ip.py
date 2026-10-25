"""Client address handling behind the PythonAnywhere load balancer."""

from __future__ import annotations

import pytest
from flask import Flask

from fairvote.security.ratelimit import client_address


@pytest.fixture()
def flask_app() -> Flask:
    return Flask(__name__)


def _ip(app: Flask, *, trust: bool, headers: dict[str, str], remote: str = "10.0.0.5") -> str:
    with app.test_request_context("/", headers=headers, environ_overrides={"REMOTE_ADDR": remote}):
        return client_address(trust_x_real_ip=trust)


def test_header_ignored_unless_enabled(flask_app: Flask) -> None:
    assert _ip(flask_app, trust=False, headers={"X-Real-IP": "203.0.113.9"}) == "10.0.0.5"


def test_header_used_when_enabled(flask_app: Flask) -> None:
    assert _ip(flask_app, trust=True, headers={"X-Real-IP": "203.0.113.9"}) == "203.0.113.9"


@pytest.mark.parametrize("bad", ["", "not-an-ip", "1.2.3.4, 5.6.7.8", "999.1.1.1"])
def test_invalid_header_falls_back(flask_app: Flask, bad: str) -> None:
    assert _ip(flask_app, trust=True, headers={"X-Real-IP": bad}) == "10.0.0.5"


def test_global_bucket_disappears_with_trusted_header(tmp_path) -> None:
    """130 different visitors behind one balancer address must not trip 120/min."""
    from dataclasses import replace

    from fairvote import create_app
    from fairvote.config import Settings
    from fairvote.db import apply_ddl

    settings = replace(Settings.for_tests(tmp_path / "instance"), trust_x_real_ip=True)
    application = create_app(settings)
    for store in application.extensions["fairvote.stores"].values():
        apply_ddl(store)
    try:
        client = application.test_client()
        codes = {
            client.get(
                "/auth/register",
                headers={"X-Real-IP": f"198.51.100.{i % 250}"},
                environ_overrides={"REMOTE_ADDR": "10.0.0.5"},
            ).status_code
            for i in range(130)
        }
        assert 429 not in codes
    finally:
        for store in application.extensions["fairvote.stores"].values():
            store.dispose()
