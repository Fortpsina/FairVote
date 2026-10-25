"""Shared pytest fixtures.

Every test gets a fresh temporary instance directory, four freshly created SQLite
files and a Flask app in demo mode with ephemeral keys. Nothing touches a real
instance directory and no test depends on network access.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from fairvote import create_app
from fairvote.config import Settings
from fairvote.db import apply_ddl
from fairvote.registry import service

CSRF_PATTERN = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    return Settings.for_tests(tmp_path / "instance")


@pytest.fixture()
def app(settings: Settings):
    application = create_app(settings)
    for store in application.extensions["fairvote.stores"].values():
        apply_ddl(store)
    yield application
    for store in application.extensions["fairvote.stores"].values():
        store.dispose()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def stores(app):
    return app.extensions["fairvote.stores"]


@pytest.fixture()
def districts(stores):
    """The demo hierarchy, needed by the registration form."""
    service.seed_districts(stores["registry"])
    return stores["registry"]


@pytest.fixture()
def csrf():
    """Return a helper that fetches a page and extracts its CSRF token."""

    def _token(test_client, path: str) -> str:
        html = test_client.get(path).get_data(as_text=True)
        match = CSRF_PATTERN.search(html)
        assert match, f"no CSRF token on {path}"
        return match.group(1)

    return _token
