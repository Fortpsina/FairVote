"""Private project/state paths must not be served by the Flask application."""
from pathlib import Path

import pytest


@pytest.mark.parametrize("url", [
    "/.git/HEAD", "/.git/config", "/.env", "/secrets.env",
    "/fairvote/config.py", "/requirements.txt", "/docs/runbook.md",
    "/instance/secrets.env", "/instance/db/registry.sqlite",
    "/db/registry.sqlite", "/.smoke-final/db/registry.sqlite",
    "/static/../../config.py", "/static/%2e%2e/%2e%2e/config.py",
    "/static/%2e%2e%2f%2e%2e%2fconfig.py", "/static/%2e%2e%5cconfig.py",
    "/static//etc/passwd", "/static/.env", "/static/.git/config",
])
def test_private_paths_are_not_public(client, settings, url):
    marker = "private-file-canary-never-serve"
    (settings.instance_dir / "secrets.env").write_text(marker, encoding="utf-8")
    response = client.get(url, follow_redirects=True)
    assert response.status_code == 404
    assert marker.encode() not in response.data


def test_static_contains_no_links_outside_public_directory(app):
    directory = Path(app.static_folder).resolve()
    for path in directory.rglob("*"):
        assert path.resolve().is_relative_to(directory), path
    assert not app.debug
