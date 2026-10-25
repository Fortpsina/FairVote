"""Vendored browser crypto: pinned hashes and a functional acceptance check."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "fairvote" / "web" / "static" / "vendor"
LOCK = VENDOR / "vendor.lock"
CHECK_SCRIPT = ROOT / "tools" / "check_vendor.js"


def _node() -> str | None:
    candidates = [
        os.environ.get("DSH_NODE"),
        shutil.which("node"),
        r"C:\Users\Пользователь\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\node\bin\node.exe",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    return None


def test_vendor_lock_lists_both_files() -> None:
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    paths = {entry["path"] for entry in lock["files"]}
    assert paths == {"libsodium.js", "libsodium-wrappers.js"}
    assert lock["libsodium_version"]


def test_vendored_files_match_the_lock() -> None:
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    for entry in lock["files"]:
        data = (VENDOR / entry["path"]).read_bytes()
        assert len(data) == entry["bytes"]
        assert hashlib.sha256(data).hexdigest() == entry["sha256"]


def test_license_is_shipped_next_to_the_code() -> None:
    for name in ("LICENSE-libsodium.txt", "LICENSE-libsodium-wrappers.txt"):
        assert (VENDOR / name).exists()
        assert "Permission to use, copy, modify" in (VENDOR / name).read_text(encoding="utf-8")


def test_vendored_bundle_seals_and_opens() -> None:
    node = _node()
    if node is None:
        pytest.skip("node is not available in this environment")
    result = subprocess.run(
        [node, str(CHECK_SCRIPT)], capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["ok"] is True
    assert report["sealedLength"] == 5 + 48


def test_no_remote_script_is_referenced() -> None:
    """The bundle must not pull code or data from another origin at runtime."""
    for name in ("libsodium.js", "libsodium-wrappers.js"):
        text = (VENDOR / name).read_text(encoding="utf-8", errors="replace")
        for pattern in ("importScripts(", "document.write("):
            assert pattern not in text
