"""The offline key generator: format, fingerprint and the Shamir refusal."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from fairvote.security import crypto

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "poll_keygen.py"


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_keygen_writes_matching_pair(tmp_path: Path) -> None:
    result = _run("--out", str(tmp_path), "--poll", "poll-42")
    assert result.returncode == 0, result.stderr

    public = json.loads((tmp_path / "poll-42.pub.json").read_text(encoding="utf-8"))
    private = json.loads((tmp_path / "poll-42.priv.json").read_text(encoding="utf-8"))

    assert public["fingerprint"] == private["fingerprint"]
    assert public["fingerprint"] == crypto.blake2b_hex(bytes.fromhex(public["public_key"]))
    derived = crypto.x25519_public_from_private(bytes.fromhex(private["private_key"]))
    assert derived.hex() == public["public_key"]
    assert "OFFLINE ONLY" in private["warning"]


def test_private_key_file_is_owner_only(tmp_path: Path) -> None:
    if os.name == "nt":
        # Windows has no POSIX permission bits; chmod is a no-op there. The check
        # matters on the target host (Linux), where the script does set 0600.
        pytest.skip("POSIX permissions are not meaningful on Windows")
    result = _run("--out", str(tmp_path), "--poll", "p1")
    assert result.returncode == 0
    mode = stat.S_IMODE((tmp_path / "p1.priv.json").stat().st_mode)
    assert mode & (stat.S_IRWXG | stat.S_IRWXO) == 0


def test_shamir_is_refused_explicitly(tmp_path: Path) -> None:
    result = _run("--out", str(tmp_path), "--poll", "p1", "--shamir", "3")
    assert result.returncode == 2
    assert "not implemented" in result.stderr
    assert not list(tmp_path.glob("*.json"))


def test_that_the_printed_fingerprint_is_the_committed_one(tmp_path: Path) -> None:
    result = _run("--out", str(tmp_path), "--poll", "p9")
    assert result.returncode == 0
    fingerprint = json.loads((tmp_path / "p9.pub.json").read_text(encoding="utf-8"))[
        "fingerprint"
    ]
    assert fingerprint in result.stdout
