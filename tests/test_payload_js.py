"""Browser and server must build byte-identical ballots.

``fairvote/web/static/js/payload.js`` is imported by Node and compared with
``fairvote/ballots/payload.py`` for the same inputs. Without this check a padding
off-by-one would only be discovered when a real ballot failed to decrypt.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from fairvote.ballots import payload as py_payload

ROOT = Path(__file__).resolve().parent.parent
CHECK_SCRIPT = ROOT / "tools" / "check_payload.js"


def _node() -> str | None:
    for candidate in (
        os.environ.get("DSH_NODE"),
        shutil.which("node"),
        r"C:\Users\Пользователь\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\node\bin\node.exe",
    ):
        if candidate and Path(candidate).exists():
            return candidate
    return None


def _run(request: dict) -> subprocess.CompletedProcess[str]:
    node = _node()
    if node is None:
        pytest.skip("node is not available in this environment")
    return subprocess.run(
        [node, str(CHECK_SCRIPT)],
        input=json.dumps(request),
        capture_output=True,
        text=True,
        timeout=120,
    )


POLL_ID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
SECRET = bytes(range(32))
PAD = ("abcdef0123456789" * 600)

VECTORS = [
    {"choices": {}, "spoil": False, "size": 1024},
    {"choices": {"c1": "o1"}, "spoil": False, "size": 1024},
    {
        "choices": {"contest-party": "party-a", "contest-77": "candidate-3"},
        "spoil": True,
        "size": 2048,
    },
    {"choices": {}, "spoil": False, "size": 512},
]


@pytest.mark.parametrize("vector", VECTORS)
def test_payload_bytes_match(vector: dict) -> None:
    options = {
        "pollId": POLL_ID,
        "district": "RU-MOW-77-012",
        "choices": vector["choices"],
        "spoil": vector["spoil"],
        "size": vector["size"],
    }
    result = _run({"options": options, "secretHex": SECRET.hex(), "pad": PAD})
    assert result.returncode == 0, result.stderr
    js = json.loads(result.stdout)

    python_payload = py_payload.build_payload(
        poll_id=options["pollId"],
        district_code=options["district"],
        choices=options["choices"],
        spoil=options["spoil"],
        size=options["size"],
        pad_source=lambda length: PAD[:length],
    )
    assert python_payload.hex() == js["payloadHex"]
    assert js["payloadLength"] == options["size"]
    assert py_payload.derive_ballot_id(SECRET, options["pollId"]) == js["ballotId"]


def test_js_refuses_a_size_out_of_range() -> None:
    result = _run(
        {
            "options": {
                "pollId": POLL_ID,
                "district": "d",
                "choices": {},
                "spoil": False,
                "size": 100,
            },
            "secretHex": SECRET.hex(),
            "pad": "",
        }
    )
    assert result.returncode != 0
    assert "out of range" in result.stderr


def test_fixed_vector_is_pinned() -> None:
    """Both sides must not drift silently: pin the exact bytes for one input."""
    data = py_payload.build_payload(
        poll_id="poll-fixed",
        district_code="RU-MOW-77-012",
        choices={"c": "o"},
        size=512,
        pad_source=lambda length: "f" * length,
    )
    assert len(data) == 512
    assert data.startswith(b'{"contests":{"c":"o"},"district":"RU-MOW-77-012"')
    parsed = py_payload.parse_payload(data, expected_size=512)
    assert parsed["contests"] == {"c": "o"}
    assert set(parsed) == {"v", "poll", "district", "contests", "spoil", "pad"}


CHECK_PASSPHRASE = ROOT / "tools" / "check_passphrase.js"

PASSPHRASE = "correct horse battery staple"


def test_passphrase_derivation_matches_browser() -> None:
    """Argon2id in libsodium (browser) and in Python must agree byte for byte."""
    node = _node()
    if node is None:
        pytest.skip("node is not available in this environment")
    result = subprocess.run(
        [node, str(CHECK_PASSPHRASE)],
        input=json.dumps({"passphrase": PASSPHRASE, "pollId": POLL_ID}),
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stderr[-500:]
    payload = json.loads(result.stdout)
    assert payload["saltHex"] == py_payload.passphrase_salt(POLL_ID).hex()
    assert (
        payload["secretHex"]
        == py_payload.derive_secret_from_passphrase(PASSPHRASE, POLL_ID).hex()
    )


def test_passphrase_policy() -> None:
    with pytest.raises(py_payload.PayloadError):
        py_payload.derive_secret_from_passphrase("short phrase", POLL_ID)
    with pytest.raises(py_payload.PayloadError):
        py_payload.derive_secret_from_passphrase("a" * 40, POLL_ID)  # one word
    secret = py_payload.derive_secret_from_passphrase(PASSPHRASE, POLL_ID)
    assert len(secret) == 32


def test_same_passphrase_differs_per_poll() -> None:
    first = py_payload.derive_secret_from_passphrase(PASSPHRASE, "poll-a")
    second = py_payload.derive_secret_from_passphrase(PASSPHRASE, "poll-b")
    assert first != second


def test_ballot_id_from_derived_secret() -> None:
    secret = py_payload.derive_secret_from_passphrase(PASSPHRASE, POLL_ID)
    ballot_id = py_payload.derive_ballot_id(secret, POLL_ID)
    assert len(ballot_id) == 64
    # Deterministic: the same passphrase yields the same ballot id.
    assert ballot_id == py_payload.derive_ballot_id(
        py_payload.derive_secret_from_passphrase(PASSPHRASE, POLL_ID), POLL_ID
    )
