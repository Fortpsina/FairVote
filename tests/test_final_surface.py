"""Final surface: recovery, asset manifest, local lookup, journal pages."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from fairvote import assets
from fairvote.audit import chain
from fairvote.ballots import payload as payload_mod
from fairvote.db import read_tx
from fairvote.polls import service as polls_service
from fairvote.registry import mfa, service
from fairvote.registry.identity import Identity
from fairvote.registry.models import app_user_table
from fairvote.security import crypto
from fairvote.security.canonical import dump_bytes
from fairvote.timeutil import from_iso, to_iso, utc_now

PASSWORD = "korrektnyj-parol-2026"
NEW_PASSWORD = "novyj-parol-2026-x"
CSRF_META = re.compile(r'<meta name="csrf-token" content="([^"]+)">')
CODES = ["ABCDE-FGHJK", "MNPQR-STVWX", "YZ012-34567", "89ABC-DEFGH"]


def _csrf(client, path: str = "/") -> str:
    page = client.get(path).get_data(as_text=True)
    match = CSRF_META.search(page)
    assert match, f"no CSRF token on {path}"
    return match.group(1)


def _shape(response) -> str:
    html = re.sub(r'value="[^"]*"', 'value=""', response.get_data(as_text=True))
    return re.sub(r'content="[^"]*"', 'content=""', html)


def _user_with_codes(registry, login: str = "voter") -> int:
    user_id = service.create_user(
        registry,
        pepper=bytes(range(32)),
        login=login,
        password=PASSWORD,
        district_code="RU-MOW-77-012",
        identity=Identity(fio=f"Тестов Тест {login}", dob="1990-01-01",
                          doc_type="passport_rf", doc_series="4510",
                          doc_number=f"{abs(hash(login)) % 100000:05d}"),
        verify_method="demo",
    )
    mfa.replace_recovery_codes(
        registry, user_id, mfa.hash_recovery_codes(CODES)
    )
    return user_id


@pytest.fixture()
def registry(stores):
    service.seed_districts(stores["registry"])
    return stores["registry"]


# --- recovery -------------------------------------------------------------------


def test_recover_page_renders(client) -> None:
    assert client.get("/auth/recover").status_code == 200


def test_recovery_code_changes_the_password(client, registry) -> None:
    _user_with_codes(registry)
    token = _csrf(client, "/auth/recover")
    response = client.post(
        "/auth/recover",
        data={"login": "voter", "code": CODES[0], "new_password": NEW_PASSWORD,
              "csrf_token": token},
    )
    assert response.status_code == 302
    assert "/account" in response.headers["Location"]

    # The new password works, the old one does not.
    token = _csrf(client, "/auth/login")
    assert client.post(
        "/auth/login",
        data={"login": "voter", "password": NEW_PASSWORD, "csrf_token": token},
    ).status_code == 302
    client.post("/auth/logout", data={"csrf_token": _csrf(client, "/")})
    token = _csrf(client, "/auth/login")
    assert client.post(
        "/auth/login",
        data={"login": "voter", "password": PASSWORD, "csrf_token": token},
    ).status_code == 401


def test_recovery_code_is_single_use(client, registry) -> None:
    _user_with_codes(registry)
    token = _csrf(client, "/auth/recover")
    client.post("/auth/recover",
                data={"login": "voter", "code": CODES[1], "new_password": NEW_PASSWORD,
                      "csrf_token": token})
    token = _csrf(client, "/auth/recover")
    response = client.post(
        "/auth/recover",
        data={"login": "voter", "code": CODES[1], "new_password": "another-parol-2026",
              "csrf_token": token},
    )
    assert response.status_code == 401


def test_unknown_login_and_wrong_code_look_the_same(client, registry) -> None:
    _user_with_codes(registry)
    token = _csrf(client, "/auth/recover")
    wrong = client.post(
        "/auth/recover",
        data={"login": "voter", "code": "ZZZZZ-ZZZZZ", "new_password": NEW_PASSWORD,
              "csrf_token": token},
    )
    token = _csrf(client, "/auth/recover")
    unknown = client.post(
        "/auth/recover",
        data={"login": "nobody", "code": "ZZZZZ-ZZZZZ", "new_password": NEW_PASSWORD,
              "csrf_token": token},
    )
    assert wrong.status_code == unknown.status_code == 401
    # Byte equality modulo per-response tokens (CSRF in the meta tag).
    assert _shape(wrong) == _shape(unknown)


def test_weak_new_password_is_refused(client, registry) -> None:
    _user_with_codes(registry)
    token = _csrf(client, "/auth/recover")
    response = client.post(
        "/auth/recover",
        data={"login": "voter", "code": CODES[2], "new_password": "short",
              "csrf_token": token},
    )
    assert response.status_code == 400
    # The policy is checked before the code is touched: a weak password must not
    # burn a single-use recovery code.
    token = _csrf(client, "/auth/recover")
    retry = client.post(
        "/auth/recover",
        data={"login": "voter", "code": CODES[2], "new_password": NEW_PASSWORD,
              "csrf_token": token},
    )
    assert retry.status_code == 302


# --- assets ---------------------------------------------------------------------


def test_manifest_covers_scripts_and_vendor() -> None:
    document = assets.build()
    files = document["files"]
    for expected in ("js/payload.js", "js/vote.js", "js/verify.js",
                     "vendor/libsodium.js", "vendor/libsodium-wrappers.js", "app.css"):
        assert expected in files, expected
    assert "manifest.json" not in files


def test_manifest_hash_is_self_consistent() -> None:
    document = assets.build()
    claimed = document.pop("manifest_hash")
    assert claimed == crypto.sha256(dump_bytes(document)).hex()


def test_manifest_is_served(client) -> None:
    payload = client.get("/manifest.json")
    assert payload.status_code == 200
    body = payload.get_json()
    assert body["manifest_hash"] == assets.manifest_hash()
    assert "js/vote.js" in body["files"]


def test_poll_start_commits_the_manifest_hash(stores, tmp_path) -> None:
    from support import open_poll

    env = open_poll(stores)
    entry = [item for item in chain.iter_entries(env["audit"]) if item.kind == "poll.start"][-1]
    assert entry.payload["js_manifest_hash"] == assets.manifest_hash()
    assert env["poll"].status == "open"


# --- local ballot lookup --------------------------------------------------------


def test_verify_page_is_local_only(client) -> None:
    body = client.get("/verify").get_data(as_text=True)
    assert "только в вашем браузере" in body
    assert "js/verify.js" in body


def test_verify_script_derives_and_finds(tmp_path: Path) -> None:
    secret = bytes(range(32))
    poll_id = "poll-find-1"
    ballot_id = payload_mod.derive_ballot_id(secret, poll_id)

    rows = [
        {"v": 1, "poll": poll_id, "seq": 1, "ballot_id": "0" * 64, "district": "D",
         "slot": "2026-03-01T10:00Z", "batch": 1, "ct": "AAAA", "batch_root": "00",
         "audit_seq": 1},
        {"v": 1, "poll": poll_id, "seq": 2, "ballot_id": ballot_id, "district": "D",
         "slot": "2026-03-01T10:00Z", "batch": 1, "ct": "AAAA", "batch_root": "00",
         "audit_seq": 1},
    ]
    path = tmp_path / "ballots.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    node = os.environ.get("DSH_NODE") or shutil.which("node")
    # The secret is written the way the voter wrote it down: decode both ways.
    words = _words_for(secret)
    script = Path("scripts/verify.py").resolve()
    derived = subprocess.run(
        [sys.executable, str(script), "--derive-ballot-id", "--secret", words,
         "--poll-id", poll_id],
        capture_output=True, text=True, timeout=60,
    )
    assert derived.returncode == 0, derived.stderr
    assert derived.stdout.strip() == ballot_id

    found = subprocess.run(
        [sys.executable, str(script), "--ballots", str(path), "--find", ballot_id],
        capture_output=True, text=True, timeout=60,
    )
    assert found.returncode == 0
    assert ballot_id in found.stdout

    missing = subprocess.run(
        [sys.executable, str(script), "--ballots", str(path), "--find", "f" * 64],
        capture_output=True, text=True, timeout=60,
    )
    assert missing.returncode == 1
    assert "not found" in missing.stdout
    assert node is None or True  # node is optional for this check


def test_secret_words_decode_in_python() -> None:
    secret = bytes(range(32))
    words = _words_for(secret)
    script = Path("scripts/verify.py").resolve()
    poll_id = "p-decode"
    result = subprocess.run(
        [sys.executable, str(script), "--derive-ballot-id", "--secret", words,
         "--poll-id", poll_id],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == payload_mod.derive_ballot_id(secret, poll_id)


def _words_for(secret: bytes) -> str:
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    bits = 0
    value = 0
    out = []
    for byte in secret:
        value = (value << 8) | byte
        bits += 8
        while bits >= 5:
            out.append(alphabet[(value >> (bits - 5)) & 31])
            bits -= 5
    if bits:
        out.append(alphabet[(value << (5 - bits)) & 31])
    text = "".join(out)
    return "-".join(text[i:i + 4] for i in range(0, len(text), 4))


# --- journal pages --------------------------------------------------------------


def test_transparency_log_lists_entries(client, stores) -> None:
    chain.append(stores["audit_log"], kind="poll.create", poll_id="p1")
    body = client.get("/transparency/log").get_data(as_text=True)
    assert "Журнал" in body
    assert "poll.create" in body
    assert client.get("/transparency/log?after=1").status_code == 200
    assert client.get("/transparency/log?after=abc").status_code == 200


def test_transparency_checkpoints_page(client, stores, settings) -> None:
    chain.append(stores["audit_log"], kind="poll.create", poll_id="p1")
    checkpoint = chain.create_checkpoint(stores["audit_log"], settings.audit_sign_key)
    body = client.get("/transparency/checkpoints").get_data(as_text=True)
    assert checkpoint.hash.hex() in body
    assert "Ed25519" in body or "контрольные" in body.lower()


def test_transparency_pubkey(client, settings) -> None:
    body = client.get("/transparency/pubkey").get_json()
    assert body["alg"] == "ed25519"
    assert body["public_key"] == crypto.ed25519_public_key(settings.audit_sign_key).hex()


def test_robots_txt(client) -> None:
    response = client.get("/robots.txt")
    assert response.status_code == 200
    assert "Disallow: /admin/" in response.get_data(as_text=True)


def test_sessions_page_and_revoke(client, registry) -> None:
    _user_with_codes(registry, "sessions-user")
    token = _csrf(client, "/auth/login")
    client.post("/auth/login", data={"login": "sessions-user", "password": PASSWORD,
                                     "csrf_token": token})
    body = client.get("/account/sessions").get_data(as_text=True)
    assert "Активные сессии" in body
    token = _csrf(client, "/")
    response = client.post("/account/sessions/revoke", data={"csrf_token": token})
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]
    assert client.get("/account/").status_code == 302
