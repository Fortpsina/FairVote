"""Voting over HTTP: access rules, submission, one ballot per account."""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone

import pytest

from fairvote.ballots import payload as payload_mod
from fairvote.ballots import service as ballot_service
from fairvote.registry import service as registry_service
from fairvote.registry.identity import Identity
from fairvote.security import crypto
from fairvote.db import write_tx
from fairvote.registry.models import app_user_table
from support import open_poll

PASSWORD = "korrektnyj-parol-2026"
CSRF_META = re.compile(r'<meta name="csrf-token" content="([^"]+)">')
POPPY = "Poppy"  # placeholder to keep linters quiet about unused names


def _make_user(registry, login: str, district: str) -> int:
    return registry_service.create_user(
        registry,
        pepper=bytes(range(32)),
        login=login,
        password=PASSWORD,
        district_code=district,
        identity=Identity(
            fio=f"Тестов Тест {login}",
            dob="1990-01-01",
            doc_type="passport_rf",
            doc_series="4510",
            doc_number=f"9{abs(hash(login)) % 100000:05d}",
        ),
        verify_method="demo",
        now=datetime(2025, 12, 31, tzinfo=timezone.utc),
    )


def _login(client, login: str) -> None:
    page = client.get("/auth/login").get_data(as_text=True)
    token = CSRF_META.search(page).group(1)
    response = client.post(
        "/auth/login",
        data={"login": login, "password": PASSWORD, "csrf_token": token},
    )
    assert response.status_code == 302


def _csrf(client, path: str) -> str:
    page = client.get(path).get_data(as_text=True)
    match = CSRF_META.search(page)
    assert match, "page must expose the CSRF token"
    return match.group(1)


@pytest.fixture()
def env(stores):
    return open_poll(stores)


@pytest.fixture()
def voter(env):
    return _make_user(env["registry"], "voter", "RU-MOW-77-012")


@pytest.fixture()
def other_voter(env):
    return _make_user(env["registry"], "outsider", "RU-SPE-78-045")


def _sealed(env, *, size: int | None = None) -> bytes:
    poll = env["poll"]
    plaintext = payload_mod.build_payload(
        poll_id=poll.id,
        district_code="RU-MOW-77-012",
        choices={},
        size=size or poll.ballot_plaintext_bytes,
    )
    return crypto.seal(plaintext, env["public_key"])


def _ballot_json(env, *, ciphertext: bytes | None = None, ballot_id: str | None = None,
                 nonce: bytes | None = None) -> dict:
    return {
        "ballot_id": ballot_id or payload_mod.derive_ballot_id(crypto.random_bytes(32), env["poll"].id),
        "nonce": base64.b64encode(nonce or crypto.random_bytes(16)).decode(),
        "ciphertext": base64.b64encode(ciphertext or _sealed(env)).decode(),
    }


def test_vote_page_requires_login(client, env) -> None:
    response = client.get(f"/vote/{env['poll'].id}")
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_vote_page_shows_config(client, env, voter) -> None:
    _login(client, "voter")
    page = client.get(f"/vote/{env['poll'].id}").get_data(as_text=True)
    assert env["poll"].title in page
    config = json.loads(re.search(
        r'<script type="application/json" id="poll-config">(.*?)</script>', page, re.S
    ).group(1))
    assert config["poll_id"] == env["poll"].id
    assert config["public_key_hex"] == env["public_key"].hex()
    assert config["ballot_plaintext_bytes"] == env["poll"].ballot_plaintext_bytes
    assert config["district"] == "RU-MOW-77-012"
    assert "libsodium.js" in page
    assert "js/vote.js" in page


def test_verified_after_start_cannot_vote(client, env, voter):
    with write_tx(env["registry"]) as connection:
        connection.execute(app_user_table.update().where(app_user_table.c.id == voter)
                           .values(verify_decided_at="2026-02-01T00:00:00Z"))
    _login(client, "voter")
    assert client.get(f"/vote/{env['poll'].id}").status_code == 403


def test_config_omits_contests_for_other_districts(app, env):
    from fairvote.web.vote import poll_config
    from fairvote.polls.service import add_contest

    # Create a poll with scoped contests before committing its start.
    holder = {}
    def setup(store, poll_id):
        holder["national"] = add_contest(
            store, poll_id, title="Общий", kind="party_list")
        holder["local"] = add_contest(store, poll_id, title="Москва", kind="candidate",
                                      scope="district", district_code="RU-MOW-77-012")
        holder["other"] = add_contest(store, poll_id, title="Петербург", kind="candidate",
                                      scope="district", district_code="RU-SPE-78-045")
    scoped = open_poll(app.extensions["fairvote.stores"], before_start=setup)
    with app.app_context():
        config = poll_config(scoped["poll"], district="RU-MOW-77-012")
    assert {contest["id"] for contest in config["contests"]} == {holder["national"], holder["local"]}


def test_outsider_cannot_open_the_ballot(client, env, other_voter) -> None:
    _login(client, "outsider")
    assert client.get(f"/vote/{env['poll'].id}").status_code == 403


def test_submit_accepts_a_sealed_ballot(client, env, voter) -> None:
    _login(client, "voter")
    token = _csrf(client, f"/vote/{env['poll'].id}")
    body = _ballot_json(env)
    response = client.post(
        f"/vote/{env['poll'].id}",
        json=body,
        headers={"X-CSRFToken": token},
    )
    assert response.status_code == 200
    assert response.get_json()["ballot_id"] == body["ballot_id"]
    assert ballot_service.has_voted(env["registry"], env["poll"].id, voter)

    status = client.get(f"/vote/{env['poll'].id}/status").get_json()
    assert status["voted"] is True


def test_second_ballot_is_rejected(client, env, voter) -> None:
    _login(client, "voter")
    token = _csrf(client, f"/vote/{env['poll'].id}")
    first = client.post(f"/vote/{env['poll'].id}", json=_ballot_json(env),
                        headers={"X-CSRFToken": token})
    assert first.status_code == 200
    second = client.post(f"/vote/{env['poll'].id}", json=_ballot_json(env),
                         headers={"X-CSRFToken": token})
    assert second.status_code == 409
    assert second.get_json() == {"error": "rejected"}


def test_wrong_ciphertext_size_is_rejected(client, env, voter) -> None:
    _login(client, "voter")
    token = _csrf(client, f"/vote/{env['poll'].id}")
    short = _ballot_json(env, ciphertext=crypto.seal(b"x" * 100, env["public_key"]))
    assert client.post(f"/vote/{env['poll'].id}", json=short,
                       headers={"X-CSRFToken": token}).status_code == 409


def test_submission_without_csrf_is_refused(client, env, voter) -> None:
    _login(client, "voter")
    response = client.post(f"/vote/{env['poll'].id}", json=_ballot_json(env))
    assert response.status_code == 400


def test_page_reports_an_existing_vote(client, env, voter) -> None:
    _login(client, "voter")
    token = _csrf(client, f"/vote/{env['poll'].id}")
    client.post(f"/vote/{env['poll'].id}", json=_ballot_json(env),
                headers={"X-CSRFToken": token})
    page = client.get(f"/vote/{env['poll'].id}").get_data(as_text=True)
    assert "уже принят" in page
    assert 'id="ballot-form"' not in page


def test_config_endpoint(client, env, voter) -> None:
    _login(client, "voter")
    config = client.get(f"/vote/{env['poll'].id}/config").get_json()
    assert config["poll_id"] == env["poll"].id
    assert config["key_fingerprint"] == env["poll"].key_fingerprint


def test_public_poll_pages(client, env, voter) -> None:
    listing = client.get("/polls")
    assert listing.status_code == 200
    assert env["poll"].title in listing.get_data(as_text=True)

    detail = client.get(f"/polls/{env['poll'].slug}")
    assert detail.status_code == 200
    body = detail.get_data(as_text=True)
    assert env["poll"].eligibility_root.hex() in body
    assert "RU-MOW-77-012" in body


def test_unknown_poll_is_404(client) -> None:
    assert client.get("/polls/no-such-poll").status_code == 404
    assert client.get("/vote/" + "0" * 32).status_code == 404
