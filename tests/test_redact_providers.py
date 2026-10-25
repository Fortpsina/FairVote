"""Log scrubbing and the verification provider boundary (M11 audit)."""

from __future__ import annotations

import logging

import pytest

from fairvote.config import Settings
from fairvote.db import read_tx
from fairvote.registry import providers, service, verification
from fairvote.registry.identity import Identity
from fairvote.registry.models import verification_request_table
from fairvote.security import redact


# --- redaction ------------------------------------------------------------------


@pytest.mark.parametrize(
    "secret",
    [
        "10.1.2.3",
        "2001:db8::ff00:42:8329",
        "user@example.org",
        "a" * 64,
        "ZmFpcnZvdGUtdG9rZW4tYmFzZTY0LWVuY29kZWQtdmFsdWU=",
    ],
)
def test_scrub_removes_identifiers(secret: str) -> None:
    assert secret not in redact.scrub(f"value={secret} done")
    assert redact.REPLACEMENT in redact.scrub(f"value={secret} done")


def test_scrub_keeps_ordinary_text() -> None:
    assert redact.scrub("vote.accepted poll=abc seq=12") == "vote.accepted poll=abc seq=12"


def test_filter_scrubs_message_and_arguments() -> None:
    record = logging.LogRecord(
        name="fairvote", level=logging.INFO, pathname=__file__, lineno=1,
        msg="login from %s for %s", args=("192.0.2.7", "a" * 64), exc_info=None,
    )
    redact.RedactFilter().filter(record)
    formatted = record.getMessage()
    assert "192.0.2.7" not in formatted
    assert "a" * 64 not in formatted


def test_app_logs_do_not_contain_a_ballot_id(client, stores, caplog) -> None:
    """A full vote must not put the ballot id into any log record."""
    from fairvote.ballots import queue as ballot_queue
    from support import add_user, make_ballot, open_poll

    env = open_poll(stores, before_start=lambda polls, poll_id: None)
    user_id = add_user(env["registry"], "log-check")
    ballot = make_ballot(env, user_id=user_id, choices={})
    ballot_id = ballot["ballot_id"]

    with caplog.at_level(logging.DEBUG):
        from fairvote.ballots import service as ballot_service

        ballot_service.accept_ballot(
            env["box"], env["registry"],
            **{key: ballot[key] for key in
               ("poll", "user_id", "district_code", "ballot_id", "nonce", "ciphertext")},
        )
        ballot_queue.commit_batch(env["box"], env["audit"], env["poll"].id, force=True)
        client.get("/")

    for record in caplog.records:
        assert ballot_id not in record.getMessage()


# --- providers ------------------------------------------------------------------


def _user(registry, login: str = "voter") -> service.User:
    user_id = service.create_user(
        registry,
        pepper=bytes(range(32)),
        login=login,
        password="korrektnyj-parol-2026",
        district_code="RU-MOW-77-012",
        identity=Identity(fio=f"Тестов Тест {login}", dob="1990-01-01",
                          doc_type="passport_rf", doc_series="4510",
                          doc_number=f"{abs(hash(login)) % 100000:05d}"),
        verify_method="manual",
    )
    found = service.find_by_id(registry, user_id)
    assert found is not None
    return found


@pytest.fixture()
def registry(stores):
    service.seed_districts(stores["registry"])
    return stores["registry"]


def test_manual_provider_leaves_the_request_pending(registry) -> None:
    user = _user(registry)
    code, request = providers.ManualProvider().request(registry, user)
    assert len(code) == 9
    assert service.find_by_id(registry, user.id).status == "proof_submitted"
    assert verification.pending_requests(registry) == 1


def test_demo_provider_decides_immediately(registry) -> None:
    user = _user(registry, "demo-user")
    code, _request = providers.DemoProvider().request(registry, user)
    refreshed = service.find_by_id(registry, user.id)
    assert refreshed.status == "verified"
    assert refreshed.verify_method == "demo"
    with read_tx(registry) as connection:
        row = connection.execute(verification_request_table.select()).mappings().one()
    assert row["decision"] == "approved"
    assert row["decided_by"] == "demo"


def test_provider_selection_depends_on_demo_mode(tmp_path) -> None:
    demo = Settings(
        instance_dir=tmp_path, demo_mode=True, ephemeral_keys=True,
        secret_key=b"s" * 32, master_key=b"m" * 32, voter_pepper=b"p" * 32,
        audit_sign_key=b"a" * 32,
    )
    production = Settings(
        instance_dir=tmp_path, demo_mode=False, ephemeral_keys=False,
        secret_key=b"s" * 32, master_key=b"m" * 32, voter_pepper=b"p" * 32,
        audit_sign_key=b"a" * 32, operator_name="Оператор", legal_basis="согласие",
        contact="mail@example.org",
    )
    assert isinstance(providers.for_settings(demo), providers.DemoProvider)
    assert isinstance(providers.for_settings(production), providers.ManualProvider)


def test_web_request_uses_the_demo_provider(client, registry, stores) -> None:
    import re

    user = _user(registry, "web-demo")
    token_page = client.get("/auth/login").get_data(as_text=True)
    token = re.search(r'name="csrf-token" content="([^"]+)"', token_page).group(1)
    client.post("/auth/login", data={"login": "web-demo", "password": "korrektnyj-parol-2026",
                                     "csrf_token": token})
    page = client.get("/verification/").get_data(as_text=True)
    token = re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)
    response = client.post("/verification/request", data={"csrf_token": token})
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    # In demo mode the provider approves immediately, so the page shows the result.
    assert "подтверждён" in body
