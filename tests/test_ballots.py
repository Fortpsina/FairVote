"""Ballot payload format and the acceptance pipeline."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from fairvote.ballots import payload as payload_mod
from fairvote.ballots import service
from fairvote.ballots.models import ballot_queue_table
from fairvote.db import read_tx, write_tx
from fairvote.polls import service as polls_service
from fairvote.registry.models import app_user_table, participation_table
from fairvote.security import crypto
from fairvote.timeutil import to_iso, utc_now

PAYLOAD_SIZE = 1024


# --- payload --------------------------------------------------------------------


def test_payload_has_exact_size() -> None:
    data = payload_mod.build_payload(
        poll_id="p1", district_code="D1", choices={}, size=PAYLOAD_SIZE
    )
    assert len(data) == PAYLOAD_SIZE
    assert payload_mod.parse_payload(data, expected_size=PAYLOAD_SIZE)["poll"] == "p1"


def test_payload_padding_is_random() -> None:
    first = payload_mod.build_payload(poll_id="p", district_code="d", choices={}, size=1024)
    second = payload_mod.build_payload(poll_id="p", district_code="d", choices={}, size=1024)
    assert first != second
    assert len(first) == len(second) == 1024


def test_payload_with_choices_fits() -> None:
    choices = {f"contest-{index}": f"option-{index}" for index in range(5)}
    data = payload_mod.build_payload(
        poll_id="p", district_code="d", choices=choices, spoil=True, size=1024
    )
    parsed = payload_mod.parse_payload(data, expected_size=1024)
    assert parsed["contests"] == choices
    assert parsed["spoil"] is True


def test_payload_that_does_not_fit_is_refused() -> None:
    choices = {f"c{index}": f"o{index}" for index in range(40)}
    with pytest.raises(payload_mod.PayloadError):
        payload_mod.build_payload(
            poll_id="p", district_code="d", choices=choices, size=512
        )


def test_payload_size_bounds() -> None:
    for size in (256, 8193):
        with pytest.raises(payload_mod.PayloadError):
            payload_mod.build_payload(poll_id="p", district_code="d", choices={}, size=size)


def test_parse_rejects_garbage() -> None:
    with pytest.raises(payload_mod.PayloadError):
        payload_mod.parse_payload(b"not json")
    with pytest.raises(payload_mod.PayloadError):
        payload_mod.parse_payload(b'{"v":2}')
    with pytest.raises(payload_mod.PayloadError):
        payload_mod.parse_payload(b'{"v":1,"poll":"p","district":"d","contests":[]}')


def test_ballot_id_derivation_matches_hmac() -> None:
    secret = bytes(range(32))
    expected = crypto.hmac_sha256(secret, b"fairvote/ballot/v1\x00poll-1").hex()
    assert payload_mod.derive_ballot_id(secret, "poll-1") == expected
    assert len(payload_mod.derive_ballot_id(secret, "poll-1")) == 64


def test_sealed_size() -> None:
    assert payload_mod.sealed_size(1024) == 1072


# --- fixtures -------------------------------------------------------------------


def _user(registry, login: str, district_code: str = "RU-MOW-77-012") -> int:
    district_id = polls_service.registry_service.get_district(registry, district_code)["id"]
    stamp = to_iso(utc_now())
    with write_tx(registry) as connection:
        result = connection.execute(
            app_user_table.insert().values(
                login=login,
                login_display=login,
                password_hash="$argon2id$v=19$m=1,t=1,p=1$abc$def",
                district_id=district_id,
                status="verified",
                role="voter",
                verify_method="demo",
                verify_decided_at=stamp,
                voter_key=hashlib.sha256(login.encode()).digest(),
                created_at=stamp,
                updated_at=stamp,
            )
        )
    return int(result.inserted_primary_key[0])


@pytest.fixture()
def env(stores):
    polls = stores["polls"]
    audit = stores["audit_log"]
    registry = stores["registry"]
    polls_service.registry_service.seed_districts(registry)
    private_key, public_key = crypto.x25519_keypair()
    poll_id = polls_service.create_poll(
        polls,
        audit,
        title="Опрос для бюллетеней",
        summary="Проверка приёма бюллетеней",
        description_md="Текст",
        system="list",
        starts_at="2026-01-01T00:00:00Z",
        ends_at="2026-12-31T00:00:00Z",
        k_threshold=1,
        ballot_plaintext_bytes=PAYLOAD_SIZE,
    )
    polls_service.set_public_key(polls, audit, poll_id, public_key)
    polls_service.add_district(
        polls, poll_id, district_code="RU-MOW-77-012", display_name="Округ 012"
    )
    polls_service.commit_start(polls, registry, audit, poll_id)
    poll = polls_service.get_poll(polls, poll_id)
    return {
        "poll": poll,
        "private_key": private_key,
        "public_key": public_key,
        "polls": polls,
        "audit": audit,
        "registry": registry,
        "box": stores["ballot_box"],
    }


def _ballot(env, *, user_id: int, secret: bytes | None = None, nonce: bytes | None = None, choices=None):
    secret = secret or crypto.random_bytes(32)
    poll = env["poll"]
    plaintext = payload_mod.build_payload(
        poll_id=poll.id,
        district_code="RU-MOW-77-012",
        choices=choices or {},
        size=poll.ballot_plaintext_bytes,
    )
    ciphertext = crypto.seal(plaintext, env["public_key"])
    return dict(
        poll=poll,
        user_id=user_id,
        district_code="RU-MOW-77-012",
        ballot_id=payload_mod.derive_ballot_id(secret, poll.id),
        nonce=nonce or crypto.random_bytes(16),
        ciphertext=ciphertext,
    )


def _accept(env, ballot, now=None):
    return service.accept_ballot(env["box"], env["registry"], **ballot, now=now)


# --- acceptance -----------------------------------------------------------------


def test_accept_stages_and_confirms(env) -> None:
    user_id = _user(env["registry"], "voter1")
    ballot = _ballot(env, user_id=user_id)
    result = _accept(env, ballot)
    assert result.duplicate is False
    with read_tx(env["box"]) as connection:
        row = connection.execute(ballot_queue_table.select()).mappings().one()
    assert row["confirmed"] == 1
    assert row["district_code"] == "RU-MOW-77-012"
    assert row["received_slot"].endswith(":00Z")
    with read_tx(env["registry"]) as connection:
        assert connection.execute(participation_table.select()).first() is not None


def test_retry_with_same_nonce_is_idempotent(env) -> None:
    user_id = _user(env["registry"], "voter1")
    ballot = _ballot(env, user_id=user_id)
    first = _accept(env, ballot)
    second = _accept(env, ballot)
    assert first.duplicate is False and second.duplicate is True
    with read_tx(env["box"]) as connection:
        assert len(connection.execute(ballot_queue_table.select()).all()) == 1


def test_nonce_reuse_with_new_content_is_refused(env) -> None:
    user_id = _user(env["registry"], "voter1")
    ballot = _ballot(env, user_id=user_id)
    _accept(env, ballot)
    with pytest.raises(service.BallotRejected):
        _accept(env, {**ballot, "ciphertext": crypto.seal(b"x" * PAYLOAD_SIZE, env["public_key"])})


def test_second_ballot_by_same_user_is_refused(env) -> None:
    user_id = _user(env["registry"], "voter1")
    _accept(env, _ballot(env, user_id=user_id))
    with pytest.raises(service.AlreadyVoted):
        _accept(env, _ballot(env, user_id=user_id))
    with read_tx(env["box"]) as connection:
        rows = connection.execute(ballot_queue_table.select()).all()
    assert len(rows) == 1  # the refused attempt left nothing behind


def test_ballot_id_cannot_be_reused_by_another_user(env) -> None:
    first_user = _user(env["registry"], "voter1")
    second_user = _user(env["registry"], "voter2")
    ballot = _ballot(env, user_id=first_user)
    _accept(env, ballot)
    stolen = _ballot(env, user_id=second_user, secret=b"\x01" * 32)
    with pytest.raises(service.BallotRejected):
        _accept(env, {**stolen, "ballot_id": ballot["ballot_id"]})


@pytest.mark.parametrize(
    "mutation",
    [
        {"ballot_id": "zz"},
        {"nonce": b"short"},
        {"ciphertext": b"short"},
    ],
)
def test_malformed_ballots_are_refused(env, mutation) -> None:
    user_id = _user(env["registry"], "voter1")
    ballot = {**_ballot(env, user_id=user_id), **mutation}
    with pytest.raises(service.BallotRejected):
        _accept(env, ballot)


def test_closed_poll_is_refused(env, polls_service_closed=None) -> None:
    user_id = _user(env["registry"], "voter1")
    poll = env["poll"]
    closed = type(poll)(**{**poll.__dict__, "status": "closed"})
    ballot = _ballot(env, user_id=user_id)
    with pytest.raises(service.BallotRejected):
        service.accept_ballot(
            env["box"], env["registry"], **{**ballot, "poll": closed}
        )


def test_has_voted(env) -> None:
    user_id = _user(env["registry"], "voter1")
    assert not service.has_voted(env["registry"], env["poll"].id, user_id)
    _accept(env, _ballot(env, user_id=user_id))
    assert service.has_voted(env["registry"], env["poll"].id, user_id)


def test_hour_slot_truncates_minutes() -> None:
    moment = datetime(2026, 3, 14, 9, 47, 12, tzinfo=timezone.utc)
    assert service.hour_slot(moment) == "2026-03-14T09:00Z"
