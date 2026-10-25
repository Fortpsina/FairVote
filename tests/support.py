"""Helpers shared by the ballot tests.

Kept out of ``conftest.py`` so that a test can import them explicitly and so that
the fixture wiring in each module stays visible.
"""

from __future__ import annotations

import hashlib
from typing import Any

from fairvote.ballots import payload as payload_mod
from fairvote.db import write_tx
from fairvote.polls import service as polls_service
from fairvote.registry import service as registry_service
from fairvote.registry.models import app_user_table
from fairvote.security import crypto
from fairvote.timeutil import to_iso, utc_now

PAYLOAD_SIZE = 1024


def add_user(registry, login: str, district_code: str = "RU-MOW-77-012") -> int:
    district = registry_service.get_district(registry, district_code)
    # These synthetic voters were verified before the fixed 2026 poll start.
    stamp = "2025-12-31T00:00:00Z"
    with write_tx(registry) as connection:
        result = connection.execute(
            app_user_table.insert().values(
                login=login,
                login_display=login,
                password_hash="$argon2id$v=19$m=1,t=1,p=1$abc$def",
                district_id=district["id"],
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


def open_poll(
    stores,
    *,
    payload_size: int = PAYLOAD_SIZE,
    before_start=None,
    key_publish_after: str | None = None,
) -> dict[str, Any]:
    """An open poll with a committed key and one district, ready for ballots.

    ``before_start(polls_store, poll_id)`` runs while the poll is still editable —
    that is where contests and options must be added, because content is frozen at
    the start.
    """
    polls = stores["polls"]
    audit = stores["audit_log"]
    registry = stores["registry"]
    registry_service.seed_districts(registry)
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
        ballot_plaintext_bytes=payload_size,
        key_publish_after=key_publish_after,
    )
    polls_service.set_public_key(polls, audit, poll_id, public_key)
    polls_service.add_district(
        polls, poll_id, district_code="RU-MOW-77-012", display_name="Округ 012"
    )
    if before_start is not None:
        before_start(polls, poll_id)
    polls_service.commit_start(polls, registry, audit, poll_id)
    return {
        "poll": polls_service.get_poll(polls, poll_id),
        "private_key": private_key,
        "public_key": public_key,
        "polls": polls,
        "audit": audit,
        "registry": registry,
        "box": stores["ballot_box"],
    }


def make_ballot(
    env: dict[str, Any],
    *,
    user_id: int,
    secret: bytes | None = None,
    nonce: bytes | None = None,
    choices: dict[str, str] | None = None,
) -> dict[str, Any]:
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
        secret=secret,
    )
