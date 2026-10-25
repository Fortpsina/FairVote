"""Accepting a ballot: validation, idempotency, one ballot per person.

Ordering matters (docs/02 §2.5.3): the ciphertext is staged in ``ballot_queue``
first, then participation is recorded in the registry, and only then is the row
confirmed. These are separate transactions: a crash after participation commits
can leave the account marked as voted and its ballot unconfirmed. Such a row is
never reported as accepted on retry or silently discarded by daily maintenance.
The protocol still needs a recovery design before production use.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

from ..db import Store, read_tx, write_tx
from ..polls.service import Poll
from ..registry.models import app_user_table, district_table, participation_table
from ..timeutil import date_today, from_iso, iso_now, utc_now
from .models import ballot_queue_table
from .payload import SEAL_OVERHEAD

BALLOT_ID_PATTERN = re.compile(r"^[0-9a-f]{64}$")
NONCE_BYTES = 16


class BallotError(ValueError):
    """A ballot was refused. The message is safe to show but stays generic."""


class AlreadyVoted(BallotError):
    """This account has already cast a ballot in this poll."""


class BallotRejected(BallotError):
    """Malformed payload, reused pseudonym, or a nonce reuse with new content."""


@dataclass(frozen=True)
class Acceptance:
    ballot_id: str
    duplicate: bool


def hour_slot(moment: datetime | None = None) -> str:
    """Coarse timestamp: the only time information the box keeps (docs/01 T11)."""
    stamp = iso_now() if moment is None else moment.strftime("%Y-%m-%dT%H:%M:%SZ")
    return stamp[:13] + ":00Z"


def validate_shape(
    *, poll: Poll, ballot_id: str, nonce: bytes, ciphertext: bytes,
    now: datetime | None = None,
) -> None:
    moment = now or utc_now()
    if poll.status != "open" or not (from_iso(poll.starts_at) <= moment < from_iso(poll.ends_at)):
        raise BallotRejected("опрос не открыт")
    if not BALLOT_ID_PATTERN.fullmatch(ballot_id or ""):
        raise BallotRejected("некорректный идентификатор бюллетеня")
    if not isinstance(nonce, bytes) or len(nonce) != NONCE_BYTES:
        raise BallotRejected("некорректный nonce")
    expected = poll.ballot_plaintext_bytes + SEAL_OVERHEAD
    if not isinstance(ciphertext, bytes) or len(ciphertext) != expected:
        raise BallotRejected("некорректный размер бюллетеня")


def accept_ballot(
    box: Store,
    registry: Store,
    *,
    poll: Poll,
    user_id: int,
    district_code: str,
    ballot_id: str,
    nonce: bytes,
    ciphertext: bytes,
    now: datetime | None = None,
) -> Acceptance:
    validate_shape(poll=poll, ballot_id=ballot_id, nonce=nonce, ciphertext=ciphertext, now=now)
    # Use the same eligibility predicate as the snapshot committed at poll start.
    # No identity or ballot reference is added to the registry by this check.
    with read_tx(registry) as connection:
        eligible = connection.execute(
            select(app_user_table.c.id)
            .select_from(app_user_table.join(district_table))
            .where(
                app_user_table.c.id == user_id,
                app_user_table.c.status == "verified",
                app_user_table.c.voter_key.is_not(None),
                app_user_table.c.verify_decided_at <= poll.starts_at,
                district_table.c.code == district_code,
            )
        ).first()
    if eligible is None:
        raise BallotRejected("нет допуска к опросу")
    stamp = iso_now() if now is None else now.strftime("%Y-%m-%dT%H:%M:%SZ")

    with write_tx(box) as connection:
        existing = connection.execute(
            select(
                ballot_queue_table.c.ballot_id, ballot_queue_table.c.ciphertext,
                ballot_queue_table.c.confirmed,
            ).where(
                ballot_queue_table.c.poll_id == poll.id,
                ballot_queue_table.c.client_nonce == nonce,
            )
        ).first()
        if existing is not None:
            # A retry of the same submission is not a second vote.
            if existing[0] == ballot_id and bytes(existing[1]) == ciphertext:
                if not existing[2]:
                    # A crash may have left staging without a committed vote.
                    # Never report success for a row the exporter will omit.
                    raise BallotRejected("запись бюллетеня не подтверждена")
                return Acceptance(ballot_id=ballot_id, duplicate=True)
            raise BallotRejected("nonce уже использован")
        try:
            connection.execute(
                ballot_queue_table.insert().values(
                    poll_id=poll.id,
                    ballot_id=ballot_id,
                    district_code=district_code,
                    client_nonce=nonce,
                    ciphertext=ciphertext,
                    received_slot=hour_slot(now),
                    confirmed=0,
                    created_at=stamp,
                )
            )
        except IntegrityError as exc:
            # UNIQUE(poll_id, ballot_id): the pseudonym belongs to another ballot.
            raise BallotRejected("идентификатор бюллетеня уже занят") from exc

    try:
        with write_tx(registry) as connection:
            connection.execute(
                participation_table.insert().values(
                    poll_id=poll.id,
                    user_id=user_id,
                    voted_on=date_today() if now is None else now.date().isoformat(),
                )
            )
    except IntegrityError as exc:
        # Participation is per account: the second attempt must not be counted.
        with write_tx(box) as connection:
            connection.execute(
                delete(ballot_queue_table).where(
                    ballot_queue_table.c.poll_id == poll.id,
                    ballot_queue_table.c.client_nonce == nonce,
                )
            )
        raise AlreadyVoted("голос уже учтён") from exc

    with write_tx(box) as connection:
        connection.execute(
            update(ballot_queue_table)
            .where(
                ballot_queue_table.c.poll_id == poll.id,
                ballot_queue_table.c.client_nonce == nonce,
            )
            .values(confirmed=1)
        )
    return Acceptance(ballot_id=ballot_id, duplicate=False)


def has_voted(registry: Store, poll_id: str, user_id: int) -> bool:
    with read_tx(registry) as connection:
        row = connection.execute(
            select(participation_table.c.user_id).where(
                participation_table.c.poll_id == poll_id,
                participation_table.c.user_id == user_id,
            )
        ).first()
    return row is not None


def voted_on(registry: Store, poll_id: str, user_id: int) -> date | None:
    with read_tx(registry) as connection:
        row = connection.execute(
            select(participation_table.c.voted_on).where(
                participation_table.c.poll_id == poll_id,
                participation_table.c.user_id == user_id,
            )
        ).first()
    return date.fromisoformat(row[0]) if row else None
