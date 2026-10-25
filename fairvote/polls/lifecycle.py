"""Closing a poll, publishing the key, and computing results.

The closing sequence is the moment the promise "anyone can recount" becomes true, so
the order is fixed and idempotent (docs/02 §2.4.8):

1. flush the last batch of ballots;
2. close the poll and commit a ``poll.close`` record with the box head and counts;
3. publish the private key — only after ``max(closed_at, key_publish_after)``, and
   only if its fingerprint matches the commitment made before the start;
4. tally locally for the results page, committing a ``poll.results`` record.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select

from ..audit import chain
from ..ballots import queue as ballot_queue
from ..ballots import tally as tally_mod
from ..ballots.models import published_key_table
from ..ballots.models import ballot_queue_table, ballot_table
from ..db import Store, read_tx, write_tx
from ..security import crypto
from ..security.canonical import dumps
from ..timeutil import from_iso, to_iso, utc_now
from . import service as polls_service
from .models import contest_table, option_table, poll_table


class PollStateError(polls_service.PollError):
    """The poll is not in a state that allows this operation."""


def _box_stats(box: Store, poll_id: str) -> dict:
    rows = list(ballot_queue.iter_ballots(box, poll_id))
    by_district: dict[str, int] = {}
    for row in rows:
        by_district[row["district"]] = by_district.get(row["district"], 0) + 1
    head = rows[-1]["seq"] if rows else 0
    return {
        "box_count": len(rows),
        "box_head_seq": head,
        "counts_by_district": dict(sorted(by_district.items())),
    }


def close_poll(
    store: Store,
    audit: Store,
    poll_id: str,
    *,
    box: Store | None = None,
    now: datetime | None = None,
) -> polls_service.Poll:
    poll = polls_service.get_poll(store, poll_id)
    if poll.status in {"closed", "published"}:
        return poll
    if poll.status != "open":
        raise PollStateError("закрыть можно только открытый опрос")
    moment = now or utc_now()
    if moment < from_iso(poll.ends_at):
        raise PollStateError("опрос ещё не закончился")

    # All callers (CLI, admin and daily) must flush the entire confirmed queue,
    # including queues larger than one batch, before committing final counts.
    if box is not None:
        while ballot_queue.commit_batch(box, audit, poll_id, force=True, now=moment):
            pass
        # An interrupted acceptance must be investigated before sealing results.
        # It cannot safely be attributed to a user after the fact.
        with read_tx(box) as connection:
            unresolved = connection.execute(
                select(ballot_queue_table.c.id)
                .where(ballot_queue_table.c.poll_id == poll_id).limit(1)
            ).first()
        if unresolved is not None:
            raise PollStateError("в очереди есть неподтверждённые бюллетени; требуется разбор сбоя")
    stats = _box_stats(box, poll_id) if box is not None else {}
    stamp = to_iso(moment)
    if not chain.has_entry(audit, kind="poll.close", poll_id=poll_id):
        chain.append(
            audit,
            kind="poll.close",
            poll_id=poll_id,
            payload={**stats, "ends_at": poll.ends_at, "k_threshold": poll.k_threshold},
            ts=stamp,
        )
    with write_tx(store) as connection:
        connection.execute(
            poll_table.update()
            .where(poll_table.c.id == poll_id)
            .values(status="closed", closed_at=stamp, updated_at=stamp)
        )
    return polls_service.get_poll(store, poll_id)


def publish_private_key(
    store: Store,
    audit: Store,
    box: Store,
    poll_id: str,
    private_key: bytes,
    *,
    now: datetime | None = None,
) -> polls_service.Poll:
    poll = polls_service.get_poll(store, poll_id)
    if poll.private_key_published_at:
        return poll
    if poll.status != "closed":
        raise PollStateError("ключ публикуется после закрытия опроса")
    if poll.key_publish_after is not None:
        moment = now or utc_now()
        if moment < from_iso(poll.key_publish_after):
            raise PollStateError("публикация ключа отложена до " + poll.key_publish_after)

    derived = crypto.x25519_public_from_private(private_key)
    fingerprint = crypto.blake2b_hex(derived)
    if poll.key_fingerprint and fingerprint != poll.key_fingerprint:
        raise PollStateError("ключ не совпадает с обязательством, опубликованным до старта")

    stamp = to_iso(now or utc_now())
    with write_tx(box) as connection:
        existing = connection.execute(
            select(published_key_table.c.poll_id).where(published_key_table.c.poll_id == poll_id)
        ).first()
        values = dict(
            public_key=derived,
            private_key=private_key,
            fingerprint=fingerprint,
            published_at=stamp,
        )
        if existing is None:
            connection.execute(published_key_table.insert().values(poll_id=poll_id, **values))
        else:
            connection.execute(
                published_key_table.update()
                .where(published_key_table.c.poll_id == poll_id)
                .values(**values)
            )
    with write_tx(store) as connection:
        connection.execute(
            poll_table.update()
            .where(poll_table.c.id == poll_id)
            .values(
                status="published",
                private_key_published_at=stamp,
                updated_at=stamp,
            )
        )
    chain.append(
        audit,
        kind="poll.key_publish",
        poll_id=poll_id,
        payload={"fingerprint": fingerprint, "public_key": derived.hex()},
        ts=stamp,
    )
    return polls_service.get_poll(store, poll_id)


def published_key(box: Store, poll_id: str) -> dict | None:
    with read_tx(box) as connection:
        row = connection.execute(
            select(
                published_key_table.c.public_key,
                published_key_table.c.private_key,
                published_key_table.c.fingerprint,
                published_key_table.c.published_at,
            ).where(published_key_table.c.poll_id == poll_id)
        ).first()
    if row is None:
        return None
    return {
        "public_key": bytes(row[0]),
        "private_key": bytes(row[1]) if row[1] is not None else None,
        "fingerprint": row[2],
        "published_at": row[3],
    }


def _contests(store: Store, poll_id: str) -> list[tally_mod.Contest]:
    with read_tx(store) as connection:
        contests = connection.execute(
            select(
                contest_table.c.id,
                contest_table.c.scope,
                contest_table.c.district_code,
            ).where(contest_table.c.poll_id == poll_id)
        ).all()
        result = []
        for contest in contests:
            options = {
                row[0]
                for row in connection.execute(
                    select(option_table.c.id).where(option_table.c.contest_id == contest[0])
                )
            }
            result.append(
                tally_mod.Contest(
                    id=contest[0],
                    scope=contest[1],
                    district_code=contest[2],
                    option_ids=frozenset(options),
                )
            )
    return result


def compute_results(
    store: Store, box: Store, poll_id: str, *, private_key: bytes | None = None
) -> tally_mod.Tally:
    poll = polls_service.get_poll(store, poll_id)
    if poll.status != "published":
        raise PollStateError("результаты недоступны до публикации ключа")
    key = private_key
    if key is None:
        stored = published_key(box, poll_id)
        if stored is None or stored["private_key"] is None:
            raise PollStateError("опубликованный ключ не найден")
        key = stored["private_key"]
    rows = list(ballot_queue.iter_ballots(box, poll_id))
    return tally_mod.tally_ballots(
        rows,
        _contests(store, poll_id),
        poll_id=poll_id,
        expected_size=poll.ballot_plaintext_bytes,
        private_key=key,
        k_threshold=poll.k_threshold,
    )


def record_results(
    store: Store, audit: Store, poll_id: str, tally: tally_mod.Tally
) -> None:
    """Commit a `poll.results` record so the published numbers have a timestamp."""
    if chain.has_entry(audit, kind="poll.results", poll_id=poll_id):
        return
    digest = crypto.sha256(dumps(tally.as_dict()).encode("utf-8")).hex()
    chain.append(
        audit,
        kind="poll.results",
        poll_id=poll_id,
        payload={"results_sha256": digest, "valid": tally.valid, "spoiled": tally.spoiled},
    )


def poll_ballots(box: Store, poll_id: str) -> list[dict]:
    with read_tx(box) as connection:
        count = connection.execute(
            select(ballot_table.c.seq).where(ballot_table.c.poll_id == poll_id).limit(1)
        ).first()
    if count is None:
        return []
    return list(ballot_queue.iter_ballots(box, poll_id))
