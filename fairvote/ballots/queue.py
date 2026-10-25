"""Batching the queue into the published ballot box.

Ballots leave the queue in batches, in shuffled order, with the hour of receipt
(never the minute). Each batch is committed to the audit chain by a Merkle root over
its ciphertexts, so a batch cannot be silently altered after publication
(docs/02 §2.5.4).

Everything happens inside one ``BEGIN IMMEDIATE`` on the ballot box, including the
audit append. The audit store is a different file, so the write is not atomic across
stores. The audit append commits before the box transaction: a crash or rollback
in between can leave an audit entry with no matching published batch. This requires
operator investigation; the lock order box → audit does not make the two commits
atomic. See docs/security-review-2026-10-26.md.

There is no background worker on the target host: batches are flushed lazily from a
request (with a small probability) and by the daily task.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select

from ..audit import chain
from ..db import Store, read_tx, write_tx
from ..merkle import merkle_root, seal_leaf
from ..timeutil import from_iso, iso_now, to_iso, utc_now
from .models import ballot_batch_table, ballot_queue_table, ballot_table

BATCH_LEAF_DOMAIN = b"fairvote/batch/v1"
MAX_BATCH_ROWS = 200


@dataclass(frozen=True)
class Batch:
    id: int
    poll_id: str
    size: int
    root: bytes
    slot: str
    audit_seq: int


def pending_count(box: Store, poll_id: str) -> int:
    with read_tx(box) as connection:
        return int(
            connection.execute(
                select(func.count())
                .select_from(ballot_queue_table)
                .where(
                    ballot_queue_table.c.poll_id == poll_id,
                    ballot_queue_table.c.confirmed == 1,
                )
            ).scalar_one()
        )


def oldest_pending(box: Store, poll_id: str) -> str | None:
    with read_tx(box) as connection:
        return connection.execute(
            select(func.min(ballot_queue_table.c.created_at)).where(
                ballot_queue_table.c.poll_id == poll_id,
                ballot_queue_table.c.confirmed == 1,
            )
        ).scalar()


def should_flush(
    box: Store,
    poll_id: str,
    *,
    min_size: int,
    max_delay_seconds: int,
    now: datetime | None = None,
) -> bool:
    count = pending_count(box, poll_id)
    if count == 0:
        return False
    if count >= min_size:
        return True
    oldest = oldest_pending(box, poll_id)
    if oldest is None:
        return False
    moment = now or utc_now()
    return moment - from_iso(oldest) >= timedelta(seconds=max_delay_seconds)


def batch_leaf(ciphertext: bytes) -> bytes:
    return seal_leaf(ciphertext, domain=BATCH_LEAF_DOMAIN)


def commit_batch(
    box: Store,
    audit: Store,
    poll_id: str,
    *,
    min_size: int = 8,
    max_delay_seconds: int = 2700,
    now: datetime | None = None,
    force: bool = False,
    max_rows: int = MAX_BATCH_ROWS,
) -> Batch | None:
    """Publish one batch, or return ``None`` when it is not time yet."""
    moment = now or utc_now()
    if not force and not should_flush(
        box, poll_id, min_size=min_size, max_delay_seconds=max_delay_seconds, now=moment
    ):
        return None

    stamp = to_iso(moment)
    with write_tx(box) as connection:
        rows = connection.execute(
            select(
                ballot_queue_table.c.id,
                ballot_queue_table.c.ballot_id,
                ballot_queue_table.c.district_code,
                ballot_queue_table.c.ciphertext,
                ballot_queue_table.c.received_slot,
                ballot_queue_table.c.created_at,
            )
            .where(
                ballot_queue_table.c.poll_id == poll_id,
                ballot_queue_table.c.confirmed == 1,
            )
            .order_by(ballot_queue_table.c.id)
            .limit(max_rows)
        ).all()
        if not rows:
            return None
        if not force and len(rows) < min_size:
            # ``received_slot`` is hour-granular by design; the delay policy needs
            # the real receipt time, which lives in ``created_at``.
            oldest = min(row[5] for row in rows)
            if moment - from_iso(oldest) < timedelta(seconds=max_delay_seconds):
                return None

        order = list(rows)
        secrets.SystemRandom().shuffle(order)
        slot = max(row[4] for row in rows)

        result = connection.execute(
            ballot_batch_table.insert().values(
                poll_id=poll_id,
                size=len(order),
                merkle_root=merkle_root([]),  # placeholder, replaced below
                slot=slot,
                audit_seq=0,
                created_at=stamp,
            )
        )
        batch_id = int(result.inserted_primary_key[0])

        connection.execute(
            ballot_table.insert(),
            [
                {
                    "poll_id": poll_id,
                    "ballot_id": row[1],
                    "district_code": row[2],
                    "ciphertext": bytes(row[3]),
                    "slot": row[4],
                    "batch_id": batch_id,
                }
                for row in order
            ],
        )

        claimed = connection.execute(
            delete(ballot_queue_table).where(
                ballot_queue_table.c.id.in_([row[0] for row in order])
            )
        )
        if int(claimed.rowcount or 0) != len(order):
            # Another worker flushed the same rows first: undo this batch entirely.
            raise RuntimeError("batch race detected; transaction rolled back")

        root = merkle_root(batch_leaf(bytes(row[3])) for row in order)
        connection.execute(
            ballot_batch_table.update()
            .where(ballot_batch_table.c.id == batch_id)
            .values(merkle_root=root)
        )

        seq_range = connection.execute(
            select(func.min(ballot_table.c.seq), func.max(ballot_table.c.seq)).where(
                ballot_table.c.batch_id == batch_id
            )
        ).one()

        # Audit append inside the box transaction: lock order is always box -> audit.
        entry = chain.append(
            audit,
            kind="ballot.batch",
            poll_id=poll_id,
            payload={
                "batch_id": batch_id,
                "size": len(order),
                "root": root.hex(),
                "slot": slot,
                "first_seq": int(seq_range[0]),
                "last_seq": int(seq_range[1]),
            },
            ts=stamp,
        )
        connection.execute(
            ballot_batch_table.update()
            .where(ballot_batch_table.c.id == batch_id)
            .values(audit_seq=entry.seq)
        )

    return Batch(
        id=batch_id,
        poll_id=poll_id,
        size=len(order),
        root=root,
        slot=slot,
        audit_seq=entry.seq,
    )


def list_batches(box: Store, poll_id: str) -> list[Batch]:
    with read_tx(box) as connection:
        rows = connection.execute(
            select(
                ballot_batch_table.c.id,
                ballot_batch_table.c.poll_id,
                ballot_batch_table.c.size,
                ballot_batch_table.c.merkle_root,
                ballot_batch_table.c.slot,
                ballot_batch_table.c.audit_seq,
            )
            .where(ballot_batch_table.c.poll_id == poll_id)
            .order_by(ballot_batch_table.c.id)
        ).all()
    return [
        Batch(
            id=int(row[0]),
            poll_id=row[1],
            size=int(row[2]),
            root=bytes(row[3]),
            slot=row[4],
            audit_seq=int(row[5]),
        )
        for row in rows
    ]


def iter_ballots(box: Store, poll_id: str):
    """Stream published rows in box order (used by the JSONL export)."""
    sql = (
        select(
            ballot_table.c.seq,
            ballot_table.c.ballot_id,
            ballot_table.c.district_code,
            ballot_table.c.ciphertext,
            ballot_table.c.slot,
            ballot_table.c.batch_id,
        )
        .where(ballot_table.c.poll_id == poll_id)
        .order_by(ballot_table.c.seq)
    )
    with read_tx(box) as connection:
        for row in connection.execute(sql):
            yield {
                "seq": int(row[0]),
                "ballot_id": row[1],
                "district": row[2],
                "ciphertext": bytes(row[3]),
                "slot": row[4],
                "batch_id": int(row[5]),
            }


def purge_unconfirmed(box: Store, *, older_than_seconds: int = 86400, now: datetime | None = None) -> int:
    """Drop abandoned staging rows (the voter never received a confirmation)."""
    moment = now or utc_now()
    cutoff = to_iso(moment - timedelta(seconds=older_than_seconds))
    with write_tx(box) as connection:
        result = connection.execute(
            delete(ballot_queue_table).where(
                ballot_queue_table.c.confirmed == 0,
                ballot_queue_table.c.created_at < cutoff,
            )
        )
    return int(result.rowcount or 0)
