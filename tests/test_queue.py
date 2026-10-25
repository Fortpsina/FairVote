"""Batching: ordering, delay policy, Merkle commitment, audit record."""

from __future__ import annotations

import secrets
from datetime import timedelta

import pytest
from sqlalchemy import select

from fairvote.audit import chain
from fairvote.ballots import queue, service
from fairvote.ballots.models import ballot_batch_table, ballot_queue_table, ballot_table
from fairvote.db import read_tx
from fairvote.timeutil import utc_now
from support import add_user, make_ballot, open_poll


@pytest.fixture()
def env(stores):
    return open_poll(stores)


def _accept(env, ballot):
    return service.accept_ballot(
        env["box"], env["registry"], **{k: ballot[k] for k in
        ("poll", "user_id", "district_code", "ballot_id", "nonce", "ciphertext")}
    )


def _fill(env, count: int) -> list[dict]:
    ballots = []
    for index in range(count):
        user_id = add_user(env["registry"], f"voter-{secrets.token_hex(4)}-{index}")
        ballot = make_ballot(env, user_id=user_id)
        _accept(env, ballot)
        ballots.append(ballot)
    return ballots


def test_batch_waits_for_size_or_delay(env) -> None:
    _fill(env, 2)
    assert queue.pending_count(env["box"], env["poll"].id) == 2
    assert queue.commit_batch(env["box"], env["audit"], env["poll"].id, min_size=8) is None
    assert queue.pending_count(env["box"], env["poll"].id) == 2


def test_batch_commits_after_delay(env) -> None:
    _fill(env, 1)
    future = utc_now() + timedelta(hours=2)
    batch = queue.commit_batch(
        env["box"], env["audit"], env["poll"].id, min_size=8, max_delay_seconds=60, now=future
    )
    assert batch is not None and batch.size == 1


def test_forced_batch_publishes_everything(env) -> None:
    _fill(env, 3)
    batch = queue.commit_batch(env["box"], env["audit"], env["poll"].id, force=True)
    assert batch is not None
    assert batch.size == 3
    assert queue.pending_count(env["box"], env["poll"].id) == 0
    with read_tx(env["box"]) as connection:
        assert len(connection.execute(ballot_table.select()).all()) == 3
        assert connection.execute(ballot_batch_table.select()).one().audit_seq > 0


def test_batch_root_matches_published_rows(env) -> None:
    _fill(env, 4)
    batch = queue.commit_batch(env["box"], env["audit"], env["poll"].id, force=True)
    rows = list(queue.iter_ballots(env["box"], env["poll"].id))
    leaves = [queue.batch_leaf(row["ciphertext"]) for row in rows]
    assert batch.root == queue.merkle_root(leaves)


def test_batch_is_recorded_in_the_audit_chain(env) -> None:
    _fill(env, 2)
    batch = queue.commit_batch(env["box"], env["audit"], env["poll"].id, force=True)
    entry = [item for item in chain.iter_entries(env["audit"]) if item.kind == "ballot.batch"][-1]
    assert entry.seq == batch.audit_seq
    assert entry.payload["root"] == batch.root.hex()
    assert entry.payload["size"] == 2
    rows = [entry.as_jsonl_row() for entry in chain.iter_entries(env["audit"])]
    assert chain.verify_rows(rows) == []


def test_ballots_keep_only_the_hour(env) -> None:
    _fill(env, 2)
    queue.commit_batch(env["box"], env["audit"], env["poll"].id, force=True)
    for row in queue.iter_ballots(env["box"], env["poll"].id):
        assert row["slot"].endswith(":00Z")
        assert row["district"] == "RU-MOW-77-012"


def test_ciphertexts_are_opaque(env) -> None:
    ballot = _fill(env, 1)[0]
    queue.commit_batch(env["box"], env["audit"], env["poll"].id, force=True)
    row = next(queue.iter_ballots(env["box"], env["poll"].id))
    assert row["ciphertext"] == ballot["ciphertext"]
    assert row["ballot_id"] == ballot["ballot_id"]
    # Only the holder of the poll private key can read the payload.
    from fairvote.ballots import payload as payload_mod

    plaintext = __import__("fairvote.security.crypto", fromlist=["unseal"]).unseal(
        row["ciphertext"], env["private_key"]
    )
    parsed = payload_mod.parse_payload(plaintext, expected_size=env["poll"].ballot_plaintext_bytes)
    assert parsed["poll"] == env["poll"].id


def test_two_batches_get_sequential_ranges(env) -> None:
    _fill(env, 2)
    first = queue.commit_batch(env["box"], env["audit"], env["poll"].id, force=True)
    _fill(env, 2)
    second = queue.commit_batch(env["box"], env["audit"], env["poll"].id, force=True)
    assert first is not None and second is not None
    assert second.audit_seq > first.audit_seq
    rows = list(queue.iter_ballots(env["box"], env["poll"].id))
    assert [row["seq"] for row in rows] == sorted(row["seq"] for row in rows)
    assert len(rows) == 4


def test_batch_order_is_not_insertion_order(env) -> None:
    """Shuffling is probabilistic; with 30 ballots a stable order is implausible."""
    ballots = _fill(env, 30)
    queue.commit_batch(env["box"], env["audit"], env["poll"].id, force=True)
    published = [row["ballot_id"] for row in queue.iter_ballots(env["box"], env["poll"].id)]
    inserted = [ballot["ballot_id"] for ballot in ballots]
    assert sorted(published) == sorted(inserted)
    assert published != inserted


def test_should_flush_respects_min_size(env) -> None:
    _fill(env, 3)
    assert not queue.should_flush(
        env["box"], env["poll"].id, min_size=8, max_delay_seconds=3600
    )
    assert queue.should_flush(
        env["box"], env["poll"].id, min_size=3, max_delay_seconds=3600
    )


def test_purge_unconfirmed(env) -> None:
    user_id = add_user(env["registry"], "voter-x")
    ballot = make_ballot(env, user_id=user_id)
    with __import__("fairvote.db", fromlist=["write_tx"]).write_tx(env["box"]) as connection:
        connection.execute(
            ballot_queue_table.insert().values(
                poll_id=env["poll"].id,
                ballot_id=ballot["ballot_id"],
                district_code="RU-MOW-77-012",
                client_nonce=ballot["nonce"],
                ciphertext=ballot["ciphertext"],
                received_slot=service.hour_slot(),
                confirmed=0,
                created_at="2020-01-01T00:00:00Z",
            )
        )
    assert queue.purge_unconfirmed(env["box"]) == 1
    with read_tx(env["box"]) as connection:
        assert connection.execute(select(ballot_queue_table.c.id)).first() is None
