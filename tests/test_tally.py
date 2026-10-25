"""Tallying: correctness of counting, anomalies and the anonymity threshold."""

from __future__ import annotations

import pytest

from fairvote.ballots import payload as payload_mod
from fairvote.ballots.tally import Contest, tally_ballots, visible_districts
from fairvote.security import crypto

POLL_ID = "poll-1"
SIZE = 1024
PRIVATE, PUBLIC = crypto.x25519_keypair()

CONTESTS = [
    Contest("c-national", "nationwide", None, frozenset({"o1", "o2", "against"})),
    Contest("c-77", "district", "D-77", frozenset({"a1", "a2"})),
]


def row(seq: int, district: str, *, choices=None, spoil=False, size=SIZE) -> dict:
    plaintext = payload_mod.build_payload(
        poll_id=POLL_ID,
        district_code=district,
        choices=choices or {},
        spoil=spoil,
        size=size,
    )
    return {
        "seq": seq,
        "ballot_id": f"{seq:064d}",
        "district": district,
        "ciphertext": crypto.seal(plaintext, PUBLIC),
        "slot": "2026-03-01T10:00:00Z",
        "batch_id": 1,
    }


def run(rows, *, k=1, contests=None):
    return tally_ballots(
        rows,
        contests or CONTESTS,
        poll_id=POLL_ID,
        expected_size=SIZE,
        private_key=PRIVATE,
        k_threshold=k,
    )


def test_counts_national_and_district_contests() -> None:
    rows = [
        row(1, "D-77", choices={"c-national": "o1", "c-77": "a1"}),
        row(2, "D-77", choices={"c-national": "o2", "c-77": "a1"}),
        row(3, "D-99", choices={"c-national": "o1"}),
    ]
    tally = run(rows)
    assert tally.total_ballots == 3
    assert tally.valid == 3
    assert tally.national["c-national"]["o1"] == 2
    assert tally.national["c-national"]["o2"] == 1
    # The district-77 contest exists only in D-77.
    assert tally.by_district["D-77"]["contests"]["c-77"]["a1"] == 2
    assert tally.by_district["D-99"]["contests"]["c-77"] == {"a1": 0, "a2": 0}


def test_abstention_is_not_counted_as_an_option() -> None:
    tally = run([row(1, "D-77", choices={})])
    assert tally.valid == 1
    assert sum(tally.national["c-national"].values()) == 0


def test_spoiled_ballots_are_separate() -> None:
    tally = run([row(1, "D-77", spoil=True), row(2, "D-77", choices={"c-national": "o1"})])
    assert tally.spoiled == 1
    assert tally.valid == 1
    assert tally.national["c-national"]["o1"] == 1


def test_wrong_district_inside_payload_is_an_anomaly() -> None:
    sealed = crypto.seal(
        payload_mod.build_payload(
            poll_id=POLL_ID, district_code="D-99", choices={}, size=SIZE
        ),
        PUBLIC,
    )
    tally = run([{**row(1, "D-77"), "ciphertext": sealed}])
    assert tally.invalid == 1
    assert tally.anomalies == [(1, "DISTRICT_MISMATCH")]


def test_unknown_option_is_an_anomaly() -> None:
    tally = run([row(1, "D-77", choices={"c-national": "nope"})])
    assert tally.invalid == 1
    assert tally.anomalies == [(1, "OPTION_UNKNOWN")]


def test_contest_not_eligible_in_that_district_is_an_anomaly() -> None:
    tally = run([row(1, "D-99", choices={"c-77": "a1"})])
    assert tally.invalid == 1
    assert tally.anomalies == [(1, "CONTEST_NOT_ELIGIBLE")]


def test_undecryptable_ballot_is_an_anomaly() -> None:
    other_private, other_public = crypto.x25519_keypair()
    sealed = crypto.seal(b"x" * SIZE, other_public)
    tally = run([{**row(1, "D-77"), "ciphertext": sealed}])
    assert tally.invalid == 1
    assert tally.anomalies == [(1, "DECRYPT_FAIL")]


def test_wrong_poll_inside_payload_is_an_anomaly() -> None:
    sealed = crypto.seal(
        payload_mod.build_payload(
            poll_id="other", district_code="D-77", choices={}, size=SIZE
        ),
        PUBLIC,
    )
    tally = run([{**row(1, "D-77"), "ciphertext": sealed}])
    assert tally.invalid == 1
    assert tally.anomalies == [(1, "POLL_MISMATCH")]


def test_threshold_suppresses_small_districts() -> None:
    rows = [row(index, "D-77", choices={"c-national": "o1"}) for index in range(1, 6)]
    rows += [row(6, "D-99", choices={"c-national": "o2"})]
    tally = run(rows, k=3)
    assert tally.suppressed_districts == ["D-99"]
    assert set(visible_districts(tally)) == {"D-77"}
    # The national total still includes the suppressed district: the threshold
    # protects the breakdown, not the aggregate.
    assert tally.national["c-national"]["o2"] == 1


def test_threshold_boundary_is_inclusive() -> None:
    rows = [row(index, "D-77", choices={"c-national": "o1"}) for index in range(1, 4)]
    tally = run(rows, k=3)
    assert tally.suppressed_districts == []


def test_as_dict_is_json_ready() -> None:
    import json

    tally = run([row(1, "D-77", choices={"c-national": "o1"})])
    json.dumps(tally.as_dict())
    assert tally.as_dict()["valid"] == 1


@pytest.mark.parametrize("k", [0, 1, 10])
def test_threshold_values(k: int) -> None:
    tally = run([row(1, "D-77", choices={})], k=k)
    assert tally.total_ballots == 1
