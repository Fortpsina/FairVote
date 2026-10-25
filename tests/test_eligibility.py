"""Merkle commitments over eligible voters: determinism, proofs, tamper resistance."""

from __future__ import annotations

import hashlib

import pytest

from fairvote.polls import eligibility
from fairvote.polls.eligibility import (
    DistrictCommitment,
    MerkleError,
    aggregate_root,
    district_leaf,
    district_root,
    eligible_leaf,
    inclusion_proof,
    merkle_root,
    verify_inclusion,
)


def key(index: int) -> bytes:
    return hashlib.sha256(f"voter-{index}".encode()).digest()


def test_leaf_is_deterministic_and_domain_separated() -> None:
    assert eligible_leaf(key(1)) == eligible_leaf(key(1))
    assert eligible_leaf(key(1)) != eligible_leaf(key(2))
    assert eligible_leaf(key(1)) != key(1)
    assert len(eligible_leaf(key(1))) == 32


def test_leaf_rejects_wrong_key_length() -> None:
    with pytest.raises(MerkleError):
        eligible_leaf(b"short")


def test_empty_tree_has_a_fixed_root() -> None:
    assert merkle_root([]) == eligibility._hash(eligibility.EMPTY_PREFIX)
    assert district_root([]) == merkle_root([])


def test_district_root_is_order_independent() -> None:
    keys = [key(index) for index in range(5)]
    assert district_root(keys) == district_root(list(reversed(keys)))
    # Duplicates are NOT deduplicated: a repeated key really is a second leaf.
    assert district_root(keys) != district_root(keys + keys[:1])


def test_district_root_depends_on_the_set() -> None:
    assert district_root([key(1), key(2)]) != district_root([key(1), key(3)])


def test_count_is_committed() -> None:
    root = district_root([key(1), key(2)])
    assert district_leaf(DistrictCommitment("D1", 2, root)) != district_leaf(
        DistrictCommitment("D1", 3, root)
    )


def test_district_code_is_committed() -> None:
    root = district_root([key(1)])
    assert district_leaf(DistrictCommitment("D1", 1, root)) != district_leaf(
        DistrictCommitment("D2", 1, root)
    )


def test_aggregate_root_is_order_independent() -> None:
    first = DistrictCommitment("D1", 2, district_root([key(1), key(2)]))
    second = DistrictCommitment("D2", 1, district_root([key(3)]))
    assert aggregate_root([first, second]) == aggregate_root([second, first])


def test_aggregate_root_rejects_duplicate_districts() -> None:
    commitment = DistrictCommitment("D1", 1, district_root([key(1)]))
    with pytest.raises(MerkleError, match="duplicate"):
        aggregate_root([commitment, commitment])


@pytest.mark.parametrize("size", range(1, 10))
def test_inclusion_proofs_verify_for_every_position(size: int) -> None:
    keys = [key(index) for index in range(size)]
    root = district_root(keys)
    for index in range(size):
        position, siblings = inclusion_proof(keys, keys[index])
        leaf = eligible_leaf(keys[index])
        assert verify_inclusion(leaf, position, siblings, root, size)


@pytest.mark.parametrize("size", range(1, 10))
def test_proof_rejects_a_different_leaf(size: int) -> None:
    keys = [key(index) for index in range(size)]
    position, siblings = inclusion_proof(keys, keys[0])
    assert not verify_inclusion(
        eligible_leaf(key(999)), position, siblings, district_root(keys), size
    )


def test_proof_rejects_wrong_index() -> None:
    keys = [key(index) for index in range(4)]
    position, siblings = inclusion_proof(keys, keys[2])
    assert not verify_inclusion(
        eligible_leaf(keys[2]), position + 1, siblings, district_root(keys), 4
    )


def test_proof_for_non_member_is_refused() -> None:
    keys = [key(index) for index in range(3)]
    with pytest.raises(MerkleError, match="not in this district"):
        inclusion_proof(keys, key(42))


def test_proof_of_a_single_leaf_is_empty() -> None:
    keys = [key(7)]
    position, siblings = inclusion_proof(keys, keys[0])
    assert position == 0 and siblings == []
    assert verify_inclusion(eligible_leaf(keys[0]), 0, [], district_root(keys), 1)


def test_promoted_node_semantics() -> None:
    """With three leaves the third is promoted; the tree must still be verifiable."""
    keys = [key(index) for index in range(3)]
    leaves = sorted(eligible_leaf(item) for item in keys)
    expected = eligibility._hash(
        eligibility.NODE_PREFIX,
        eligibility._hash(eligibility.NODE_PREFIX, leaves[0], leaves[1]),
        leaves[2],
    )
    assert district_root(keys) == expected


def test_negative_index_is_not_verified() -> None:
    keys = [key(1)]
    assert not verify_inclusion(eligible_leaf(keys[0]), -1, [], district_root(keys), 1)
