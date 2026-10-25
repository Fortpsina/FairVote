"""Merkle commitments over the eligible voters of a poll.

The commitment must be reproducible by anyone who can see the published numbers, so
the construction is spelled out (docs/02 §2.4.3) and implemented exactly once::

    leaf_i      = SHA-256(b"fairvote/elig/v1" || voter_key_i)
    node        = SHA-256(0x01 || left || right)
    odd node    = promoted unchanged (no duplication, RFC 6962 style)
    dleaf       = SHA-256(b"fairvote/dist/v1" || district_code || be64(count) || d_root)
    root        = merkle(dleaf, sorted by district code)

Only the aggregate root and per-district ``(count, root)`` are published; leaves and
inclusion paths are never published, otherwise ``H(voter_key)`` would become a
membership oracle for anyone holding someone's passport data (docs/01 T15).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable, Sequence

from ..merkle import EMPTY_PREFIX, NODE_PREFIX, _hash, merkle_root, next_level

LEAF_PREFIX = b"fairvote/elig/v1"
DISTRICT_PREFIX = b"fairvote/dist/v1"


class MerkleError(ValueError):
    """The tree cannot be built or a proof does not verify."""


@dataclass(frozen=True)
class DistrictCommitment:
    district_code: str
    count: int
    root: bytes


def eligible_leaf(voter_key: bytes) -> bytes:
    if len(voter_key) != 32:
        raise MerkleError("voter_key must be 32 bytes")
    return _hash(LEAF_PREFIX, voter_key)


def district_root(voter_keys: Iterable[bytes]) -> bytes:
    """Root of one district's leaves, sorted for determinism."""
    leaves = sorted(eligible_leaf(key) for key in voter_keys)
    return merkle_root(leaves)


def district_leaf(commitment: DistrictCommitment) -> bytes:
    if commitment.count < 0:
        raise MerkleError("count must be non-negative")
    return _hash(
        DISTRICT_PREFIX,
        commitment.district_code.encode("utf-8"),
        struct.pack(">Q", commitment.count),
        commitment.root,
    )


def aggregate_root(commitments: Iterable[DistrictCommitment]) -> bytes:
    ordered = sorted(commitments, key=lambda item: item.district_code)
    seen: set[str] = set()
    for item in ordered:
        if item.district_code in seen:
            raise MerkleError(f"duplicate district {item.district_code!r}")
        seen.add(item.district_code)
    return merkle_root(district_leaf(item) for item in ordered)


def inclusion_proof(voter_keys: Iterable[bytes], target: bytes) -> tuple[int, list[bytes]]:
    """Return ``(index, siblings)`` for ``target`` inside its district subtree.

    ``index`` is the position in the sorted leaf list; the siblings are ordered from
    the leaf level upwards. A promoted node contributes no sibling.
    """
    leaves = sorted(eligible_leaf(key) for key in voter_keys)
    wanted = eligible_leaf(target)
    try:
        index = leaves.index(wanted)
    except ValueError as exc:
        raise MerkleError("voter is not in this district") from exc

    siblings: list[bytes] = []
    position = index
    level = leaves
    while len(level) > 1:
        sibling = position ^ 1
        if sibling < len(level):
            siblings.append(level[sibling])
        position //= 2
        level = next_level(level)
    return index, siblings


def verify_inclusion(
    leaf: bytes,
    index: int,
    siblings: Sequence[bytes],
    root: bytes,
    count: int,
) -> bool:
    """Recompute the root from a leaf and its path.

    ``count`` is required: with promoted odd nodes the shape of the tree is not
    implied by the path alone, and a verifier that guesses the shape will reject
    valid proofs (or accept invalid ones). The count is published in the district
    commitment, so a verifier always has it.
    """
    if index < 0 or index >= count or count < 1:
        return False
    node = bytes(leaf)
    position = index
    level_size = count
    iterator = iter(siblings)
    while level_size > 1:
        sibling_position = position ^ 1
        if sibling_position < level_size:
            sibling = next(iterator, None)
            if sibling is None:
                return False
            if position % 2 == 0:
                node = _hash(NODE_PREFIX, node, sibling)
            else:
                node = _hash(NODE_PREFIX, sibling, node)
        # Promoted node: it moves up unchanged and consumes no sibling.
        position //= 2
        level_size = (level_size + 1) // 2
    return node == root and next(iterator, None) is None
