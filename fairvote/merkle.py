"""Generic binary Merkle tree over 32-byte leaves.

Shared by two commitments with the same shape but different domains: eligibility
(leaves derived from ``voter_key``) and ballot batches (leaves derived from
ciphertexts). Keeping one implementation means the promotion rule and the prefix
byte cannot drift between them.

Construction (docs/02 §2.4.3)::

    node     = SHA-256(0x01 || left || right)
    odd node = promoted unchanged (RFC 6962 style, never duplicated)
    empty    = SHA-256(b"fairvote/empty/v1")
"""

from __future__ import annotations

import hashlib
from typing import Iterable, Sequence

NODE_PREFIX = b"\x01"
EMPTY_PREFIX = b"fairvote/empty/v1"


def _hash(*parts: bytes) -> bytes:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


def next_level(level: Sequence[bytes]) -> list[bytes]:
    result: list[bytes] = []
    for index in range(0, len(level) - 1, 2):
        result.append(_hash(NODE_PREFIX, level[index], level[index + 1]))
    if len(level) % 2:
        result.append(level[-1])
    return result


def merkle_root(leaves: Iterable[bytes]) -> bytes:
    level = [bytes(leaf) for leaf in leaves]
    if not level:
        return _hash(EMPTY_PREFIX)
    for leaf in level:
        if len(leaf) != 32:
            raise ValueError("leaves must be 32 bytes")
    while len(level) > 1:
        level = next_level(level)
    return level[0]


def seal_leaf(data: bytes, *, domain: bytes) -> bytes:
    """Domain-separated leaf hash: ``SHA-256(domain || data)``."""
    return _hash(domain, data)
