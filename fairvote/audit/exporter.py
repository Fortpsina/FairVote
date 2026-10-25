"""JSONL export, detached signatures and the public transparency artefacts."""

from __future__ import annotations

import json
from typing import Iterable

from ..db import Store
from ..security import crypto
from .chain import Entry, iter_entries
from ..security.canonical import dumps


def entries_to_jsonl(entries: Iterable[Entry]) -> bytes:
    """Serialise entries as canonical JSON, one record per line.

    Canonical (sorted keys, no whitespace) so that a consumer can re-serialise a
    parsed row and get the same bytes — which is what makes the hash check possible
    without our code.
    """
    lines = [dumps(entry.as_jsonl_row()) for entry in entries]
    return "".join(line + "\n" for line in lines).encode("utf-8")


def parse_jsonl(data: bytes) -> list[dict]:
    """Parse an export; blank lines are ignored, malformed lines raise ValueError."""
    rows: list[dict] = []
    for number, raw in enumerate(data.decode("utf-8").splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {number}: not JSON ({exc})") from exc
        if not isinstance(value, dict):
            raise ValueError(f"line {number}: expected an object")
        rows.append(value)
    return rows


def export_audit(store: Store, *, after_seq: int = 0) -> bytes:
    return entries_to_jsonl(iter_entries(store, after_seq=after_seq))


def detached_sign(seed: bytes, data: bytes) -> bytes:
    """Ed25519 signature over ``SHA-256(data)`` (docs/02 §2.4.7, docs/03 §3.10)."""
    return crypto.ed25519_sign(seed, crypto.sha256(data))


def detached_verify(public_key: bytes, data: bytes, signature: bytes) -> bool:
    return crypto.ed25519_verify(public_key, crypto.sha256(data), signature)


def signature_document(public_key: bytes, signature: bytes) -> bytes:
    """The ``.sig`` side-car: one line of JSON, easy to publish and to check."""
    return dumps(
        {"alg": "ed25519", "public_key": public_key.hex(), "signature": signature.hex()}
    ).encode("utf-8")
