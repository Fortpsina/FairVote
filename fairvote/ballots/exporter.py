"""Publishing the ballot box as JSONL, with a detached signature.

The export is the artefact an outsider actually audits: ciphertexts, pseudonyms,
districts, hours and the batch commitments. It is written in canonical JSON so that
re-serialising a parsed row yields the same bytes — `verify.py` relies on that for
the hash checks.
"""

from __future__ import annotations

import base64
from typing import Iterable

from sqlalchemy import select

from ..audit import exporter as audit_exporter
from ..db import Store, read_tx
from ..security import crypto
from ..security.canonical import dumps
from .models import ballot_batch_table, ballot_table
from .queue import iter_ballots

EXPORT_VERSION = 1


def _batch_index(box: Store, poll_id: str) -> dict[int, dict]:
    with read_tx(box) as connection:
        rows = connection.execute(
            select(
                ballot_batch_table.c.id,
                ballot_batch_table.c.merkle_root,
                ballot_batch_table.c.audit_seq,
            ).where(ballot_batch_table.c.poll_id == poll_id)
        ).all()
    return {
        int(row[0]): {"root": bytes(row[1]).hex(), "audit_seq": int(row[2])} for row in rows
    }


def ballot_rows(box: Store, poll_id: str) -> Iterable[dict]:
    batches = _batch_index(box, poll_id)
    for row in iter_ballots(box, poll_id):
        batch = batches.get(row["batch_id"], {"root": "", "audit_seq": 0})
        yield {
            "v": EXPORT_VERSION,
            "poll": poll_id,
            "seq": row["seq"],
            "ballot_id": row["ballot_id"],
            "district": row["district"],
            "slot": row["slot"],
            "batch": row["batch_id"],
            "ct": base64.b64encode(row["ciphertext"]).decode("ascii"),
            "batch_root": batch["root"],
            "audit_seq": batch["audit_seq"],
        }


def export_ballots_jsonl(box: Store, poll_id: str) -> bytes:
    return "".join(dumps(row) + "\n" for row in ballot_rows(box, poll_id)).encode("utf-8")


def poll_config_document(store: Store, poll) -> dict:
    """Everything a third party needs to recount, minus the key itself."""
    from ..polls import service as polls_service

    contests = polls_service.contest_options(store, poll.id)
    return {
        "v": 1,
        "id": poll.id,
        "slug": poll.slug,
        "title": poll.title,
        "system": poll.system,
        "starts_at": poll.starts_at,
        "ends_at": poll.ends_at,
        "k_threshold": poll.k_threshold,
        "ballot_plaintext_bytes": poll.ballot_plaintext_bytes,
        "key_fingerprint": poll.key_fingerprint,
        "eligibility_root": poll.eligibility_root.hex() if poll.eligibility_root else None,
        "districts": [
            {"code": item["code"], "count": item["count"], "root": item["root"]}
            for item in polls_service.list_commitments(store, poll.id)
        ],
        "contests": [
            {
                "id": contest["id"],
                "scope": contest["scope"],
                "district_code": contest["district_code"],
                "title": contest["title"],
                "options": [
                    {"id": option["id"], "name": option["name"], "kind": option["kind"]}
                    for option in contest["options"]
                ],
            }
            for contest in contests
        ],
    }


def sign_export(seed: bytes, data: bytes) -> tuple[bytes, bytes]:
    signature = audit_exporter.detached_sign(seed, data)
    public_key = crypto.ed25519_public_key(seed)
    return signature, audit_exporter.signature_document(public_key, signature)
