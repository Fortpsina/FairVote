"""Append-only audit chain: hashing, appending, verification, checkpoints.

Record format (docs/02 §2.4.7)::

    rec = {"seq": n, "ts": "…Z", "kind": "…", "poll": "<uuid>|null", "payload": {…}}
    h_n = SHA-256(h_{n-1} || canonical_json(rec)),   h_0 = 0x00 * 32

Everything the chain needs is inside the record, so a third party can recompute
the hash with nothing but the exported JSONL — no database, no code of ours.

Appends run inside ``BEGIN IMMEDIATE`` (docs/02 §2.6.4): reading the head and
writing the next link must not interleave between workers, otherwise two entries
would claim the same predecessor and the chain would silently fork.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterator

from sqlalchemy import select

from ..db import Store, read_tx, write_tx
from ..security import crypto
from ..security.canonical import CanonicalError, dump_bytes, dumps
from .models import checkpoint_table, entry_table

GENESIS_HASH: bytes = b"\x00" * 32
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

#: Record kinds this build knows how to emit. Anything else is a typo that would
#: fork the public vocabulary of the journal, so it is refused.
KINDS: frozenset[str] = frozenset(
    {
        "poll.create",
        "poll.update",
        "poll.schedule",
        "poll.districts",
        "poll.key_commit",
        "poll.start",
        "ballot.batch",
        "poll.close",
        "poll.key_publish",
        "poll.results",
        "admin.action",
        "registry.purge",
        "asset.manifest",
    }
)

#: Fields covered by the record hash, and the full set allowed in an export row.
RECORD_FIELDS = frozenset({"seq", "ts", "kind", "poll", "payload"})
ROW_FIELDS = RECORD_FIELDS | {"prev_hash", "hash"}


class AuditError(RuntimeError):
    """Raised when the chain cannot be extended consistently."""


@dataclass(frozen=True)
class Entry:
    """One link of the chain."""

    seq: int
    ts: str
    kind: str
    poll_id: str | None
    payload: dict[str, Any]
    prev_hash: bytes
    hash: bytes
    sig: bytes | None = None

    def record(self) -> dict[str, Any]:
        """The exact object that is hashed (docs/02 §2.4.7)."""
        return {
            "seq": self.seq,
            "ts": self.ts,
            "kind": self.kind,
            "poll": self.poll_id,
            "payload": self.payload,
        }

    def as_jsonl_row(self) -> dict[str, Any]:
        row = self.record()
        row["prev_hash"] = self.prev_hash.hex()
        row["hash"] = self.hash.hex()
        return row


@dataclass(frozen=True)
class Problem:
    """A verification finding. ``seq`` is 0 when it concerns the whole file."""

    code: str
    seq: int
    detail: str


def utc_now_string() -> str:
    """Second-precision UTC timestamp, the only format accepted in records."""
    return datetime.now(timezone.utc).strftime(TIMESTAMP_FORMAT)


def is_valid_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        datetime.strptime(value, TIMESTAMP_FORMAT)
    except ValueError:
        return False
    return True


def record_hash(prev_hash: bytes, record: dict[str, Any]) -> bytes:
    """``SHA-256(prev_hash || canonical_json(record))``."""
    if len(prev_hash) != 32:
        raise ValueError("prev_hash must be 32 bytes")
    try:
        body = dump_bytes(record)
    except CanonicalError as exc:
        raise AuditError(f"record is not canonicalisable: {exc}") from exc
    return crypto.sha256(prev_hash + body)


def _last_link(connection) -> tuple[int, bytes]:
    row = connection.execute(
        select(entry_table.c.seq, entry_table.c.hash)
        .order_by(entry_table.c.seq.desc())
        .limit(1)
    ).first()
    if row is None:
        return 0, GENESIS_HASH
    return int(row[0]), bytes(row[1])


def head(store: Store) -> tuple[int, bytes]:
    """Return ``(seq, hash)`` of the last entry, or ``(0, GENESIS_HASH)``."""
    with read_tx(store) as connection:
        return _last_link(connection)


def append(
    store: Store,
    *,
    kind: str,
    poll_id: str | None = None,
    payload: dict[str, Any] | None = None,
    ts: str | None = None,
) -> Entry:
    """Append one record to the chain and return it."""
    if kind not in KINDS:
        raise AuditError(f"unknown audit record kind: {kind!r}")
    payload = {} if payload is None else payload
    if not isinstance(payload, dict):
        raise AuditError("payload must be a JSON object")
    stamp = ts or utc_now_string()
    if not is_valid_timestamp(stamp):
        raise AuditError(f"timestamp must be UTC 'YYYY-MM-DDTHH:MM:SSZ', got {stamp!r}")

    with write_tx(store) as connection:
        seq, prev_hash = _last_link(connection)
        seq += 1
        record = {
            "seq": seq,
            "ts": stamp,
            "kind": kind,
            "poll": poll_id,
            "payload": payload,
        }
        digest = record_hash(prev_hash, record)
        connection.execute(
            entry_table.insert().values(
                seq=seq,
                ts=stamp,
                kind=kind,
                poll_id=poll_id,
                payload=dumps(payload),
                prev_hash=prev_hash,
                hash=digest,
            )
        )
    return Entry(
        seq=seq,
        ts=stamp,
        kind=kind,
        poll_id=poll_id,
        payload=payload,
        prev_hash=prev_hash,
        hash=digest,
    )


def has_entry(store: Store, *, kind: str, poll_id: str | None = None) -> bool:
    """Used by idempotent operations (``poll.start`` must be recorded once)."""
    with read_tx(store) as connection:
        query = select(entry_table.c.seq).where(entry_table.c.kind == kind)
        if poll_id is None:
            query = query.where(entry_table.c.poll_id.is_(None))
        else:
            query = query.where(entry_table.c.poll_id == poll_id)
        return connection.execute(query.limit(1)).first() is not None


def iter_entries(
    store: Store, *, after_seq: int = 0, limit: int | None = None
) -> Iterator[Entry]:
    """Stream entries in chain order (used by the exporter and the UI)."""
    sql = (
        select(entry_table)
        .where(entry_table.c.seq > after_seq)
        .order_by(entry_table.c.seq.asc())
    )
    if limit is not None:
        sql = sql.limit(limit)
    with read_tx(store) as connection:
        for row in connection.execute(sql):
            yield Entry(
                seq=int(row.seq),
                ts=row.ts,
                kind=row.kind,
                poll_id=row.poll_id,
                payload=json.loads(row.payload),
                prev_hash=bytes(row.prev_hash),
                hash=bytes(row.hash),
                sig=bytes(row.sig) if row.sig is not None else None,
            )


# --- verification ---------------------------------------------------------------


def verify_rows(rows: list[dict[str, Any]]) -> list[Problem]:
    """Verify a parsed JSONL export.

    The input is exactly what a third party has: JSON objects. No database, no
    trust in the exporter. Every check is byte-for-byte reproducible.
    """
    problems: list[Problem] = []
    previous_hash = GENESIS_HASH
    expected_seq = 1

    for row in rows:
        if not isinstance(row, dict):
            problems.append(Problem("MALFORMED_ROW", expected_seq, "row is not an object"))
            expected_seq += 1
            continue

        seq = row.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            problems.append(Problem("MALFORMED_ROW", expected_seq, "seq is not an integer"))
            expected_seq += 1
            continue

        if seq != expected_seq:
            problems.append(Problem("SEQ_GAP", seq, f"expected seq {expected_seq}, got {seq}"))

        if not RECORD_FIELDS <= set(row):
            missing = ", ".join(sorted(RECORD_FIELDS - set(row)))
            problems.append(Problem("MISSING_FIELD", seq, f"missing {missing}"))
            expected_seq = seq + 1
            continue
        extra = set(row) - ROW_FIELDS
        if extra:
            problems.append(
                Problem("EXTRA_FIELD", seq, "unexpected " + ", ".join(sorted(extra)))
            )

        record = {key: row[key] for key in RECORD_FIELDS}
        if not is_valid_timestamp(record["ts"]):
            problems.append(Problem("BAD_TIMESTAMP", seq, f"bad timestamp {record['ts']!r}"))
            expected_seq = seq + 1
            continue
        if not isinstance(record["kind"], str):
            problems.append(Problem("MALFORMED_ROW", seq, "kind is not a string"))
            expected_seq = seq + 1
            continue

        try:
            prev_hash = bytes.fromhex(str(row["prev_hash"]))
            claimed = bytes.fromhex(str(row["hash"]))
        except ValueError:
            problems.append(Problem("MALFORMED_ROW", seq, "hash is not hex"))
            expected_seq = seq + 1
            continue
        if len(prev_hash) != 32 or len(claimed) != 32:
            problems.append(Problem("MALFORMED_ROW", seq, "hash must be 32 bytes"))
            expected_seq = seq + 1
            continue

        if prev_hash != previous_hash:
            problems.append(
                Problem("CHAIN_BREAK", seq, "prev_hash does not match the previous row")
            )

        try:
            computed = record_hash(prev_hash, record)
        except AuditError as exc:
            problems.append(Problem("NON_CANONICAL", seq, str(exc)))
            expected_seq = seq + 1
            continue

        if computed != claimed:
            problems.append(Problem("HASH_MISMATCH", seq, "record hash does not match"))
        if record["kind"] not in KINDS:
            problems.append(
                Problem("UNKNOWN_KIND", seq, f"kind {record['kind']!r} is not known")
            )

        previous_hash = claimed
        expected_seq = seq + 1

    if expected_seq == 1:
        problems.append(Problem("EMPTY", 0, "no records found"))
    return problems


# --- checkpoints ----------------------------------------------------------------


@dataclass(frozen=True)
class Checkpoint:
    seq: int
    hash: bytes
    signature: bytes
    public_key: bytes
    signed_at: str


@dataclass(frozen=True)
class StoredCheckpoint:
    """A checkpoint as persisted (the public key is a server-wide constant)."""

    seq: int
    hash: bytes
    signature: bytes
    anchor_note: str | None
    created_at: str


def checkpoint_message(seq: int, head_hash: bytes) -> bytes:
    """The exact bytes signed by a checkpoint.

    A JSON descriptor instead of a raw hash: it is self-describing, so a third
    party does not need to know a binary layout to verify a signature, and ``seq``
    stops an old signature from being replayed onto a truncated chain.
    """
    return dump_bytes({"hash": head_hash.hex(), "seq": int(seq), "v": 1})


def create_checkpoint(
    store: Store,
    seed: bytes,
    *,
    anchor_note: str | None = None,
    now: str | None = None,
) -> Checkpoint:
    """Sign the current head. Idempotent for an unchanged head."""
    seq, head_hash = head(store)
    if seq == 0:
        raise AuditError("cannot checkpoint an empty chain")
    signature = crypto.ed25519_sign(seed, checkpoint_message(seq, head_hash))
    public_key = crypto.ed25519_public_key(seed)
    stamp = now or utc_now_string()

    with write_tx(store) as connection:
        existing = connection.execute(
            select(checkpoint_table.c.hash, checkpoint_table.c.signature).where(
                checkpoint_table.c.seq == seq
            )
        ).first()
        if existing is None:
            connection.execute(
                checkpoint_table.insert().values(
                    seq=seq,
                    hash=head_hash,
                    signature=signature,
                    anchor_note=anchor_note,
                    created_at=stamp,
                )
            )
        elif bytes(existing[0]) != head_hash:
            # The same sequence number now points at a different hash: history was
            # rewritten. This is the incident the checkpoint exists to catch.
            raise AuditError(f"checkpoint conflict at seq {seq}: history was rewritten")
    return Checkpoint(
        seq=seq,
        hash=head_hash,
        signature=signature,
        public_key=public_key,
        signed_at=stamp,
    )


def verify_checkpoint_signature(
    seq: int, head_hash: bytes, signature: bytes, public_key: bytes
) -> bool:
    return crypto.ed25519_verify(
        public_key, checkpoint_message(seq, head_hash), signature
    )


def list_checkpoints(store: Store) -> list[StoredCheckpoint]:
    with read_tx(store) as connection:
        rows = connection.execute(
            select(checkpoint_table).order_by(checkpoint_table.c.seq.asc())
        ).all()
    return [
        StoredCheckpoint(
            seq=int(row.seq),
            hash=bytes(row.hash),
            signature=bytes(row.signature),
            anchor_note=row.anchor_note,
            created_at=row.created_at,
        )
        for row in rows
    ]
