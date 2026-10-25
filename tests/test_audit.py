"""Audit chain: hashing, linking, idempotency, checkpoints, verification."""

from __future__ import annotations

import json

import pytest

from fairvote.audit import chain
from fairvote.audit.chain import GENESIS_HASH, AuditError
from fairvote.db import write_tx


def test_genesis_head_is_zero_hash(stores) -> None:
    assert chain.head(stores["audit_log"]) == (0, GENESIS_HASH)


def test_append_links_records(stores) -> None:
    store = stores["audit_log"]
    first = chain.append(store, kind="poll.create", poll_id="p1", payload={"a": 1})
    second = chain.append(store, kind="poll.update", poll_id="p1", payload={"b": 2})

    assert first.seq == 1 and first.prev_hash == GENESIS_HASH
    assert second.seq == 2 and second.prev_hash == first.hash
    assert second.hash == chain.record_hash(first.hash, second.record())
    assert chain.head(store) == (2, second.hash)


def test_head_hash_depends_on_every_byte(stores) -> None:
    store = stores["audit_log"]
    entry = chain.append(store, kind="poll.create", poll_id="p1", payload={"a": 1})
    other = chain.record_hash(
        entry.prev_hash,
        {**entry.record(), "payload": {"a": 2}},
    )
    assert other != entry.hash


def test_unknown_kind_is_refused(stores) -> None:
    with pytest.raises(AuditError, match="unknown audit record kind"):
        chain.append(stores["audit_log"], kind="poll.hacked")


def test_bad_timestamp_is_refused(stores) -> None:
    with pytest.raises(AuditError, match="timestamp"):
        chain.append(stores["audit_log"], kind="poll.create", ts="2026-01-01 10:00")


def test_payload_must_be_an_object(stores) -> None:
    with pytest.raises(AuditError, match="payload must be a JSON object"):
        chain.append(stores["audit_log"], kind="poll.create", payload=["x"])  # type: ignore[arg-type]


def test_non_canonical_payload_is_refused(stores) -> None:
    with pytest.raises(AuditError, match="not canonicalisable"):
        chain.append(stores["audit_log"], kind="poll.create", payload={"a": 1.5})


def test_has_entry_is_scoped_by_poll(stores) -> None:
    store = stores["audit_log"]
    chain.append(store, kind="poll.start", poll_id="p1")
    assert chain.has_entry(store, kind="poll.start", poll_id="p1")
    assert not chain.has_entry(store, kind="poll.start", poll_id="p2")


def test_iter_entries_streams_in_order(stores) -> None:
    store = stores["audit_log"]
    for index in range(5):
        chain.append(store, kind="admin.action", payload={"i": index})
    entries = list(chain.iter_entries(store))
    assert [entry.seq for entry in entries] == [1, 2, 3, 4, 5]
    assert list(chain.iter_entries(store, after_seq=3))[0].seq == 4
    assert len(list(chain.iter_entries(store, limit=2))) == 2


def test_stored_payload_is_reparsed_canonically(stores) -> None:
    store = stores["audit_log"]
    appended = chain.append(
        store, kind="poll.create", poll_id="p", payload={"z": [1, {"b": 2, "a": 3}]}
    )
    stored = list(chain.iter_entries(store))[0]
    assert stored.payload == appended.payload
    assert stored.hash == appended.hash


def test_verify_rows_accepts_a_clean_chain(stores) -> None:
    store = stores["audit_log"]
    for index in range(3):
        chain.append(store, kind="poll.update", poll_id="p1", payload={"i": index})
    rows = [entry.as_jsonl_row() for entry in chain.iter_entries(store)]
    assert chain.verify_rows(rows) == []


def _chain_rows(store) -> list[dict]:
    return [entry.as_jsonl_row() for entry in chain.iter_entries(store)]


def test_verify_rows_detects_edited_payload(stores) -> None:
    chain.append(stores["audit_log"], kind="poll.create", poll_id="p1", payload={"a": 1})
    rows = _chain_rows(stores["audit_log"])
    rows[0]["payload"] = {"a": 2}
    codes = {problem.code for problem in chain.verify_rows(rows)}
    assert "HASH_MISMATCH" in codes


def test_verify_rows_detects_edited_record(stores) -> None:
    """A changed field breaks that record's hash; the link itself still holds,
    which is exactly why the verifier must recompute every hash."""
    store = stores["audit_log"]
    chain.append(store, kind="poll.create", poll_id="p1")
    chain.append(store, kind="poll.update", poll_id="p1")
    rows = _chain_rows(store)
    rows[0]["ts"] = "2020-01-01T00:00:00Z"
    problems = chain.verify_rows(rows)
    assert [(problem.code, problem.seq) for problem in problems] == [("HASH_MISMATCH", 1)]


def test_verify_rows_detects_deleted_record(stores) -> None:
    store = stores["audit_log"]
    for _ in range(3):
        chain.append(store, kind="poll.update", poll_id="p1")
    rows = _chain_rows(store)
    del rows[1]
    codes = {problem.code for problem in chain.verify_rows(rows)}
    assert "SEQ_GAP" in codes
    assert "CHAIN_BREAK" in codes


def test_verify_rows_detects_reordering(stores) -> None:
    store = stores["audit_log"]
    for _ in range(3):
        chain.append(store, kind="poll.update", poll_id="p1")
    rows = _chain_rows(store)
    rows[1], rows[2] = rows[2], rows[1]
    codes = {problem.code for problem in chain.verify_rows(rows)}
    assert "SEQ_GAP" in codes


def test_verify_rows_detects_injected_field(stores) -> None:
    chain.append(stores["audit_log"], kind="poll.create", poll_id="p1")
    rows = _chain_rows(stores["audit_log"])
    rows[0]["note"] = "hidden"
    codes = {problem.code for problem in chain.verify_rows(rows)}
    assert "EXTRA_FIELD" in codes


def test_verify_rows_detects_missing_field_and_bad_hex(stores) -> None:
    chain.append(stores["audit_log"], kind="poll.create", poll_id="p1")
    rows = _chain_rows(stores["audit_log"])
    del rows[0]["payload"]
    assert {p.code for p in chain.verify_rows(rows)} == {"MISSING_FIELD"}

    rows = _chain_rows(stores["audit_log"])
    rows[0]["hash"] = "zz"
    assert "MALFORMED_ROW" in {p.code for p in chain.verify_rows(rows)}


def test_verify_rows_reports_empty_input() -> None:
    assert [problem.code for problem in chain.verify_rows([])] == ["EMPTY"]


def test_verify_rows_reports_unknown_kind(stores) -> None:
    """A kind outside the published vocabulary is visible to a third party."""
    chain.append(stores["audit_log"], kind="poll.create", poll_id="p1")
    rows = _chain_rows(stores["audit_log"])
    rows[0]["kind"] = "poll.secret"
    # The hash no longer matches (kind is covered), so both findings must appear.
    codes = {problem.code for problem in chain.verify_rows(rows)}
    assert "HASH_MISMATCH" in codes


def test_direct_write_of_a_broken_record_is_detected(stores) -> None:
    """Simulates a malicious operator bypassing the service layer via SQL."""
    store = stores["audit_log"]
    chain.append(store, kind="poll.create", poll_id="p1")
    with write_tx(store) as connection:
        # A well-formed link with a payload that does not match its hash.
        connection.exec_driver_sql(
            "INSERT INTO entry (seq, ts, kind, poll_id, payload, prev_hash, hash) "
            "VALUES (2, '2026-01-01T00:00:00Z', 'poll.update', 'p1', '{\"x\":1}', "
            "zeroblob(32), zeroblob(32))"
        )
    rows = [entry.as_jsonl_row() for entry in chain.iter_entries(store)]
    codes = {problem.code for problem in chain.verify_rows(rows)}
    assert "HASH_MISMATCH" in codes


def test_checkpoint_signs_the_head(stores, settings) -> None:
    store = stores["audit_log"]
    chain.append(store, kind="poll.create", poll_id="p1")
    checkpoint = chain.create_checkpoint(store, settings.audit_sign_key)
    assert checkpoint.seq == 1
    assert chain.verify_checkpoint_signature(
        checkpoint.seq, checkpoint.hash, checkpoint.signature, checkpoint.public_key
    )
    assert not chain.verify_checkpoint_signature(
        checkpoint.seq + 1, checkpoint.hash, checkpoint.signature, checkpoint.public_key
    )


def test_checkpoint_is_idempotent(stores, settings) -> None:
    store = stores["audit_log"]
    chain.append(store, kind="poll.create", poll_id="p1")
    first = chain.create_checkpoint(store, settings.audit_sign_key)
    second = chain.create_checkpoint(store, settings.audit_sign_key)
    assert first.signature == second.signature
    assert len(chain.list_checkpoints(store)) == 1


def test_checkpoint_rejects_rewritten_history(stores, settings) -> None:
    """Same seq, different hash: the operation must fail loudly."""
    store = stores["audit_log"]
    chain.append(store, kind="poll.create", poll_id="p1")
    with write_tx(store) as connection:
        connection.exec_driver_sql(
            "INSERT INTO checkpoint (seq, hash, signature, anchor_note, created_at) "
            "VALUES (1, x'22', x'33', NULL, '2026-01-01T00:00:00Z')"
        )
    with pytest.raises(AuditError, match="history was rewritten"):
        chain.create_checkpoint(store, settings.audit_sign_key)


def test_checkpoint_of_empty_chain_is_refused(stores, settings) -> None:
    with pytest.raises(AuditError, match="empty chain"):
        chain.create_checkpoint(stores["audit_log"], settings.audit_sign_key)


def test_checkpoint_keeps_anchor_note(stores, settings) -> None:
    chain.append(stores["audit_log"], kind="poll.create", poll_id="p1")
    chain.create_checkpoint(stores["audit_log"], settings.audit_sign_key, anchor_note="url")
    stored = chain.list_checkpoints(stores["audit_log"])[0]
    assert stored.anchor_note == "url"


def test_entry_jsonl_row_is_json_serialisable(stores) -> None:
    entry = chain.append(stores["audit_log"], kind="poll.create", poll_id=None)
    json.dumps(entry.as_jsonl_row())
