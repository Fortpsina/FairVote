"""Export artefacts: JSONL round-trip and detached signatures."""

from __future__ import annotations

import json

import pytest

from fairvote.audit import chain, exporter
from fairvote.security import crypto


def _fill(store, count: int = 3) -> None:
    for index in range(count):
        chain.append(store, kind="poll.update", poll_id="p1", payload={"i": index})


def test_jsonl_has_one_canonical_line_per_entry(stores) -> None:
    _fill(stores["audit_log"])
    data = exporter.export_audit(stores["audit_log"])
    lines = data.decode("utf-8").splitlines()
    assert len(lines) == 3
    assert data.endswith(b"\n")
    assert all(line == json.dumps(json.loads(line), ensure_ascii=False, sort_keys=True,
                                  separators=(",", ":")) for line in lines)


def test_jsonl_round_trip(stores) -> None:
    _fill(stores["audit_log"])
    data = exporter.export_audit(stores["audit_log"])
    rows = exporter.parse_jsonl(data)
    entries = list(chain.iter_entries(stores["audit_log"]))
    assert rows == [entry.as_jsonl_row() for entry in entries]
    assert chain.verify_rows(rows) == []


def test_export_can_start_after_a_sequence(stores) -> None:
    _fill(stores["audit_log"], 5)
    data = exporter.export_audit(stores["audit_log"], after_seq=3)
    assert [row["seq"] for row in exporter.parse_jsonl(data)] == [4, 5]


def test_parse_jsonl_rejects_broken_input() -> None:
    with pytest.raises(ValueError, match="not JSON"):
        exporter.parse_jsonl(b'{"a":1}\nnot json\n')
    with pytest.raises(ValueError, match="expected an object"):
        exporter.parse_jsonl(b"[1,2]\n")


def test_parse_jsonl_ignores_blank_lines() -> None:
    assert exporter.parse_jsonl(b'\n{"a":1}\n\n') == [{"a": 1}]


def test_detached_signature_round_trip(settings) -> None:
    data = b'{"seq":1}\n'
    signature = exporter.detached_sign(settings.audit_sign_key, data)
    public_key = crypto.ed25519_public_key(settings.audit_sign_key)
    assert exporter.detached_verify(public_key, data, signature)
    assert not exporter.detached_verify(public_key, data + b"x", signature)


def test_detached_signature_rejects_other_key(settings) -> None:
    data = b"payload"
    signature = exporter.detached_sign(settings.audit_sign_key, data)
    other = crypto.ed25519_public_key(crypto.random_bytes(32))
    assert not exporter.detached_verify(other, data, signature)


def test_signature_document_is_json(settings) -> None:
    signature = exporter.detached_sign(settings.audit_sign_key, b"x")
    public_key = crypto.ed25519_public_key(settings.audit_sign_key)
    document = json.loads(exporter.signature_document(public_key, signature))
    assert document == {
        "alg": "ed25519",
        "public_key": public_key.hex(),
        "signature": signature.hex(),
    }
