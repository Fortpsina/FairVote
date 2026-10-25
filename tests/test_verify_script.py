"""The public verifier must work without our package and catch tampering.

``scripts/verify.py`` is executed as a separate process with only the standard
library plus Ed25519 — exactly the situation of an outside auditor.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from fairvote.audit import chain, exporter
from fairvote.security import crypto
from fairvote.security.canonical import CanonicalError
from fairvote.security.canonical import dumps as package_dumps

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "verify.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("fairvote_verify_script", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["fairvote_verify_script"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def verifier():
    return _load_module()


def _export(store, settings, directory: Path) -> tuple[Path, Path]:
    chain.append(store, kind="poll.create", poll_id="p1", payload={"title": "Тест"})
    chain.append(store, kind="poll.update", poll_id="p1", payload={"k": 3})
    chain.append(store, kind="admin.action", poll_id=None, payload={"action": "edit"})
    data = exporter.export_audit(store)
    audit_path = directory / "audit.jsonl"
    audit_path.write_bytes(data)
    signature = exporter.detached_sign(settings.audit_sign_key, data)
    public_key = crypto.ed25519_public_key(settings.audit_sign_key)
    sig_path = directory / "audit.jsonl.sig"
    sig_path.write_bytes(exporter.signature_document(public_key, signature))
    return audit_path, sig_path


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_clean_export_passes(stores, settings, tmp_path: Path) -> None:
    audit, signature = _export(stores["audit_log"], settings, tmp_path)
    public_key = crypto.ed25519_public_key(settings.audit_sign_key).hex()
    result = _run(
        "--audit", str(audit), "--audit-sig", str(signature), "--pubkey", public_key
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "RESULT: OK" in result.stdout
    assert "records: 3" in result.stdout


def test_tampered_export_is_rejected(stores, settings, tmp_path: Path) -> None:
    audit, _signature = _export(stores["audit_log"], settings, tmp_path)
    rows = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    rows[1]["payload"] = {"k": 4}
    audit.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    result = _run("--audit", str(audit))
    assert result.returncode == 1
    assert "HASH_MISMATCH" in result.stdout


def test_deleted_record_is_rejected(stores, settings, tmp_path: Path) -> None:
    audit, _signature = _export(stores["audit_log"], settings, tmp_path)
    lines = audit.read_text(encoding="utf-8").splitlines()
    audit.write_text("\n".join(lines[:1] + lines[2:]) + "\n", encoding="utf-8")
    result = _run("--audit", str(audit))
    assert result.returncode == 1
    assert "SEQ_GAP" in result.stdout or "CHAIN_BREAK" in result.stdout


def test_wrong_public_key_is_rejected(stores, settings, tmp_path: Path) -> None:
    audit, signature = _export(stores["audit_log"], settings, tmp_path)
    wrong = crypto.ed25519_public_key(crypto.random_bytes(32)).hex()
    result = _run(
        "--audit", str(audit), "--audit-sig", str(signature), "--pubkey", wrong
    )
    assert result.returncode == 1
    assert "PUBKEY_MISMATCH" in result.stdout


def test_tampered_file_breaks_the_signature(stores, settings, tmp_path: Path) -> None:
    audit, signature = _export(stores["audit_log"], settings, tmp_path)
    data = audit.read_bytes()
    audit.write_bytes(data + b'\n{"seq":99}\n')
    result = _run("--audit", str(audit), "--audit-sig", str(signature))
    assert result.returncode == 1
    assert "SIG_INVALID" in result.stdout


def test_json_report_is_machine_readable(stores, settings, tmp_path: Path) -> None:
    audit, signature = _export(stores["audit_log"], settings, tmp_path)
    result = _run("--audit", str(audit), "--audit-sig", str(signature), "--json")
    assert result.returncode == 0
    report = json.loads(result.stdout)
    assert report["ok"] is True
    assert report["audit"]["records"] == 3
    assert len(report["audit"]["head_hash"]) == 64
    assert report["problems"] == []


def test_missing_file_exits_with_usage_error(tmp_path: Path) -> None:
    result = _run("--audit", str(tmp_path / "nope.jsonl"))
    assert result.returncode == 2


def test_no_arguments_exits_with_usage_error() -> None:
    result = _run()
    assert result.returncode == 2


# --- the two canonical implementations must agree byte for byte ----------------


VECTORS = [
    {"a": 1, "b": 2},
    {"z": [1, {"b": True, "a": None}], "a": "текст"},
    {"ё": "й", "a": -1},
    {"nested": {"deep": {"x": [None, False, 0]}}},
    {},
    {"k": 2**53},
]


@pytest.mark.parametrize("vector", VECTORS)
def test_canonical_implementations_agree(verifier, vector) -> None:
    assert verifier.canonical_json(vector) == package_dumps(vector)


@pytest.mark.parametrize("vector", [{"a": 1.5}, {1: "x"}, {"a": 2**53 + 1}])
def test_canonical_implementations_reject_the_same_values(verifier, vector) -> None:
    with pytest.raises(ValueError):
        verifier.canonical_json(vector)
    with pytest.raises(CanonicalError):
        package_dumps(vector)


def test_hash_implementations_agree(verifier) -> None:
    record = {"seq": 7, "ts": "2026-03-01T10:00:00Z", "kind": "poll.start",
              "poll": "abc", "payload": {"k": 3}}
    prev = bytes(range(32))
    assert verifier.record_hash(prev, record) == chain.record_hash(prev, record)
