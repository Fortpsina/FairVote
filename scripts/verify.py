#!/usr/bin/env python3
"""FairVote independent verifier.

Purpose: check the published artefacts *without* running FairVote and without
trusting our server. This file is deliberately standalone — standard library plus
Ed25519 and X25519 sealed boxes (PyNaCl, or ``cryptography`` for signatures). It never
touches the network and never reads a database.

What it verifies:

* every audit record's hash: ``SHA-256(prev_hash || canonical_json(record))``;
* the link between consecutive records, the genesis value and sequence continuity;
* the record field set (an injected field is reported, not silently ignored);
* the detached Ed25519 signature of an export file, when supplied;
* every batch's Merkle root over its ciphertexts;
* decryption of the ballot box with the *published* key, the district binding inside
  each payload, option validity and the anonymity threshold, followed by a recount.

Exit codes: 0 = all checks passed, 1 = discrepancies found, 2 = usage/IO error.

The canonical-JSON function below MUST stay byte-identical to
``fairvote/security/canonical.py``; ``tests/test_verify_script.py`` pins both
implementations to shared vectors.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Iterable

GENESIS_HASH = b"\x00" * 32
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
RECORD_FIELDS = frozenset({"seq", "ts", "kind", "poll", "payload"})
ROW_FIELDS = RECORD_FIELDS | {"prev_hash", "hash"}
MAX_SAFE_INTEGER = 2**53

NODE_PREFIX = b"\x01"
EMPTY_PREFIX = b"fairvote/empty/v1"
BATCH_LEAF_DOMAIN = b"fairvote/batch/v1"
BALLOT_ID_DOMAIN = b"fairvote/ballot/v1\x00"
SEAL_OVERHEAD = 48

EXIT_OK = 0
EXIT_PROBLEMS = 1
EXIT_USAGE = 2

KNOWN_KINDS = frozenset(
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


class UsageError(Exception):
    """Bad input: exit code 2."""


# --- canonical JSON (mirror of fairvote/security/canonical.py) -------------------


def _check(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValueError(f"{path}: integer out of safe range")
        return
    if isinstance(value, float):
        raise ValueError(f"{path}: floats are not allowed")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path}: object keys must be strings")
            _check(item, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _check(item, f"{path}[{index}]")
        return
    raise ValueError(f"{path}: unsupported type {type(value).__name__}")


def canonical_json(value: Any) -> str:
    _check(value)
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def record_hash(prev_hash: bytes, record: dict[str, Any]) -> bytes:
    return sha256(prev_hash + canonical_json(record).encode("utf-8"))


# --- input ----------------------------------------------------------------------


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise UsageError(f"cannot read {path}: {exc}") from exc
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(raw.decode("utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise UsageError(f"{path}: line {number} is not JSON ({exc})") from exc
        if not isinstance(value, dict):
            raise UsageError(f"{path}: line {number} is not an object")
        rows.append(value)
    return rows


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UsageError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise UsageError(f"{path}: expected a JSON object")
    return value


def load_signature(path: Path) -> dict[str, str]:
    value = load_json(path)
    if "signature" not in value:
        raise UsageError(f"{path}: not a signature document")
    return value


# --- audit chain ----------------------------------------------------------------


def check_chain(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    problems: list[dict[str, Any]] = []
    previous_hash = GENESIS_HASH
    expected_seq = 1
    seen = 0

    def add(code: str, seq: int, detail: str) -> None:
        problems.append({"code": code, "seq": seq, "detail": detail})

    for row in rows:
        seen += 1
        if not isinstance(row, dict):
            add("MALFORMED_ROW", expected_seq, "row is not an object")
            expected_seq += 1
            continue

        seq = row.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            add("MALFORMED_ROW", expected_seq, "seq is not an integer")
            expected_seq += 1
            continue

        if seq != expected_seq:
            add("SEQ_GAP", seq, f"expected seq {expected_seq}, got {seq}")

        if not RECORD_FIELDS <= set(row):
            add("MISSING_FIELD", seq, "missing " + ", ".join(sorted(RECORD_FIELDS - set(row))))
            expected_seq = seq + 1
            continue
        extra = set(row) - ROW_FIELDS
        if extra:
            add("EXTRA_FIELD", seq, "unexpected " + ", ".join(sorted(extra)))

        record = {key: row[key] for key in RECORD_FIELDS}
        ts = record["ts"]
        if not isinstance(ts, str) or len(ts) != 20 or not ts.endswith("Z"):
            add("BAD_TIMESTAMP", seq, f"bad timestamp {ts!r}")
            expected_seq = seq + 1
            continue
        if not isinstance(record["kind"], str):
            add("MALFORMED_ROW", seq, "kind is not a string")
            expected_seq = seq + 1
            continue

        try:
            prev_hash = bytes.fromhex(str(row["prev_hash"]))
            claimed = bytes.fromhex(str(row["hash"]))
        except ValueError:
            add("MALFORMED_ROW", seq, "hash is not hex")
            expected_seq = seq + 1
            continue
        if len(prev_hash) != 32 or len(claimed) != 32:
            add("MALFORMED_ROW", seq, "hash must be 32 bytes")
            expected_seq = seq + 1
            continue

        if prev_hash != previous_hash:
            add("CHAIN_BREAK", seq, "prev_hash does not match the previous row")

        try:
            computed = record_hash(prev_hash, record)
        except ValueError as exc:
            add("NON_CANONICAL", seq, str(exc))
            expected_seq = seq + 1
            continue

        if computed != claimed:
            add("HASH_MISMATCH", seq, "record hash does not match")
        if record["kind"] not in KNOWN_KINDS:
            add("UNKNOWN_KIND", seq, f"kind {record['kind']!r} is not known")

        previous_hash = claimed
        expected_seq = seq + 1

    if seen == 0:
        add("EMPTY", 0, "no records found")
    return problems


# --- signatures -----------------------------------------------------------------


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Ed25519 verification through PyNaCl, falling back to ``cryptography``."""
    try:
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey
    except ImportError:
        pass
    else:
        try:
            VerifyKey(public_key).verify(message, signature)
        except (BadSignatureError, ValueError):
            return False
        return True

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise UsageError("signature checks need PyNaCl or cryptography installed") from exc
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def check_signature(
    data: bytes, signature_doc: dict[str, str], public_key_hex: str | None
) -> list[dict[str, Any]]:
    try:
        signature = bytes.fromhex(signature_doc["signature"])
        embedded_key = signature_doc.get("public_key")
    except (KeyError, ValueError):
        return [{"code": "SIG_MALFORMED", "seq": 0, "detail": "signature document is broken"}]
    if signature_doc.get("alg") not in (None, "ed25519"):
        return [
            {
                "code": "SIG_ALGORITHM",
                "seq": 0,
                "detail": f"unsupported algorithm {signature_doc.get('alg')!r}",
            }
        ]

    key_hex = public_key_hex or embedded_key
    if not key_hex:
        return [
            {
                "code": "PUBKEY_MISSING",
                "seq": 0,
                "detail": "no public key given and none embedded in the signature",
            }
        ]
    if public_key_hex and embedded_key and public_key_hex.lower() != embedded_key.lower():
        return [
            {
                "code": "PUBKEY_MISMATCH",
                "seq": 0,
                "detail": "signature embeds a different public key",
            }
        ]
    try:
        public_key = bytes.fromhex(key_hex)
    except ValueError:
        return [{"code": "PUBKEY_MALFORMED", "seq": 0, "detail": "public key is not hex"}]
    if len(public_key) != 32:
        return [{"code": "PUBKEY_MALFORMED", "seq": 0, "detail": "public key must be 32 bytes"}]

    if not verify_ed25519(public_key, sha256(data), signature):
        return [
            {"code": "SIG_INVALID", "seq": 0, "detail": "signature does not match SHA-256 of the file"}
        ]
    return []


# --- ballots --------------------------------------------------------------------


def _node_hash(*parts: bytes) -> bytes:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


def merkle_root(leaves: Iterable[bytes]) -> bytes:
    level = [bytes(leaf) for leaf in leaves]
    if not level:
        return _node_hash(EMPTY_PREFIX)
    while len(level) > 1:
        merged: list[bytes] = []
        for index in range(0, len(level) - 1, 2):
            merged.append(_node_hash(NODE_PREFIX, level[index], level[index + 1]))
        if len(level) % 2:
            merged.append(level[-1])
        level = merged
    return level[0]


def batch_leaf(ciphertext: bytes) -> bytes:
    return _node_hash(BATCH_LEAF_DOMAIN, ciphertext)


def unseal(ciphertext: bytes, private_key: bytes) -> bytes:
    try:
        from nacl.public import PrivateKey, SealedBox
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise UsageError("decryption needs PyNaCl installed") from exc
    try:
        return SealedBox(PrivateKey(private_key)).decrypt(ciphertext)
    except Exception as exc:  # noqa: BLE001 - libsodium raises its own type
        raise ValueError(str(exc)) from exc


def public_from_private(private_key: bytes) -> bytes:
    from nacl.public import PrivateKey

    return bytes(PrivateKey(private_key).public_key)


def fingerprint(public_key: bytes) -> str:
    return hashlib.blake2b(public_key, digest_size=32).hexdigest()


def check_batches(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[int, int]]:
    """Recompute each batch root and check that rows agree on it."""
    problems: list[dict[str, Any]] = []
    grouped: dict[int, list[bytes]] = {}
    roots: dict[int, str] = {}
    for row in rows:
        batch = row.get("batch")
        if not isinstance(batch, int):
            problems.append({"code": "BATCH_FIELD", "seq": row.get("seq", 0), "detail": "bad batch id"})
            continue
        try:
            ciphertext = base64.b64decode(str(row.get("ct", "")), validate=True)
        except ValueError:
            problems.append(
                {"code": "BALLOT_MALFORMED", "seq": row.get("seq", 0), "detail": "ct is not base64"}
            )
            continue
        grouped.setdefault(batch, []).append(ciphertext)
        declared = row.get("batch_root")
        if not isinstance(declared, str):
            problems.append(
                {"code": "BATCH_FIELD", "seq": row.get("seq", 0), "detail": "batch_root missing"}
            )
            continue
        known = roots.setdefault(batch, declared)
        if known != declared:
            problems.append(
                {"code": "BATCH_ROOT_CONFLICT", "seq": row.get("seq", 0), "detail": "two roots for one batch"}
            )
    for batch, ciphertexts in grouped.items():
        computed = merkle_root(batch_leaf(item) for item in ciphertexts).hex()
        if roots.get(batch) != computed:
            problems.append(
                {
                    "code": "BATCH_ROOT_MISMATCH",
                    "seq": 0,
                    "detail": f"batch {batch}: computed {computed}",
                }
            )
    sizes = {batch: len(items) for batch, items in grouped.items()}
    return problems, sizes


def check_audit_links(
    ballots: list[dict[str, Any]], audit: list[dict[str, Any]], poll: dict[str, Any]
) -> list[dict[str, Any]]:
    """Bind the exported box to the commitments in the supplied audit chain.

    Self-consistent roots in an edited box do not prove it is the committed box.
    The audit chain/signing key must still be independently pinned by the reader.
    """
    problems: list[dict[str, Any]] = []
    poll_id = poll.get("id")

    def add(code: str, detail: str) -> None:
        problems.append({"code": code, "seq": 0, "detail": detail})

    relevant = [row for row in audit if row.get("poll") == poll_id]
    committed = {}
    for entry in relevant:
        if entry.get("kind") != "ballot.batch":
            continue
        batch = entry["payload"].get("batch_id")
        if not isinstance(batch, int):
            add("AUDIT_BATCH_FIELD", "invalid committed batch id")
            continue
        if batch in committed:
            add("AUDIT_BATCH_DUPLICATE", f"batch {batch} committed more than once")
        committed[batch] = entry

    grouped: dict[int, list[dict[str, Any]]] = {}
    for row in ballots:
        if row.get("poll") != poll_id:
            add("EXPORT_POLL_MISMATCH", "export row belongs to a different poll")
        batch = row.get("batch")
        if isinstance(batch, int):
            grouped.setdefault(batch, []).append(row)
    for batch in set(grouped) | set(committed):
        rows = grouped.get(batch, [])
        entry = committed.get(batch)
        if not rows or entry is None:
            add("AUDIT_BATCH_MISSING", f"batch {batch} is absent from the box or audit")
            continue
        payload = entry["payload"]
        seqs = [row.get("seq") for row in rows]
        if not all(isinstance(seq, int) for seq in seqs):
            add("AUDIT_BATCH_MISMATCH", f"batch {batch} has invalid sequence numbers")
            continue
        if (payload.get("size") != len(rows)
                or payload.get("first_seq") != min(seqs)
                or payload.get("last_seq") != max(seqs)
                or any(row.get("batch_root") != payload.get("root")
                       or row.get("audit_seq") != entry.get("seq") for row in rows)):
            add("AUDIT_BATCH_MISMATCH", f"batch {batch} differs from its journal commitment")

    starts = [row for row in relevant if row.get("kind") == "poll.start"]
    closes = [row for row in relevant if row.get("kind") == "poll.close"]
    if len(starts) != 1 or len(closes) != 1:
        add("AUDIT_POLL_LIFECYCLE", "expected one poll.start and one poll.close")
    else:
        start, close = starts[0], closes[0]
        for field in ("starts_at", "ends_at", "k_threshold", "ballot_plaintext_bytes"):
            if poll.get(field) != start["payload"].get(field):
                add("AUDIT_POLL_MISMATCH", f"poll configuration differs for {field}")
        if close["payload"].get("box_count") != len(ballots):
            add("AUDIT_BOX_COUNT", "box row count differs from poll.close")
        if any(not (start["seq"] < row["seq"] < close["seq"]) for row in committed.values()):
            add("AUDIT_BATCH_ORDER", "batch commitment is outside the voting lifecycle")
        keys = [row for row in relevant if row.get("kind") == "poll.key_commit"
                and row["seq"] < start["seq"]]
        if not keys or keys[-1]["payload"].get("fingerprint") != poll.get("key_fingerprint"):
            add("AUDIT_KEY_MISMATCH", "key fingerprint differs from the pre-start commitment")
    return problems


def recount(
    rows: list[dict[str, Any]], poll: dict[str, Any], private_key: bytes
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    problems: list[dict[str, Any]] = []
    contests = {item["id"]: item for item in poll.get("contests", [])}
    k_threshold = int(poll.get("k_threshold", 1))
    expected_size = int(poll.get("ballot_plaintext_bytes", 0))
    poll_id = poll.get("id")
    if not isinstance(poll_id, str) or not expected_size:
        raise UsageError("poll document must contain id and ballot_plaintext_bytes")

    national = {
        contest_id: {option["id"]: 0 for option in contest.get("options", [])}
        for contest_id, contest in contests.items()
    }
    districts: dict[str, dict[str, Any]] = {}
    stats = {"total": 0, "valid": 0, "spoiled": 0, "invalid": 0}

    for row in rows:
        stats["total"] += 1
        district = str(row.get("district"))
        bucket = districts.setdefault(
            district,
            {
                "total": 0,
                "valid": 0,
                "spoiled": 0,
                "invalid": 0,
                "suppressed": False,
            },
        )
        bucket["total"] += 1
        seq = row.get("seq", 0)
        try:
            ciphertext = base64.b64decode(str(row["ct"]), validate=True)
            plaintext = unseal(ciphertext, private_key)
        except (ValueError, KeyError):
            stats["invalid"] += 1
            bucket["invalid"] += 1
            problems.append({"code": "DECRYPT_FAIL", "seq": seq, "detail": "cannot open ballot"})
            continue
        if len(plaintext) != expected_size:
            stats["invalid"] += 1
            bucket["invalid"] += 1
            problems.append({"code": "PAYLOAD_SIZE", "seq": seq, "detail": "wrong plaintext size"})
            continue
        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            stats["invalid"] += 1
            bucket["invalid"] += 1
            problems.append({"code": "PAYLOAD_INVALID", "seq": seq, "detail": "not JSON"})
            continue
        if payload.get("poll") != poll_id:
            problems.append({"code": "POLL_MISMATCH", "seq": seq, "detail": "poll id differs"})
            stats["invalid"] += 1
            bucket["invalid"] += 1
            continue
        if payload.get("district") != district:
            problems.append(
                {"code": "DISTRICT_MISMATCH", "seq": seq, "detail": "payload district differs"}
            )
            stats["invalid"] += 1
            bucket["invalid"] += 1
            continue

        choices = payload.get("contests") or {}
        valid = True
        for contest_id, option_id in choices.items():
            contest = contests.get(contest_id)
            if contest is None:
                valid = False
                problems.append(
                    {"code": "CONTEST_NOT_ELIGIBLE", "seq": seq, "detail": contest_id}
                )
                break
            if contest.get("scope") == "district" and contest.get("district_code") != district:
                valid = False
                problems.append(
                    {"code": "CONTEST_NOT_ELIGIBLE", "seq": seq, "detail": contest_id}
                )
                break
            option_ids = {option["id"] for option in contest.get("options", [])}
            if option_id not in option_ids:
                valid = False
                problems.append({"code": "OPTION_UNKNOWN", "seq": seq, "detail": option_id})
                break
        if not valid:
            stats["invalid"] += 1
            bucket["invalid"] += 1
            continue
        if payload.get("spoil") is True:
            stats["spoiled"] += 1
            bucket["spoiled"] += 1
            continue

        stats["valid"] += 1
        bucket["valid"] += 1
        for contest_id, option_id in choices.items():
            national[contest_id][option_id] += 1

    for code, bucket in districts.items():
        if bucket["total"] < k_threshold:
            bucket["suppressed"] = True

    result = {
        "poll_id": poll_id,
        "stats": stats,
        "national": national,
        "by_district": districts,
        "suppressed_districts": sorted(c for c, b in districts.items() if b["suppressed"]),
    }
    return result, problems


def check_key(poll: dict[str, Any], key_doc: dict[str, Any]) -> tuple[bytes | None, list[dict[str, Any]]]:
    problems: list[dict[str, Any]] = []
    private_hex = key_doc.get("private_key") or key_doc.get("private_key_hex")
    if not private_hex:
        return None, [
            {"code": "KEY_MISSING", "seq": 0, "detail": "no private key in the key document"}
        ]
    try:
        private_key = bytes.fromhex(str(private_hex))
    except ValueError:
        return None, [{"code": "KEY_MALFORMED", "seq": 0, "detail": "private key is not hex"}]
    derived = public_from_private(private_key)
    derived_fp = fingerprint(derived)
    expected = poll.get("key_fingerprint")
    if expected and derived_fp != expected:
        problems.append(
            {
                "code": "KEY_MISMATCH",
                "seq": 0,
                "detail": "key does not match the commitment from poll.start",
            }
        )
    declared = key_doc.get("fingerprint")
    if declared and declared != derived_fp:
        problems.append(
            {"code": "KEY_DOC_MISMATCH", "seq": 0, "detail": "key document fingerprint differs"}
        )
    return private_key, problems


def check_expected(result: dict[str, Any], expected: dict[str, Any]) -> list[dict[str, Any]]:
    problems: list[dict[str, Any]] = []
    for contest_id, counts in expected.get("national", {}).items():
        actual = result["national"].get(contest_id, {})
        if actual != counts:
            problems.append(
                {
                    "code": "TALLY_MISMATCH",
                    "seq": 0,
                    "detail": f"contest {contest_id}: {actual} != {counts}",
                }
            )
    return problems


# --- CLI ------------------------------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verify.py",
        description="Verify FairVote transparency artefacts offline.",
    )
    parser.add_argument("--audit", type=Path, help="audit chain export (JSONL)")
    parser.add_argument("--audit-sig", type=Path, help="detached signature of --audit")
    parser.add_argument("--ballots", type=Path, help="ballot box export (JSONL)")
    parser.add_argument("--ballots-sig", type=Path, help="detached signature of --ballots")
    parser.add_argument("--poll", type=Path, help="published poll document (JSON)")
    parser.add_argument("--poll-key", type=Path, help="published poll key (JSON)")
    parser.add_argument("--results", type=Path, help="expected results (JSON)")
    parser.add_argument("--find", help="print the row with this ballot id")
    parser.add_argument(
        "--derive-ballot-id",
        action="store_true",
        dest="derive",
        help="derive a ballot id from --secret and --poll",
    )
    parser.add_argument("--secret", help="secret in Crockford base32 (with the dashes it had)")
    parser.add_argument("--poll-id", dest="poll_id", help="poll id for --derive-ballot-id")
    parser.add_argument("--pubkey", help="Ed25519 public key (hex) obtained independently")
    parser.add_argument("--json", action="store_true", help="machine-readable report")
    return parser


CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def secret_from_words(text: str) -> bytes:
    """Decode a human-written secret (mirror of secretFromWords in payload.js)."""
    cleaned = (
        str(text or "").upper().replace("-", "").replace(" ", "").replace("O", "0").replace("I", "1").replace("L", "1")
    )
    buffer = 0
    bits = 0
    out = bytearray()
    for character in cleaned:
        if character not in CROCKFORD:
            raise UsageError(f"недопустимый символ в секрете: {character!r}")
        buffer = (buffer << 5) | CROCKFORD.index(character)
        bits += 5
        if bits >= 8:
            out.append((buffer >> (bits - 8)) & 0xFF)
            bits -= 8
    if len(out) < 32:
        raise UsageError("секрет слишком короткий")
    return bytes(out[:32])


def derive_ballot_id(secret: bytes, poll_id: str) -> str:
    import hmac as _hmac

    message = BALLOT_ID_DOMAIN + poll_id.encode("utf-8")
    return _hmac.new(secret, message, hashlib.sha256).hexdigest()


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)

    if args.derive:
        if not args.secret or not args.poll_id:
            print("error: --derive-ballot-id needs --secret and --poll-id", file=sys.stderr)
            return EXIT_USAGE
        try:
            secret = secret_from_words(args.secret)
        except UsageError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_USAGE
        print(derive_ballot_id(secret, args.poll_id))
        return EXIT_OK

    if args.find:
        if not args.ballots:
            print("error: --find needs --ballots", file=sys.stderr)
            return EXIT_USAGE
        try:
            rows = load_jsonl(args.ballots)
        except UsageError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_USAGE
        matches = [row for row in rows if row.get("ballot_id") == args.find]
        if not matches:
            print("not found")
            return EXIT_PROBLEMS
        for row in matches:
            print(canonical_json(row))
        return EXIT_OK
    if not any([args.audit, args.ballots]):
        _parser().print_usage(sys.stderr)
        print("error: --audit or --ballots is required", file=sys.stderr)
        return EXIT_USAGE

    problems: list[dict[str, Any]] = []
    report: dict[str, Any] = {"ok": False, "problems": problems}

    audit_rows = None
    try:
        if args.audit:
            rows = load_jsonl(args.audit)
            chain_problems = check_chain(rows)
            audit_rows = rows if not chain_problems else None
            problems.extend(chain_problems)
            report["audit"] = {
                "records": len(rows),
                "head_hash": rows[-1].get("hash") if rows else "",
            }
            if args.audit_sig:
                signature_doc = load_signature(args.audit_sig)
                problems.extend(
                    check_signature(args.audit.read_bytes(), signature_doc, args.pubkey)
                )
                report["audit"]["signature_checked"] = True

        if args.ballots:
            if not args.poll or not args.poll_key:
                raise UsageError("--ballots requires --poll and --poll-key")
            ballots = load_jsonl(args.ballots)
            poll = load_json(args.poll)
            key_doc = load_json(args.poll_key)
            private_key, key_problems = check_key(poll, key_doc)
            problems.extend(key_problems)
            batch_problems, sizes = check_batches(ballots)
            problems.extend(batch_problems)
            if audit_rows is not None:
                problems.extend(check_audit_links(ballots, audit_rows, poll))
                report["audit"]["box_linkage_checked"] = True
            if private_key is not None:
                result, recount_problems = recount(ballots, poll, private_key)
                problems.extend(recount_problems)
                if args.results:
                    problems.extend(check_expected(result, load_json(args.results)))
                report["ballots"] = {
                    "rows": len(ballots),
                    "batches": len(sizes),
                    "results": result,
                }
            if args.ballots_sig:
                signature_doc = load_signature(args.ballots_sig)
                problems.extend(
                    check_signature(args.ballots.read_bytes(), signature_doc, args.pubkey)
                )
    except UsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    report["ok"] = not problems
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        for problem in problems:
            print(f"[{problem['code']}] seq {problem['seq']}: {problem['detail']}")
        if "audit" in report:
            print(f"audit records: {report['audit']['records']}")
            print(f"audit head: {report['audit']['head_hash']}")
        if "ballots" in report:
            result = report["ballots"]["results"]
            stats = result["stats"]
            print(f"ballots: {stats['total']} valid={stats['valid']} "
                  f"spoiled={stats['spoiled']} invalid={stats['invalid']}")
            for contest_id, counts in result["national"].items():
                print(f"  {contest_id}: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
        print("RESULT:", "OK" if report["ok"] else f"{len(problems)} PROBLEM(S)")

    return EXIT_OK if report["ok"] else EXIT_PROBLEMS


if __name__ == "__main__":
    sys.exit(main())
