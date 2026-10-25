"""The ballot payload: fixed-size, canonical JSON, encrypted in the browser.

The size is fixed per poll (``ballot_plaintext_bytes``) and the browser pads the
payload to exactly that size, so every ciphertext in a poll has the same length —
the length leaks neither the number of choices nor a "yes/no" pattern (docs/01 T12).

This module is the server-side mirror of ``static/js/payload.js``. The two must
produce byte-identical output for identical inputs; ``tests/test_payload_js.py``
compares them with Node.

Payload (canonical JSON, keys sorted)::

    {"v":1,"poll":"<uuid>","district":"<code>",
     "contests":{"<contest_id>":"<option_id>"},"spoil":false,"pad":"<random hex>"}
"""

from __future__ import annotations

import json
import secrets
from typing import Callable, Mapping

from ..security import crypto
from ..security.canonical import CanonicalError, dump_bytes

PAYLOAD_VERSION = 1
SEAL_OVERHEAD = 48  # crypto_box_seal: ephemeral public key (32) + MAC (16)
MIN_PAYLOAD = 512
MAX_PAYLOAD = 8192
MAX_CONTESTS = 32
_PAD_OVERHEAD = len(',"pad":""')

BALLOT_ID_DOMAIN = b"fairvote/ballot/v1\x00"
SECRET_DOMAIN = b"fairvote/secret/v1"
MIN_PASSPHRASE_LENGTH = 20
MIN_PASSPHRASE_WORDS = 4
#: Must match libsodium's crypto_pwhash_OPSLIMIT_INTERACTIVE / MEMLIMIT_INTERACTIVE.
PASSPHRASE_OPS = 2
PASSPHRASE_MEMORY_KIB = 65536

PadSource = Callable[[int], str]


class PayloadError(ValueError):
    """The payload cannot be built or does not have the expected shape."""


def _default_pad(length: int) -> str:
    if length <= 0:
        return ""
    return secrets.token_hex((length + 1) // 2)[:length]


def _render(base: dict, pad: str | None) -> bytes:
    data = dict(base)
    if pad is not None:
        data["pad"] = pad
    try:
        return dump_bytes(data)
    except CanonicalError as exc:  # pragma: no cover - inputs are validated
        raise PayloadError(str(exc)) from exc


def build_payload(
    *,
    poll_id: str,
    district_code: str,
    choices: Mapping[str, str],
    spoil: bool = False,
    size: int,
    pad_source: PadSource | None = None,
) -> bytes:
    """Build a payload of exactly ``size`` bytes."""
    if not (MIN_PAYLOAD <= size <= MAX_PAYLOAD):
        raise PayloadError("размер бюллетеня вне допустимого диапазона")
    if not poll_id or not district_code:
        raise PayloadError("нужны poll_id и district_code")
    if len(choices) > MAX_CONTESTS:
        raise PayloadError("слишком много пунктов для одного бюллетеня")
    for contest_id, option_id in choices.items():
        if not isinstance(contest_id, str) or not isinstance(option_id, str):
            raise PayloadError("пункты бюллетеня должны быть строками")

    base = {
        "v": PAYLOAD_VERSION,
        "poll": poll_id,
        "district": district_code,
        "contests": dict(choices),
        "spoil": bool(spoil),
    }
    unpadded = _render(base, None)
    if len(unpadded) == size:
        return unpadded
    pad_length = size - len(unpadded) - _PAD_OVERHEAD
    if pad_length < 0:
        raise PayloadError("бюллетень не помещается в заданный размер")

    pad = (pad_source or _default_pad)(pad_length)
    if len(pad) != pad_length:
        raise PayloadError("источник padding вернул строку неверной длины")
    payload = _render(base, pad)
    if len(payload) != size:
        raise PayloadError("не удалось достичь точного размера бюллетеня")
    return payload


def parse_payload(plaintext: bytes, *, expected_size: int | None = None) -> dict:
    """Parse and sanity-check a payload (used by the tally and by tests)."""
    if expected_size is not None and len(plaintext) != expected_size:
        raise PayloadError("неверный размер открытого текста")
    try:
        data = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PayloadError("бюллетень не является JSON") from exc
    if not isinstance(data, dict):
        raise PayloadError("бюллетень должен быть объектом")
    if data.get("v") != PAYLOAD_VERSION:
        raise PayloadError("неизвестная версия бюллетеня")
    if not isinstance(data.get("poll"), str) or not isinstance(data.get("district"), str):
        raise PayloadError("в бюллетене нет poll/district")
    contests = data.get("contests")
    if not isinstance(contests, dict) or len(contests) > MAX_CONTESTS:
        raise PayloadError("неверный список пунктов")
    if not all(isinstance(key, str) and isinstance(value, str) for key, value in contests.items()):
        raise PayloadError("пункты бюллетеня должны быть строками")
    if not isinstance(data.get("spoil", False), bool):
        raise PayloadError("spoil должен быть булевым")
    return data


def derive_ballot_id(secret: bytes, poll_id: str) -> str:
    """``HMAC-SHA256(secret, "fairvote/ballot/v1\\0" || poll_id)`` in hex.

    Computed in the browser; the server never sees the secret. The same function
    exists in ``static/js/payload.js`` and is cross-checked by a test.
    """
    if not isinstance(secret, bytes) or not secret:
        raise PayloadError("секрет должен быть непустыми байтами")
    message = BALLOT_ID_DOMAIN + poll_id.encode("utf-8")
    return crypto.hmac_sha256(secret, message).hex()


def sealed_size(plaintext_size: int) -> int:
    return plaintext_size + SEAL_OVERHEAD


def validate_passphrase(passphrase: str) -> str:
    """Mirror of ``validatePassphrase`` in payload.js."""
    text = (passphrase or "").strip()
    if len(text) < MIN_PASSPHRASE_LENGTH:
        raise PayloadError(f"кодовое слово короче {MIN_PASSPHRASE_LENGTH} символов")
    if len(text.split()) < MIN_PASSPHRASE_WORDS:
        raise PayloadError(f"нужно не меньше {MIN_PASSPHRASE_WORDS} слов")
    return text


def passphrase_salt(poll_id: str) -> bytes:
    return crypto.sha256(SECRET_DOMAIN + b"|" + poll_id.encode("utf-8"))[:16]


def derive_secret_from_passphrase(passphrase: str, poll_id: str) -> bytes:
    """Argon2id(passphrase, salt=SHA-256(domain|poll_id)[:16]) — mirror of the browser."""
    from argon2.low_level import Type, hash_secret_raw

    text = validate_passphrase(passphrase)
    return hash_secret_raw(
        secret=text.encode("utf-8"),
        salt=passphrase_salt(poll_id),
        time_cost=PASSPHRASE_OPS,
        memory_cost=PASSPHRASE_MEMORY_KIB,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )
