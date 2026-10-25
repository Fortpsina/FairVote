"""Canonical JSON serialisation for the audit hash chain.

The audit chain hashes ``canonical_json(record)``, so the byte representation must
be identical in the application and in the independent verifier
(``scripts/verify.py``). This module implements the subset of RFC 8785 (JCS) that
the record schema actually uses:

* object keys are strings, sorted by Unicode code point, no duplicates;
* no insignificant whitespace, ``","`` and ``":"`` separators;
* UTF-8 output, non-ASCII characters are emitted literally (no ``\\u`` escapes);
* numbers are integers only, within ``±2**53`` (JCS interoperability bound);
* ``true``/``false``/``null`` are the only other scalars.

Anything else raises :class:`CanonicalError`. Floats are rejected on purpose: a
float would make the hash depend on the platform's number formatting, which is
exactly the class of bug a verifier must not inherit.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

MAX_SAFE_INTEGER = 2**53


class CanonicalError(ValueError):
    """Raised when a value cannot be represented canonically."""


def _check(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalError(f"{path}: integer out of safe range: {value}")
        return
    if isinstance(value, float):
        raise CanonicalError(f"{path}: floats are not allowed in canonical records")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError(f"{path}: object keys must be strings, got {type(key)!r}")
            _check(item, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _check(item, f"{path}[{index}]")
        return
    raise CanonicalError(f"{path}: unsupported type {type(value).__name__}")


def dumps(value: Any) -> str:
    """Return the canonical JSON text of ``value`` (UTF-8 encodable)."""
    _check(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def dump_bytes(value: Any) -> bytes:
    """Canonical JSON as UTF-8 bytes."""
    return dumps(value).encode("utf-8")


def digest(value: Any) -> bytes:
    """SHA-256 over the canonical bytes of ``value``."""
    return hashlib.sha256(dump_bytes(value)).digest()
