"""Canonical JSON: the byte format the audit chain hashes."""

from __future__ import annotations

import json

import pytest

from fairvote.security.canonical import CanonicalError, digest, dump_bytes, dumps


def test_keys_are_sorted_and_compact() -> None:
    assert dumps({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_nested_structures_are_stable() -> None:
    value = {"z": [1, {"b": True, "a": None}], "a": "текст"}
    assert dumps(value) == '{"a":"текст","z":[1,{"a":null,"b":true}]}'


def test_unicode_is_not_escaped() -> None:
    assert dumps({"имя": "ё"}) == '{"имя":"ё"}'
    assert json.loads(dump_bytes({"имя": "ё"}).decode("utf-8")) == {"имя": "ё"}


def test_insertion_order_does_not_matter() -> None:
    left = dumps({"a": 1, "b": [1, 2], "c": {"d": None}})
    right = dumps({"c": {"d": None}, "b": [1, 2], "a": 1})
    assert left == right


def test_tuples_are_arrays() -> None:
    assert dumps({"a": (1, 2)}) == '{"a":[1,2]}'


def test_negative_and_zero_integers() -> None:
    assert dumps({"a": 0, "b": -1}) == '{"a":0,"b":-1}'


@pytest.mark.parametrize("value", [{"a": 1.5}, {"a": float("nan")}, [0.0]])
def test_floats_are_rejected(value) -> None:
    with pytest.raises(CanonicalError):
        dumps(value)


def test_non_string_keys_are_rejected() -> None:
    with pytest.raises(CanonicalError):
        dumps({1: "a"})


def test_integers_outside_safe_range_are_rejected() -> None:
    with pytest.raises(CanonicalError):
        dumps({"a": 2**53 + 1})


def test_unsupported_types_are_rejected() -> None:
    with pytest.raises(CanonicalError):
        dumps({"a": object()})
    with pytest.raises(CanonicalError):
        dumps({"a": b"bytes"})


def test_digest_is_sha256_of_the_canonical_bytes() -> None:
    import hashlib

    value = {"seq": 1, "kind": "poll.create"}
    assert digest(value) == hashlib.sha256(dump_bytes(value)).digest()


def test_known_vector_is_pinned() -> None:
    """Changing the canonical form breaks every published hash, so pin it."""
    assert dump_bytes({"a": 1, "b": "ё"}) == b'{"a":1,"b":"\xd1\x91"}'
