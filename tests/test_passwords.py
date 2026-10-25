"""Password policy and Argon2id wrappers."""

from __future__ import annotations

import pytest
from argon2 import PasswordHasher
from argon2.low_level import Type

from fairvote.security import passwords

GOOD = "korrektnyj-parol-2026"


def test_policy_accepts_a_reasonable_password() -> None:
    passwords.validate_password(GOOD)


@pytest.mark.parametrize(
    "bad",
    ["short", "a" * 11, "a" * 129, "password", "Password123", "123456789012",
     "aaaaaaaaaaaaaaa", "qwertyuiop123"],
)
def test_policy_rejects_weak_passwords(bad: str) -> None:
    with pytest.raises(passwords.WeakPassword):
        passwords.validate_password(bad)


def test_policy_rejects_password_equal_to_login() -> None:
    with pytest.raises(passwords.WeakPassword, match="совпадать"):
        passwords.validate_password("ivanovivanivan", login="IVANOVIVANIVAN")


def test_hash_and_verify_round_trip() -> None:
    stored = passwords.hash_password(GOOD)
    assert stored.startswith("$argon2id$")
    assert passwords.verify_password(stored, GOOD)
    assert not passwords.verify_password(stored, GOOD + "x")


def test_verify_survives_broken_hashes() -> None:
    assert not passwords.verify_password("", GOOD)
    assert not passwords.verify_password("not-a-hash", GOOD)
    assert not passwords.verify_password("$argon2id$v=19$m=1,t=1,p=1$abc$def", GOOD)


def test_needs_rehash_detects_weaker_parameters() -> None:
    old = PasswordHasher(
        time_cost=1, memory_cost=8192, parallelism=1, hash_len=32, salt_len=16, type=Type.ID
    ).hash(GOOD)
    assert passwords.needs_rehash(old) is True
    assert passwords.needs_rehash(passwords.hash_password(GOOD)) is False
    assert passwords.needs_rehash("garbage") is True


def test_two_hashes_of_the_same_password_differ() -> None:
    assert passwords.hash_password(GOOD) != passwords.hash_password(GOOD)


def test_dummy_hash_is_stable_and_verifies_nothing() -> None:
    first = passwords.dummy_hash()
    assert first == passwords.dummy_hash()
    assert not passwords.verify_password(first, GOOD)


def test_recovery_codes_are_hashed_like_passwords() -> None:
    stored = passwords.hash_recovery_code("ABCD-EFGH-IJKL")
    assert passwords.verify_recovery_code(stored, "ABCD-EFGH-IJKL")
    assert not passwords.verify_recovery_code(stored, "ABCD-EFGH-IJKM")
