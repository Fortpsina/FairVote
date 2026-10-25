"""Password and secret hashing with Argon2id.

Parameters follow OWASP's current recommendation for password verification
(``m=46 MiB, t=1, p=1``) and are deliberately cheap enough for the CPU budget of a
free PythonAnywhere account. The memory-hard ``voter_key`` derivation uses its own,
heavier parameters because it runs once per registration (docs/02 §2.4.2).

Nothing here compares secrets with ``==``: :func:`verify_password` delegates to
Argon2's constant-time verification, and callers must never branch on the reason a
verification failed (docs/01 T19).
"""

from __future__ import annotations

import functools
import re

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.low_level import Type

#: Argon2id parameters for password verification (OWASP 2024, second option).
PASSWORD_PARAMS = dict(
    time_cost=1, memory_cost=47104, parallelism=1, hash_len=32, salt_len=16, type=Type.ID
)

#: Heavier parameters for the deterministic ``voter_key`` KDF (docs/02 §2.4.2).
VOTER_KEY_PARAMS = dict(
    time_cost=3, memory_cost=65536, parallelism=1, hash_len=32, type=Type.ID
)

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128

_hasher = PasswordHasher(**PASSWORD_PARAMS)

#: A short list of the passwords people actually pick. Not a substitute for a full
#: breach corpus, but it removes the worst cases without shipping a 100 MB list.
COMMON_PASSWORDS = frozenset(
    {
        "password", "password1", "password123", "qwerty", "qwerty123", "123456",
        "12345678", "123456789", "1234567890", "111111", "000000", "iloveyou",
        "admin", "admin123", "administrator", "letmein", "welcome", "monkey",
        "dragon", "sunshine", "princess", "football", "baseball", "master",
        "superman", "batman", "trustno1", "abc123", "qwertyuiop", "1q2w3e4r",
        "qazwsx", "password!", "p@ssw0rd", "passw0rd", "hello123", "welcome1",
        "changeme", "secret", "love", "god", "russia", "moskva", "moscow",
        "golos", "vybory", "fairvote", "честныйголос", "пароль", "йцукен",
    }
)

_REPEATED = re.compile(r"^(.)\1+$")
_SEQUENTIAL = re.compile(r"^(?:0123456789|1234567890|abcdefghij|qwertyuiop)+$")

#: Fragments that make a password guessable no matter how long it is.
WEAK_MARKERS = (
    "qwerty",
    "123456",
    "password",
    "passwd",
    "iloveyou",
    "admin",
    "welcome",
    "letmein",
    "football",
    "abc123",
    "monkey",
)


class WeakPassword(ValueError):
    """The password does not meet the policy (message is safe to show)."""


def validate_password(password: str, *, login: str | None = None) -> None:
    """Raise :class:`WeakPassword` if the password is not acceptable.

    Policy is length-based plus a small denylist (NIST SP 800-63B: no composition
    rules, no forced rotation, compare against known-bad values). A long but
    entirely numeric or dictionary-derived password is still rejected: length
    alone is not a defence against targeted guessing.
    """
    if not isinstance(password, str):
        raise WeakPassword("пароль должен быть строкой")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPassword(f"пароль короче {MIN_PASSWORD_LENGTH} символов")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise WeakPassword(f"пароль длиннее {MAX_PASSWORD_LENGTH} символов")
    lowered = password.casefold()
    if lowered in COMMON_PASSWORDS:
        raise WeakPassword("этот пароль слишком часто используется")
    if login and lowered == login.casefold():
        raise WeakPassword("пароль не должен совпадать с логином")
    if _REPEATED.match(password) or _SEQUENTIAL.match(lowered):
        raise WeakPassword("пароль слишком простой")
    if lowered.isdigit():
        raise WeakPassword("пароль не должен состоять только из цифр")
    if any(marker in lowered for marker in WEAK_MARKERS):
        raise WeakPassword("пароль содержит общеизвестную последовательность")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Constant-time verification; never raises on mismatch or a broken hash."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError, ValueError):
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except (InvalidHashError, ValueError):
        return True


@functools.lru_cache(maxsize=1)
def dummy_hash() -> str:
    """A throw-away hash used to equalise timing for unknown logins (T19)."""
    return _hasher.hash("fairvote-dummy-" + "x" * 24)


def hash_recovery_code(code: str) -> str:
    """Recovery codes are hashed like passwords (single use, low entropy each)."""
    return _hasher.hash(code)


def verify_recovery_code(code_hash: str, code: str) -> bool:
    return verify_password(code_hash, code)
