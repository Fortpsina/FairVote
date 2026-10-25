"""Identity normalisation and the deterministic voter_key."""

from __future__ import annotations

import pytest

from fairvote.registry.identity import (
    Identity,
    IdentityError,
    canonical_string,
    display_identity,
    normalize_dob,
    normalize_document,
    normalize_name,
    voter_key,
)

PEPPER = bytes(range(32))


def identity(**overrides) -> Identity:
    values = dict(
        fio="Иванов Иван Иванович",
        dob="1980-05-17",
        doc_type="passport_rf",
        doc_series="4510",
        doc_number="123456",
    )
    values.update(overrides)
    return Identity(**values)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ИВАНОВ ИВАН", "иванов иван"),
        ("  Иванов   Иван  ", "иванов иван"),
        ("Семёнов Пётр", "семенов петр"),
        ("Семенов Пётр", "семенов петр"),
        ("Иванов-Петров Иван", "иванов-петров иван"),
        ("Иванов, Иван.", "иванов иван"),
        ("Ёлкин\tИлья", "елкин илья"),
    ],
)
def test_normalize_name(raw: str, expected: str) -> None:
    assert normalize_name(raw) == expected


def test_normalize_name_handles_compatibility_forms() -> None:
    # Full-width characters normalise to their ASCII counterparts.
    assert normalize_name("ＩＶＡＮＯＶ Ivan") == "ivanov ivan"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("4510 123456", "4510123456"),
        ("45-10-123456", "4510123456"),
        ("45 10 123456", "4510123456"),
        ("АВ123", "AB123"),  # Cyrillic homoglyphs typed by mistake
        ("ab123", "AB123"),
    ],
)
def test_normalize_document(raw: str, expected: str) -> None:
    assert normalize_document(raw) == expected


def test_normalize_dob() -> None:
    assert normalize_dob("1980-05-17") == "1980-05-17"
    with pytest.raises(IdentityError):
        normalize_dob("17.05.1980")
    with pytest.raises(IdentityError):
        normalize_dob("2999-01-01")
    with pytest.raises(IdentityError):
        normalize_dob("1850-01-01")


def test_canonical_string_is_stable() -> None:
    first = canonical_string(identity())
    second = canonical_string(identity(fio="ИВАНОВ   ИВАН ИВАНОВИЧ"))
    assert first == second
    assert first.split("\x1f") == [
        "v1",
        "иванов иван иванович",
        "1980-05-17",
        "passport_rf",
        "4510",
        "123456",
    ]


def test_canonical_string_separates_fields_unambiguously() -> None:
    # Without a separator "Иванов Иван" + dob would collide with a shifted split.
    assert canonical_string(identity()) != canonical_string(
        identity(fio="Иванов Иван Иванович 1980", dob="2001-01-01")
    )


def test_canonical_string_rejects_incomplete_identity() -> None:
    with pytest.raises(IdentityError):
        canonical_string(identity(fio="Иванов"))
    with pytest.raises(IdentityError):
        canonical_string(identity(doc_series="", doc_number=""))
    with pytest.raises(IdentityError):
        canonical_string(identity(doc_type="passport"))


def test_voter_key_is_deterministic_and_person_specific() -> None:
    first = voter_key(PEPPER, identity())
    second = voter_key(PEPPER, identity(fio="ИВАНОВ ИВАН ИВАНОВИЧ"))
    other = voter_key(PEPPER, identity(doc_number="123457"))
    assert first == second
    assert first != other
    assert len(first) == 32


def test_voter_key_depends_on_the_pepper() -> None:
    assert voter_key(PEPPER, identity()) != voter_key(bytes(32), identity())


def test_voter_key_rejects_wrong_pepper_size() -> None:
    with pytest.raises(ValueError):
        voter_key(b"short", identity())


def test_display_identity_shows_the_normalised_form() -> None:
    shown = display_identity(identity(fio="ИВАНОВ  Иван", doc_series="45 10"))
    assert shown == "иванов иван · 1980-05-17 · passport_rf · 4510 123456"
