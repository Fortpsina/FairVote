"""Identity normalisation and the deterministic ``voter_key``.

The rule "one person — one account" is implemented as a deterministic KDF over the
person's identity (docs/02 §2.4.2)::

    string = fio \\x1f dob \\x1f doc_type \\x1f series \\x1f number
    key    = Argon2id(string, salt=FV_VOTER_PEPPER_V1, t=3, m=64 MiB, p=1, len=32)

Consequences, stated up front:

* the raw identity is **never stored** — only the 32-byte key;
* a pepper leak plus a known identity lets an attacker test membership (docs/01
  T1a); that is inherent to a deterministic scheme and is documented, not hidden;
* normalisation must be aggressive and predictable, otherwise the same person can
  register twice with "Иванов" and "ИВАНОВ". The user sees the normalised form and
  confirms it before submission (:func:`display_identity`).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import date

from argon2.low_level import hash_secret_raw

from ..security.passwords import VOTER_KEY_PARAMS

SEPARATOR = "\x1f"

#: Cyrillic letters that look like Latin ones, mapped to Latin so that document
#: numbers typed with a Cyrillic keyboard still normalise to the same value.
HOMOGLYPHS = str.maketrans(
    {
        "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
        "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X",
    }
)

_ALLOWED_NAME = re.compile(r"[^\w\s-]", re.UNICODE)
_SPACES = re.compile(r"\s+")
_DOC_ALLOWED = re.compile(r"[^0-9A-Z]", re.ASCII)

DOC_TYPES = frozenset({"passport_rf", "foreign_passport", "residence_permit"})


class IdentityError(ValueError):
    """The identity input is incomplete or malformed."""


@dataclass(frozen=True)
class Identity:
    """Raw identity as typed by the applicant (never persisted)."""

    fio: str
    dob: str
    doc_type: str
    doc_series: str
    doc_number: str


def normalize_name(value: str) -> str:
    """NFKC, casefold, ё→е, strip punctuation, collapse whitespace."""
    text = unicodedata.normalize("NFKC", value).replace("\u00a0", " ").casefold()
    text = text.replace("ё", "е")
    text = _ALLOWED_NAME.sub(" ", text)
    return _SPACES.sub(" ", text).strip()


def normalize_document(value: str) -> str:
    """Digits and Latin capitals only; Cyrillic homoglyphs become Latin."""
    text = unicodedata.normalize("NFKC", value).upper().translate(HOMOGLYPHS)
    return _DOC_ALLOWED.sub("", text)


def normalize_dob(value: str) -> str:
    """Accept ``YYYY-MM-DD`` only; anything else is a typo we refuse to guess."""
    text = value.strip()
    try:
        parsed = date.fromisoformat(text)
    except ValueError as exc:
        raise IdentityError("дата рождения должна быть в формате ГГГГ-ММ-ДД") from exc
    if parsed.year < 1900 or parsed > date.today():
        raise IdentityError("дата рождения вне допустимого диапазона")
    return parsed.isoformat()


def canonical_string(identity: Identity) -> str:
    """The exact byte source of ``voter_key``; documented for auditability."""
    fio = normalize_name(identity.fio)
    dob = normalize_dob(identity.dob)
    doc_type = identity.doc_type.strip().casefold()
    if doc_type not in DOC_TYPES:
        raise IdentityError("неизвестный тип документа")
    series = normalize_document(identity.doc_series)
    number = normalize_document(identity.doc_number)
    if len(fio.split()) < 2:
        raise IdentityError("нужны фамилия и имя как в документе")
    if not series and not number:
        raise IdentityError("нужен номер документа")
    return SEPARATOR.join(("v1", fio, dob, doc_type, series, number))


def display_identity(identity: Identity) -> str:
    """Human-readable normalised form for the confirmation screen."""
    fio = normalize_name(identity.fio)
    dob = normalize_dob(identity.dob)
    series = normalize_document(identity.doc_series)
    number = normalize_document(identity.doc_number)
    document = " ".join(part for part in (series, number) if part)
    return f"{fio} · {dob} · {identity.doc_type} · {document}"


def voter_key(pepper: bytes, identity: Identity) -> bytes:
    """Deterministic 32-byte key for "one person — one account"."""
    if len(pepper) != 32:
        raise ValueError("pepper must be 32 bytes")
    material = canonical_string(identity).encode("utf-8")
    return hash_secret_raw(
        secret=material,
        salt=pepper,
        time_cost=VOTER_KEY_PARAMS["time_cost"],
        memory_cost=VOTER_KEY_PARAMS["memory_cost"],
        parallelism=VOTER_KEY_PARAMS["parallelism"],
        hash_len=VOTER_KEY_PARAMS["hash_len"],
        type=VOTER_KEY_PARAMS["type"],
    )
