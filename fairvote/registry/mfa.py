"""Multi-factor authentication state: TOTP secrets and recovery codes.

The TOTP secret is stored encrypted (AES-256-GCM, AAD bound to the user id), never
in the session and never in logs. Recovery codes are stored as Argon2id hashes and
are single use; they exist so that a lost phone does not lock a voter out, which
matters because an administrator cannot read the registry and therefore cannot reset
anything (docs/04 C4).

Deliberately absent: anyone else's ability to reset MFA. Support cannot disable TOTP
for a user — only a recovery code can.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import delete, select, update

from ..db import Store, read_tx, write_tx
from ..security import crypto, passwords
from ..timeutil import to_iso, utc_now
from .models import app_user_table, recovery_code_table

RECOVERY_CODE_COUNT = 10
_RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I

TOTP_FAIL_LIMIT = 5


@dataclass(frozen=True)
class MfaState:
    secret_blob: bytes | None
    confirmed_at: str | None
    last_step: int | None
    fail_count: int
    unused_recovery_codes: int

    @property
    def enabled(self) -> bool:
        return self.confirmed_at is not None and self.secret_blob is not None


def _aad(user_id: int) -> bytes:
    return f"totp:{user_id}".encode("ascii")


def encrypt_secret(key: bytes, secret: str, user_id: int) -> bytes:
    return crypto.aead_encrypt(key, secret.encode("ascii"), aad=_aad(user_id))


def decrypt_secret(key: bytes, blob: bytes, user_id: int) -> str:
    return crypto.aead_decrypt(key, blob, aad=_aad(user_id)).decode("ascii")


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Human-transcribable codes: 10 characters, 50 bits of entropy each."""
    codes: list[str] = []
    for _ in range(count):
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def normalize_recovery_code(code: str) -> str:
    cleaned = "".join(ch for ch in (code or "").upper() if ch.isalnum())
    if len(cleaned) != 10:
        return ""
    return f"{cleaned[:5]}-{cleaned[5:]}"


# --- state ----------------------------------------------------------------------


def get_state(store: Store, user_id: int) -> MfaState:
    with read_tx(store) as connection:
        row = connection.execute(
            select(
                app_user_table.c.totp_secret_enc,
                app_user_table.c.totp_confirmed_at,
                app_user_table.c.totp_last_step,
                app_user_table.c.totp_fail_count,
            ).where(app_user_table.c.id == user_id)
        ).first()
        unused = connection.execute(
            select(recovery_code_table.c.id).where(
                recovery_code_table.c.user_id == user_id,
                recovery_code_table.c.used_at.is_(None),
            )
        ).all()
    if row is None:
        return MfaState(None, None, None, 0, 0)
    return MfaState(
        secret_blob=bytes(row[0]) if row[0] is not None else None,
        confirmed_at=row[1],
        last_step=int(row[2]) if row[2] is not None else None,
        fail_count=int(row[3]),
        unused_recovery_codes=len(unused),
    )


def store_secret(
    store: Store, user_id: int, blob: bytes, *, now: datetime | None = None
) -> None:
    """Save a not-yet-confirmed secret (``totp_confirmed_at`` stays NULL)."""
    stamp = to_iso(now or utc_now())
    with write_tx(store) as connection:
        connection.execute(
            update(app_user_table)
            .where(app_user_table.c.id == user_id)
            .values(
                totp_secret_enc=blob,
                totp_confirmed_at=None,
                totp_last_step=None,
                totp_fail_count=0,
                updated_at=stamp,
            )
        )


def confirm_secret(
    store: Store, user_id: int, step: int, *, now: datetime | None = None
) -> None:
    stamp = to_iso(now or utc_now())
    with write_tx(store) as connection:
        connection.execute(
            update(app_user_table)
            .where(app_user_table.c.id == user_id)
            .values(
                totp_confirmed_at=stamp,
                totp_last_step=step,
                totp_fail_count=0,
                updated_at=stamp,
            )
        )


def record_step(store: Store, user_id: int, step: int, *, now: datetime | None = None) -> None:
    stamp = to_iso(now or utc_now())
    with write_tx(store) as connection:
        connection.execute(
            update(app_user_table)
            .where(app_user_table.c.id == user_id)
            .values(totp_last_step=step, totp_fail_count=0, updated_at=stamp)
        )


def note_failure(store: Store, user_id: int, *, now: datetime | None = None) -> int:
    stamp = to_iso(now or utc_now())
    with write_tx(store) as connection:
        current = connection.execute(
            select(app_user_table.c.totp_fail_count).where(app_user_table.c.id == user_id)
        ).scalar_one()
        count = int(current) + 1
        connection.execute(
            update(app_user_table)
            .where(app_user_table.c.id == user_id)
            .values(totp_fail_count=count, updated_at=stamp)
        )
    return count


# --- recovery codes -------------------------------------------------------------


def replace_recovery_codes(
    store: Store, user_id: int, code_hashes: list[str], *, now: datetime | None = None
) -> None:
    stamp = to_iso(now or utc_now())
    with write_tx(store) as connection:
        connection.execute(
            delete(recovery_code_table).where(recovery_code_table.c.user_id == user_id)
        )
        for index, code_hash in enumerate(code_hashes):
            connection.execute(
                recovery_code_table.insert().values(
                    user_id=user_id,
                    idx=index,
                    code_hash=code_hash,
                    created_at=stamp,
                )
            )
        connection.execute(
            update(app_user_table)
            .where(app_user_table.c.id == user_id)
            .values(recovery_seen_at=stamp, updated_at=stamp)
        )


def hash_recovery_codes(codes: list[str]) -> list[str]:
    return [passwords.hash_recovery_code(code) for code in codes]


def consume_recovery_code(
    store: Store, user_id: int, code: str, *, now: datetime | None = None
) -> bool:
    """Verify and burn one unused code. Returns False if none matches."""
    normalized = normalize_recovery_code(code)
    if not normalized:
        return False
    with read_tx(store) as connection:
        rows = connection.execute(
            select(recovery_code_table.c.id, recovery_code_table.c.code_hash).where(
                recovery_code_table.c.user_id == user_id,
                recovery_code_table.c.used_at.is_(None),
            )
        ).all()
    for row_id, code_hash in rows:
        if passwords.verify_recovery_code(code_hash, normalized):
            stamp = to_iso(now or utc_now())
            with write_tx(store) as connection:
                result = connection.execute(
                    update(recovery_code_table)
                    .where(
                        recovery_code_table.c.id == row_id,
                        recovery_code_table.c.used_at.is_(None),
                    )
                    .values(used_at=stamp)
                )
            # A concurrent request may have burned the same code first.
            return bool(result.rowcount)
    return False


def disable_totp(store: Store, user_id: int, *, now: datetime | None = None) -> None:
    """Remove MFA material (used after a recovery-code login followed by re-enrol)."""
    stamp = to_iso(now or utc_now())
    with write_tx(store) as connection:
        connection.execute(
            update(app_user_table)
            .where(app_user_table.c.id == user_id)
            .values(
                totp_secret_enc=None,
                totp_confirmed_at=None,
                totp_last_step=None,
                totp_fail_count=0,
                updated_at=stamp,
            )
        )
        connection.execute(
            delete(recovery_code_table).where(recovery_code_table.c.user_id == user_id)
        )
