"""Manual verification by a one-time code (docs/05 D-3).

No documents are uploaded. The applicant gets a short single-use code, hands it to
the verification provider out of band, and the provider records the decision with
``flask verification-decide``. FairVote stores only: the code hash (Argon2id), the
method, the date and a reason code.

Why the code is hashed and looked up by scanning: an 8-character code over a
32-letter alphabet is ~40 bits, and a database dump must not let anyone brute-force
"which codes are still pending". Pending requests are few, and the web endpoint is
rate limited.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select, update

from ..db import Store, read_tx, write_tx
from ..security import passwords
from ..timeutil import from_iso, to_iso, utc_now
from .models import app_user_table, verification_request_table
from .service import User, log_event

CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I
CODE_LENGTH = 8
CODE_TTL_DAYS = 14
MAX_REQUESTS_PER_USER = 3

METHODS = ("demo", "manual", "idp", "esign")
REASON_CODES = ("document_unreadable", "not_eligible", "identity_mismatch", "other")


class VerificationError(ValueError):
    """The request cannot be created or decided; the message is user-safe."""


class CodeNotFound(VerificationError):
    """No pending request matches this code."""


@dataclass(frozen=True)
class Request:
    id: int
    user_id: int
    method: str
    created_at: str
    expires_at: str
    decision: str | None


def generate_code() -> str:
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))
    return f"{raw[:4]}-{raw[4:]}"


def normalize_code(code: str) -> str:
    cleaned = "".join(ch for ch in (code or "").upper() if ch.isalnum())
    if len(cleaned) != CODE_LENGTH:
        return ""
    return f"{cleaned[:4]}-{cleaned[4:]}"


def _hash(code: str) -> bytes:
    return passwords.hash_recovery_code(code).encode("ascii")


def request_verification(
    store: Store,
    user: User,
    *,
    method: str = "manual",
    now: datetime | None = None,
) -> tuple[str, Request]:
    """Create a pending request and return ``(code, request)`` — show the code once."""
    if method not in METHODS:
        raise VerificationError("неизвестный метод проверки")
    if user.status not in {"registered", "rejected"}:
        raise VerificationError("заявка уже отправлена или аккаунт уже проверен")

    moment = now or utc_now()
    with read_tx(store) as connection:
        existing = connection.execute(
            select(
                verification_request_table.c.id,
                verification_request_table.c.created_at,
                verification_request_table.c.expires_at,
                verification_request_table.c.decision,
            ).where(verification_request_table.c.user_id == user.id)
        ).all()
    pending = [row for row in existing if row[3] is None and from_iso(row[2]) > moment]
    if pending:
        raise VerificationError("заявка уже ожидает решения")
    if len(existing) >= MAX_REQUESTS_PER_USER:
        raise VerificationError("исчерпан лимит заявок")

    code = generate_code()
    stamp = to_iso(moment)
    expires = to_iso(moment + timedelta(days=CODE_TTL_DAYS))
    with write_tx(store) as connection:
        result = connection.execute(
            verification_request_table.insert().values(
                user_id=user.id,
                method=method,
                code_hash=_hash(code),
                created_at=stamp,
                expires_at=expires,
            )
        )
        request_id = int(result.inserted_primary_key[0])
        connection.execute(
            update(app_user_table)
            .where(app_user_table.c.id == user.id)
            .values(status="proof_submitted", verify_method=method, updated_at=stamp)
        )
    log_event(store, "verification_request", user_id=user.id, detail=method, now=moment)
    return code, Request(
        id=request_id,
        user_id=user.id,
        method=method,
        created_at=stamp,
        expires_at=expires,
        decision=None,
    )


def find_pending(store: Store, code: str, *, now: datetime | None = None) -> Request:
    normalized = normalize_code(code)
    if not normalized:
        raise CodeNotFound("код не найден")
    moment = now or utc_now()
    with read_tx(store) as connection:
        rows = connection.execute(
            select(
                verification_request_table.c.id,
                verification_request_table.c.user_id,
                verification_request_table.c.method,
                verification_request_table.c.code_hash,
                verification_request_table.c.created_at,
                verification_request_table.c.expires_at,
            ).where(verification_request_table.c.decision.is_(None))
        ).all()
    for row in rows:
        if from_iso(row[5]) <= moment:
            continue
        if passwords.verify_recovery_code(bytes(row[3]).decode("ascii"), normalized):
            return Request(
                id=int(row[0]),
                user_id=int(row[1]),
                method=row[2],
                created_at=row[4],
                expires_at=row[5],
                decision=None,
            )
    raise CodeNotFound("код не найден или истёк")


def decide(
    store: Store,
    code: str,
    *,
    approved: bool,
    decided_by: str,
    reason: str | None = None,
    now: datetime | None = None,
) -> tuple[int, str]:
    """Record the provider's decision. Returns ``(user_id, new_status)``."""
    if not approved and reason is not None and reason not in REASON_CODES:
        raise VerificationError("неизвестный код причины")
    moment = now or utc_now()
    stamp = to_iso(moment)
    request = find_pending(store, code, now=moment)
    status = "verified" if approved else "rejected"
    with write_tx(store) as connection:
        claimed = connection.execute(
            update(verification_request_table)
            .where(
                verification_request_table.c.id == request.id,
                verification_request_table.c.decision.is_(None),
            )
            .values(
                decision="approved" if approved else "rejected",
                decided_at=stamp,
                reason_code=None if approved else (reason or "other"),
                decided_by=decided_by[:120],
                code_attempts=verification_request_table.c.code_attempts + 1,
            )
        )
        if int(claimed.rowcount or 0) != 1:
            raise VerificationError("заявка уже обработана")
        connection.execute(
            update(app_user_table)
            .where(app_user_table.c.id == request.user_id)
            .values(
                status=status,
                verify_decided_at=stamp,
                verify_reason_code=None if approved else (reason or "other"),
                updated_at=stamp,
            )
        )
    log_event(
        store,
        "verification_approved" if approved else "verification_rejected",
        user_id=request.user_id,
        detail=decided_by[:40],
        now=moment,
    )
    return request.user_id, status


def pending_requests(store: Store, *, now: datetime | None = None) -> int:
    moment = now or utc_now()
    with read_tx(store) as connection:
        rows = connection.execute(
            select(verification_request_table.c.expires_at).where(
                verification_request_table.c.decision.is_(None)
            )
        ).all()
    return sum(1 for row in rows if from_iso(row[0]) > moment)


def expire_requests(store: Store, *, now: datetime | None = None) -> int:
    """Mark expired requests as rejected and return the count."""
    moment = now or utc_now()
    stamp = to_iso(moment)
    with read_tx(store) as connection:
        rows = connection.execute(
            select(
                verification_request_table.c.id,
                verification_request_table.c.user_id,
                verification_request_table.c.expires_at,
            ).where(verification_request_table.c.decision.is_(None))
        ).all()
    expired = [
        (int(row[0]), int(row[1])) for row in rows if from_iso(row[2]) <= moment
    ]
    for request_id, user_id in expired:
        with write_tx(store) as connection:
            connection.execute(
                update(verification_request_table)
                .where(
                    verification_request_table.c.id == request_id,
                    verification_request_table.c.decision.is_(None),
                )
                .values(decision="rejected", decided_at=stamp, reason_code="expired")
            )
            connection.execute(
                update(app_user_table)
                .where(app_user_table.c.id == user_id, app_user_table.c.status == "proof_submitted")
                .values(status="rejected", verify_reason_code="expired", updated_at=stamp)
            )
    return len(expired)
