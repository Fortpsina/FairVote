"""Registry service: accounts, districts, lockout.

No Flask imports here: the service takes a :class:`~fairvote.db.Store` and plain
values, so it is testable without an application context and cannot accidentally
read the request or the session.

Registration never reveals whether an identity is already registered: both the
"login taken" and the "same person already has an account" cases raise
:class:`DuplicateAccount` with one generic message (docs/01 T19).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from ..db import Store, read_tx, write_tx
from ..security import passwords
from ..timeutil import from_iso, iso_now, to_iso, utc_now
from .identity import Identity, IdentityError, normalize_name, voter_key
from .models import app_user_table, auth_event_table, district_table

LOGIN_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
MAX_FAILED_LOGINS = 5
LOCK_STEP_MINUTES = 1
LOCK_MAX_MINUTES = 15

#: A small synthetic hierarchy for DEMO_MODE and for tests (docs/02 §2.3.1).
DEMO_DISTRICTS: tuple[tuple[str, str, str, str | None], ...] = (
    ("RU", "country", "Российская Федерация", None),
    ("RU-MOW", "region", "Москва", "RU"),
    ("RU-MOW-77-012", "district", "Одномандатный округ 012 (Москва)", "RU-MOW"),
    ("RU-MOW-77-012-0041", "precinct", "Участок 0041", "RU-MOW-77-012"),
    ("RU-SPE", "region", "Санкт-Петербург", "RU"),
    ("RU-SPE-78-045", "district", "Одномандатный округ 045 (Санкт-Петербург)", "RU-SPE"),
    ("RU-SPE-78-045-0210", "precinct", "Участок 0210", "RU-SPE-78-045"),
)


class RegistrationError(ValueError):
    """Base class for registration failures with user-safe messages."""


class DuplicateAccount(RegistrationError):
    """Either the login or the identity is already registered (indistinguishable)."""


class UnknownDistrict(RegistrationError):
    """The district code is not in the registry."""


@dataclass(frozen=True)
class User:
    id: int
    login: str
    login_display: str
    status: str
    role: str
    district_id: int
    district_code: str
    district_name: str
    verify_method: str | None
    verify_decided_at: str | None
    failed_login_count: int
    locked_until: str | None
    totp_enabled: bool
    created_at: str


def normalize_login(login: str) -> str:
    candidate = (login or "").strip().casefold()
    if not LOGIN_PATTERN.match(candidate):
        raise RegistrationError(
            "логин: 3–32 символа, латиница в нижнем регистре, цифры, точка, дефис, "
            "подчёркивание; начинается с буквы или цифры"
        )
    return candidate


def district_path(parent_path: str | None, code: str) -> str:
    return f"{parent_path}/{code}" if parent_path else code


def seed_districts(store: Store) -> int:
    """Insert the demo hierarchy if it is absent (idempotent)."""
    inserted = 0
    with write_tx(store) as connection:
        existing = {
            row[0] for row in connection.execute(select(district_table.c.code))
        }
        for code, level, name, parent_code in DEMO_DISTRICTS:
            if code in existing:
                continue
            parent_id = None
            parent_path = None
            if parent_code is not None:
                row = connection.execute(
                    select(district_table.c.id, district_table.c.path).where(
                        district_table.c.code == parent_code
                    )
                ).first()
                if row is None:
                    raise UnknownDistrict(f"parent district {parent_code} is missing")
                parent_id, parent_path = int(row[0]), row[1]
            connection.execute(
                district_table.insert().values(
                    code=code,
                    level=level,
                    parent_id=parent_id,
                    name=name,
                    path=district_path(parent_path, code),
                )
            )
            inserted += 1
    return inserted


def list_districts(store: Store, *, level: str = "district") -> list[dict]:
    with read_tx(store) as connection:
        rows = connection.execute(
            select(district_table.c.code, district_table.c.name)
            .where(district_table.c.level == level, district_table.c.is_active == 1)
            .order_by(district_table.c.name)
        ).all()
    return [{"code": row[0], "name": row[1]} for row in rows]


def get_district(store: Store, code: str) -> dict | None:
    with read_tx(store) as connection:
        row = connection.execute(
            select(district_table.c.id, district_table.c.code, district_table.c.name).where(
                district_table.c.code == code
            )
        ).first()
    if row is None:
        return None
    return {"id": int(row[0]), "code": row[1], "name": row[2]}


_USER_QUERY = (
    select(
        app_user_table.c.id,
        app_user_table.c.login,
        app_user_table.c.login_display,
        app_user_table.c.status,
        app_user_table.c.role,
        app_user_table.c.district_id,
        district_table.c.code,
        district_table.c.name,
        app_user_table.c.verify_method,
        app_user_table.c.verify_decided_at,
        app_user_table.c.failed_login_count,
        app_user_table.c.locked_until,
        app_user_table.c.totp_confirmed_at,
        app_user_table.c.created_at,
    )
    .select_from(app_user_table.join(district_table, app_user_table.c.district_id == district_table.c.id))
)


def _row_to_user(row) -> User:
    return User(
        id=int(row[0]),
        login=row[1],
        login_display=row[2],
        status=row[3],
        role=row[4],
        district_id=int(row[5]),
        district_code=row[6],
        district_name=row[7],
        verify_method=row[8],
        verify_decided_at=row[9],
        failed_login_count=int(row[10]),
        locked_until=row[11],
        totp_enabled=row[12] is not None,
        created_at=row[13],
    )


def find_by_login(store: Store, login: str) -> User | None:
    candidate = (login or "").strip().casefold()
    with read_tx(store) as connection:
        row = connection.execute(_USER_QUERY.where(app_user_table.c.login == candidate)).first()
    return _row_to_user(row) if row else None


def find_by_id(store: Store, user_id: int) -> User | None:
    with read_tx(store) as connection:
        row = connection.execute(_USER_QUERY.where(app_user_table.c.id == user_id)).first()
    return _row_to_user(row) if row else None


def get_password_hash(store: Store, user_id: int) -> str | None:
    with read_tx(store) as connection:
        row = connection.execute(
            select(app_user_table.c.password_hash).where(app_user_table.c.id == user_id)
        ).first()
    return row[0] if row else None


def create_user(
    store: Store,
    *,
    pepper: bytes,
    login: str,
    password: str,
    district_code: str,
    identity: Identity,
    verify_method: str,
    role: str = "voter",
    now: datetime | None = None,
) -> int:
    """Create an account; raises :class:`RegistrationError` subclasses on refusal."""
    if role not in {"voter", "admin"}:
        raise ValueError("role must be 'voter' or 'admin'")
    normalized_login = normalize_login(login)
    passwords.validate_password(password, login=normalized_login)

    district = get_district(store, district_code)
    if district is None:
        raise UnknownDistrict("выберите округ из списка")

    try:
        key = voter_key(pepper, identity)
    except IdentityError as exc:
        raise RegistrationError(str(exc)) from exc

    stamp = to_iso(now or utc_now())
    status = "verified" if verify_method == "demo" else "registered"
    decided = stamp if status == "verified" else None

    try:
        with write_tx(store) as connection:
            result = connection.execute(
                app_user_table.insert().values(
                    login=normalized_login,
                    login_display=login.strip(),
                    password_hash=passwords.hash_password(password),
                    district_id=district["id"],
                    status=status,
                    role=role,
                    verify_method=verify_method,
                    verify_decided_at=decided,
                    voter_key=key,
                    created_at=stamp,
                    updated_at=stamp,
                )
            )
            user_id = int(result.inserted_primary_key[0])
    except IntegrityError as exc:
        # One generic outcome for both unique constraints: the applicant must not
        # learn whether the login or the person is already registered.
        raise DuplicateAccount("регистрация не может быть завершена") from exc

    log_event(store, "register", user_id=user_id, detail=verify_method, now=now)
    return user_id


# --- lockout --------------------------------------------------------------------


def lock_deadline(failed_count: int, now: datetime | None = None) -> datetime | None:
    """Exponential delay after the fifth failure, capped at 15 minutes."""
    if failed_count < MAX_FAILED_LOGINS:
        return None
    minutes = min(LOCK_STEP_MINUTES * 2 ** (failed_count - MAX_FAILED_LOGINS), LOCK_MAX_MINUTES)
    return (now or utc_now()) + timedelta(minutes=minutes)


def note_failed_login(store: Store, user_id: int, *, now: datetime | None = None) -> datetime | None:
    """Count a failure and (possibly) set ``locked_until``; returns the deadline."""
    moment = now or utc_now()
    with write_tx(store) as connection:
        current = connection.execute(
            select(app_user_table.c.failed_login_count).where(app_user_table.c.id == user_id)
        ).scalar_one()
        count = int(current) + 1
        deadline = lock_deadline(count, moment)
        connection.execute(
            update(app_user_table)
            .where(app_user_table.c.id == user_id)
            .values(
                failed_login_count=count,
                locked_until=to_iso(deadline) if deadline else None,
                updated_at=to_iso(moment),
            )
        )
    log_event(store, "login_fail", user_id=user_id, detail="password", now=moment)
    return deadline


def set_password(store: Store, user_id: int, password: str, *, now: datetime | None = None) -> None:
    """Replace the password hash and record the event (no PII, no password)."""
    moment = now or utc_now()
    with write_tx(store) as connection:
        connection.execute(
            update(app_user_table)
            .where(app_user_table.c.id == user_id)
            .values(password_hash=passwords.hash_password(password), updated_at=to_iso(moment))
        )
    log_event(store, "password_change", user_id=user_id, detail="recovery", now=moment)


def clear_login_failures(store: Store, user_id: int, *, now: datetime | None = None) -> None:
    moment = now or utc_now()
    with write_tx(store) as connection:
        connection.execute(
            update(app_user_table)
            .where(app_user_table.c.id == user_id)
            .values(failed_login_count=0, locked_until=None, last_login_at=to_iso(moment))
        )


def is_locked(user: User, *, now: datetime | None = None) -> bool:
    if not user.locked_until:
        return False
    return from_iso(user.locked_until) > (now or utc_now())


# --- internal audit trail (no personal data) ------------------------------------


def log_event(
    store: Store,
    event: str,
    *,
    user_id: int | None = None,
    detail: str | None = None,
    now: datetime | None = None,
) -> None:
    with write_tx(store) as connection:
        connection.execute(
            auth_event_table.insert().values(
                ts=to_iso(now or utc_now()),
                user_id=user_id,
                event=event,
                detail=detail,
            )
        )


def count_users(store: Store, *, status: str | None = None) -> int:
    query = select(func.count()).select_from(app_user_table)
    if status is not None:
        query = query.where(app_user_table.c.status == status)
    with read_tx(store) as connection:
        return int(connection.execute(query).scalar_one())


def eligible_voters(
    store: Store, district_codes: list[str], *, cutoff: str
) -> dict[str, list[bytes]]:
    """Voters eligible for a poll, keyed by district code.

    ``cutoff`` is the poll start time: someone verified *after* the start is not
    eligible, which makes the snapshot deterministic even when the start is committed
    lazily (docs/02 §2.5.2). Districts without eligible voters are returned empty so
    that the commitment covers every district of the poll.
    """
    result: dict[str, list[bytes]] = {code: [] for code in district_codes}
    if not district_codes:
        return result
    with read_tx(store) as connection:
        rows = connection.execute(
            select(district_table.c.code, app_user_table.c.voter_key)
            .select_from(
                app_user_table.join(
                    district_table, app_user_table.c.district_id == district_table.c.id
                )
            )
            .where(
                app_user_table.c.status == "verified",
                app_user_table.c.voter_key.is_not(None),
                app_user_table.c.verify_decided_at.is_not(None),
                app_user_table.c.verify_decided_at <= cutoff,
                district_table.c.code.in_(district_codes),
            )
        ).all()
    for code, voter_key in rows:
        result.setdefault(code, []).append(bytes(voter_key))
    return result


def normalized_name_of(identity: Identity) -> str:
    """Convenience for templates that show the confirmed normal form."""
    return normalize_name(identity.fio)
