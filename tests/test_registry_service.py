"""Registry service: districts, registration, duplicate handling, lockout."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.exc import DatabaseError as SADatabaseError

from fairvote.db import read_tx
from fairvote.registry import service
from fairvote.registry.identity import Identity
from fairvote.registry.models import app_user_table, auth_event_table, district_table
from fairvote.security import passwords
from fairvote.timeutil import from_iso, utc_now

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


@pytest.fixture()
def registry(stores):
    service.seed_districts(stores["registry"])
    return stores["registry"]


def register(registry, *, login="ivanov", password="korrektnyj-parol-2026", **overrides):
    return service.create_user(
        registry,
        pepper=PEPPER,
        login=login,
        password=password,
        district_code=overrides.pop("district_code", "RU-MOW-77-012"),
        identity=overrides.pop("identity", identity()),
        verify_method=overrides.pop("verify_method", "demo"),
    )


def test_seed_districts_is_idempotent(registry) -> None:
    assert service.seed_districts(registry) == 0
    with read_tx(registry) as connection:
        total = len(connection.execute(district_table.select()).all())
    assert total == len(service.DEMO_DISTRICTS)


def test_list_districts_returns_only_districts(registry) -> None:
    districts = service.list_districts(registry)
    codes = {item["code"] for item in districts}
    assert codes == {"RU-MOW-77-012", "RU-SPE-78-045"}


def test_unknown_district_is_looked_up(registry) -> None:
    assert service.get_district(registry, "RU-XXX") is None
    assert service.get_district(registry, "RU-MOW-77-012")["name"].startswith("Одномандатный")


def test_register_creates_a_verified_user_in_demo_mode(registry) -> None:
    user_id = register(registry)
    user = service.find_by_id(registry, user_id)
    assert user is not None
    assert user.login == "ivanov"
    assert user.status == "verified"
    assert user.verify_method == "demo"
    assert user.district_code == "RU-MOW-77-012"
    assert user.totp_enabled is False


def test_register_keeps_pending_status_without_demo_provider(registry) -> None:
    user_id = register(registry, verify_method="manual")
    user = service.find_by_id(registry, user_id)
    assert user is not None
    assert user.status == "registered"
    assert user.verify_method == "manual"
    assert user.verify_decided_at is None


def test_register_stores_no_raw_identity(registry) -> None:
    register(registry)
    with read_tx(registry) as connection:
        row = connection.execute(app_user_table.select()).mappings().one()
    blob = repr(dict(row)).casefold()
    for fragment in ("иванов", "1980", "4510", "123456"):
        assert fragment not in blob
    assert isinstance(row["voter_key"], bytes) and len(row["voter_key"]) == 32


def test_password_is_stored_hashed(registry) -> None:
    user_id = register(registry)
    stored = service.get_password_hash(registry, user_id)
    assert stored is not None
    assert stored.startswith("$argon2id$")
    assert passwords.verify_password(stored, "korrektnyj-parol-2026")


def test_duplicate_login_is_generic(registry) -> None:
    register(registry)
    with pytest.raises(service.DuplicateAccount) as first:
        register(registry, identity=identity(doc_number="999999"))
    with pytest.raises(service.DuplicateAccount) as second:
        register(registry, login="petrov")
    assert str(first.value) == str(second.value)


def test_duplicate_identity_with_other_login_is_generic(registry) -> None:
    register(registry)
    with pytest.raises(service.DuplicateAccount, match="регистрация не может быть завершена"):
        register(registry, login="ivanov2")


def test_same_normalized_identity_from_another_spelling_is_duplicate(registry) -> None:
    register(registry)
    with pytest.raises(service.DuplicateAccount):
        register(registry, login="ivanov3", identity=identity(fio="ИВАНОВ  ИВАН ИВАНОВИЧ"))


def test_different_person_can_register(registry) -> None:
    register(registry)
    other = register(registry, login="petrov", identity=identity(fio="Петров Пётр", doc_number="654321"))
    assert service.find_by_id(registry, other) is not None
    assert service.count_users(registry) == 2


def test_unknown_district_is_refused(registry) -> None:
    with pytest.raises(service.UnknownDistrict):
        register(registry, district_code="RU-XXX")


def test_weak_password_is_refused_before_any_write(registry) -> None:
    with pytest.raises(passwords.WeakPassword):
        register(registry, password="short")
    assert service.count_users(registry) == 0


def test_login_normalisation(registry) -> None:
    assert service.normalize_login("  Ivanov ") == "ivanov"
    for bad in ("iv", "иванов", "1ivanov!", "a" * 33):
        with pytest.raises(service.RegistrationError):
            service.normalize_login(bad)


def test_registration_is_audited_without_personal_data(registry) -> None:
    register(registry)
    with read_tx(registry) as connection:
        rows = connection.execute(auth_event_table.select()).mappings().all()
    assert [row["event"] for row in rows] == ["register"]
    assert rows[0]["detail"] == "demo"


# --- lockout --------------------------------------------------------------------


def test_lock_deadline_grows_and_caps() -> None:
    now = utc_now()
    assert service.lock_deadline(4, now) is None
    assert service.lock_deadline(5, now) == now + timedelta(minutes=1)
    assert service.lock_deadline(6, now) == now + timedelta(minutes=2)
    assert service.lock_deadline(7, now) == now + timedelta(minutes=4)
    assert service.lock_deadline(8, now) == now + timedelta(minutes=8)
    assert service.lock_deadline(9, now) == now + timedelta(minutes=15)
    assert service.lock_deadline(50, now) == now + timedelta(minutes=15)


def test_failed_logins_lock_the_account(registry) -> None:
    user_id = register(registry)
    for _ in range(4):
        assert service.note_failed_login(registry, user_id) is None
    deadline = service.note_failed_login(registry, user_id)
    assert deadline is not None
    user = service.find_by_id(registry, user_id)
    assert user is not None
    assert user.failed_login_count == 5
    assert service.is_locked(user)


def test_lock_expires(registry) -> None:
    user_id = register(registry)
    for _ in range(5):
        service.note_failed_login(registry, user_id)
    user = service.find_by_id(registry, user_id)
    assert user is not None
    later = from_iso(user.locked_until) + timedelta(minutes=1)
    assert not service.is_locked(user, now=later)


def test_successful_login_clears_failures(registry) -> None:
    user_id = register(registry)
    service.note_failed_login(registry, user_id)
    service.clear_login_failures(registry, user_id)
    user = service.find_by_id(registry, user_id)
    assert user is not None
    assert user.failed_login_count == 0
    assert user.locked_until is None


def test_auth_event_detail_has_no_pii(registry) -> None:
    user_id = register(registry)
    service.note_failed_login(registry, user_id)
    with read_tx(registry) as connection:
        details = [row[0] for row in connection.execute(select(auth_event_table.c.detail))]
    assert all(value in {"demo", "password"} for value in details)
