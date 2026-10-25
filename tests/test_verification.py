"""Manual verification by one-time code: request, decide, expire."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from fairvote.db import read_tx
from fairvote.registry import service, verification
from fairvote.registry.identity import Identity
from fairvote.registry.models import app_user_table, verification_request_table
from fairvote.timeutil import to_iso, utc_now


def _user(registry, login: str = "voter", status: str = "registered") -> service.User:
    user_id = service.create_user(
        registry,
        pepper=bytes(range(32)),
        login=login,
        password="korrektnyj-parol-2026",
        district_code="RU-MOW-77-012",
        identity=Identity(
            fio=f"Тестов Тест {login}",
            dob="1990-01-01",
            doc_type="passport_rf",
            doc_series="4510",
            doc_number=f"{abs(hash(login)) % 100000:05d}",
        ),
        verify_method=None if False else "manual",  # placeholder, overridden below
    )
    if status != "registered":
        from fairvote.db import write_tx

        with write_tx(registry) as connection:
            connection.execute(
                app_user_table.update()
                .where(app_user_table.c.id == user_id)
                .values(status=status)
            )
    found = service.find_by_id(registry, user_id)
    assert found is not None
    return found


@pytest.fixture()
def registry(stores):
    service.seed_districts(stores["registry"])
    return stores["registry"]


def test_code_format_and_normalisation() -> None:
    code = verification.generate_code()
    assert len(code) == 9 and code[4] == "-"
    assert verification.normalize_code(code.lower()) == code
    assert verification.normalize_code("123") == ""


def test_request_creates_pending_state(registry) -> None:
    user = _user(registry)
    code, request = verification.request_verification(registry, user, method="manual")
    assert len(code) == 9
    assert request.expires_at.endswith("Z")
    refreshed = service.find_by_id(registry, user.id)
    assert refreshed.status == "proof_submitted"
    with read_tx(registry) as connection:
        rows = connection.execute(verification_request_table.select()).all()
    assert len(rows) == 1
    # The code itself is never stored, only its hash.
    assert code.encode() not in rows[0].code_hash


def test_second_pending_request_is_refused(registry) -> None:
    user = _user(registry)
    verification.request_verification(registry, user)
    with pytest.raises(verification.VerificationError, match="ожидает"):
        verification.request_verification(registry, user)


def test_approve_verifies_the_account(registry) -> None:
    user = _user(registry)
    code, _request = verification.request_verification(registry, user)
    user_id, status = verification.decide(registry, code, approved=True, decided_by="manual:op")
    assert (user_id, status) == (user.id, "verified")
    refreshed = service.find_by_id(registry, user.id)
    assert refreshed.status == "verified"
    assert refreshed.verify_decided_at is not None


def test_reject_records_a_reason(registry) -> None:
    user = _user(registry)
    code, _request = verification.request_verification(registry, user)
    verification.decide(registry, code, approved=False, decided_by="manual:op",
                        reason="document_unreadable")
    refreshed = service.find_by_id(registry, user.id)
    assert refreshed.status == "rejected"
    with read_tx(registry) as connection:
        row = connection.execute(verification_request_table.select()).mappings().one()
    assert row["reason_code"] == "document_unreadable"


def test_unknown_reason_is_refused(registry) -> None:
    user = _user(registry)
    code, _request = verification.request_verification(registry, user)
    with pytest.raises(verification.VerificationError):
        verification.decide(registry, code, approved=False, decided_by="x", reason="because")


def test_wrong_code_is_not_found(registry) -> None:
    _user(registry)
    with pytest.raises(verification.CodeNotFound):
        verification.find_pending(registry, "AAAA-BBBB")


def test_code_cannot_be_used_twice(registry) -> None:
    user = _user(registry)
    code, _request = verification.request_verification(registry, user)
    verification.decide(registry, code, approved=True, decided_by="op")
    with pytest.raises(verification.CodeNotFound):
        verification.decide(registry, code, approved=True, decided_by="op")


def test_expired_code_is_refused(registry) -> None:
    user = _user(registry)
    code, request = verification.request_verification(registry, user)
    later = utc_now() + timedelta(days=verification.CODE_TTL_DAYS + 1)
    with pytest.raises(verification.CodeNotFound):
        verification.find_pending(registry, code, now=later)
    assert verification.pending_requests(registry, now=later) == 0


def test_rejected_user_can_try_again(registry) -> None:
    user = _user(registry)
    code, _request = verification.request_verification(registry, user)
    verification.decide(registry, code, approved=False, decided_by="op", reason="other")
    refreshed = service.find_by_id(registry, user.id)
    code2, _request2 = verification.request_verification(registry, refreshed)
    assert code2 != code


def test_request_limit(registry) -> None:
    user = _user(registry)
    for _ in range(verification.MAX_REQUESTS_PER_USER):
        current = service.find_by_id(registry, user.id)
        code, _request = verification.request_verification(registry, current)
        verification.decide(registry, code, approved=False, decided_by="op", reason="other")
    current = service.find_by_id(registry, user.id)
    with pytest.raises(verification.VerificationError, match="лимит"):
        verification.request_verification(registry, current)


def test_verified_user_cannot_request(registry) -> None:
    user = _user(registry)
    code, _request = verification.request_verification(registry, user)
    verification.decide(registry, code, approved=True, decided_by="op")
    verified = service.find_by_id(registry, user.id)
    with pytest.raises(verification.VerificationError):
        verification.request_verification(registry, verified)


def test_expire_requests(registry) -> None:
    user = _user(registry)
    verification.request_verification(registry, user)
    later = utc_now() + timedelta(days=verification.CODE_TTL_DAYS + 1)
    assert verification.pending_requests(registry) == 1
    assert verification.expire_requests(registry, now=later) == 1
    refreshed = service.find_by_id(registry, user.id)
    assert refreshed.status == "rejected"
    assert verification.pending_requests(registry, now=later) == 0


def test_unknown_method_is_refused(registry) -> None:
    user = _user(registry)
    with pytest.raises(verification.VerificationError):
        verification.request_verification(registry, user, method="magic")


# --- web ------------------------------------------------------------------------


def test_verification_page_requires_login(client) -> None:
    response = client.get("/verification/")
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_verification_page_shows_status(client, registry) -> None:
    service.create_user(
        registry,
        pepper=bytes(range(32)),
        login="applicant",
        password="korrektnyj-parol-2026",
        district_code="RU-MOW-77-012",
        identity=Identity(fio="Заявитель Тест", dob="1990-01-01", doc_type="passport_rf",
                          doc_series="4510", doc_number="777777"),
        verify_method="manual",
    )
    page = client.get("/auth/login").get_data(as_text=True)
    import re

    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page).group(1)
    client.post("/auth/login", data={"login": "applicant",
                                     "password": "korrektnyj-parol-2026",
                                     "csrf_token": token})
    body = client.get("/verification/").get_data(as_text=True)
    assert "не подтверждён" in body
    assert "Отправить заявку" in body
