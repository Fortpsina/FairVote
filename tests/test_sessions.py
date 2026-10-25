"""Server-side sessions: storage, rotation, expiry, revocation."""

from __future__ import annotations

import base64
import hashlib
from datetime import timedelta

import pytest
from sqlalchemy import select

from fairvote.db import read_tx, write_tx
from fairvote.registry import service
from fairvote.registry.identity import Identity
from fairvote.registry.models import session_table
from fairvote.security.sessions import purge_expired_sessions, revoke_all_sessions
from fairvote.timeutil import to_iso, utc_now

PASSWORD = "korrektnyj-parol-2026"


@pytest.fixture()
def account(districts, stores):
    return service.create_user(
        stores["registry"],
        pepper=bytes(range(32)),
        login="ivanov",
        password=PASSWORD,
        district_code="RU-MOW-77-012",
        identity=Identity(
            fio="Иванов Иван Иванович",
            dob="1980-05-17",
            doc_type="passport_rf",
            doc_series="4510",
            doc_number="123456",
        ),
        verify_method="demo",
    )


@pytest.fixture()
def login(client, csrf):
    def _login(login_name: str = "ivanov", password: str = PASSWORD):
        token = csrf(client, "/auth/login")
        return client.post(
            "/auth/login",
            data={"login": login_name, "password": password, "csrf_token": token},
        )

    return _login


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _sessions(store) -> list[dict]:
    with read_tx(store) as connection:
        return [dict(row) for row in connection.execute(session_table.select()).mappings()]


def test_login_creates_a_session_row(client, districts, stores, account, login) -> None:
    response = login()
    assert response.status_code == 302
    rows = _sessions(stores["registry"])
    assert len(rows) == 1
    assert rows[0]["user_id"] == account
    assert rows[0]["auth_level"] == "full"


def test_cookie_holds_only_a_token(client, districts, stores, account, login) -> None:
    login()
    cookie = client.get_cookie("__Host-fv_sid")
    assert cookie is not None
    assert cookie.http_only is True
    assert cookie.same_site == "Strict"
    value = cookie.value
    assert len(value) == 43  # 32 bytes in unpadded base64url
    row = _sessions(stores["registry"])[0]
    assert row["id"] == hashlib.sha256(_decode(value)).digest()
    assert row["id"] != value.encode()


def test_session_survives_requests(client, districts, account, login) -> None:
    login()
    page = client.get("/").get_data(as_text=True)
    assert "ivanov" in page


def test_session_token_rotates_on_login(client, districts, account, login) -> None:
    client.get("/auth/login")
    before = client.get_cookie("__Host-fv_sid")
    login()
    after = client.get_cookie("__Host-fv_sid")
    assert before is not None and after is not None
    assert before.value != after.value


def test_logout_deletes_the_row(client, districts, stores, account, login, csrf) -> None:
    login()
    token = csrf(client, "/")
    response = client.post("/auth/logout", data={"csrf_token": token})
    assert response.status_code == 302
    # The user session row is gone; a fresh anonymous row may exist for the flash
    # message and the new CSRF token, but it must not carry a user id.
    assert all(row["user_id"] is None for row in _sessions(stores["registry"]))
    assert "ivanov" not in client.get("/").get_data(as_text=True)


def test_expired_session_is_rejected_and_removed(
    client, districts, stores, account, login
) -> None:
    login()
    sid = _sessions(stores["registry"])[0]["id"]
    past = to_iso(utc_now() - timedelta(minutes=1))
    with write_tx(stores["registry"]) as connection:
        connection.execute(
            session_table.update().where(session_table.c.id == sid).values(expires_at=past)
        )
    page = client.get("/").get_data(as_text=True)
    assert "ivanov" not in page
    # The expired row is gone. A fresh anonymous row may appear because every page
    # now carries a CSRF token, but it must not be a session for this user.
    rows = _sessions(stores["registry"])
    assert sid not in {row["id"] for row in rows}
    assert all(row["user_id"] is None for row in rows)


def test_tampered_cookie_is_ignored(client, districts, stores, account, login) -> None:
    login()
    client.set_cookie("__Host-fv_sid", "A" * 43)
    page = client.get("/").get_data(as_text=True)
    assert "ivanov" not in page


def test_revoke_all_sessions(client, districts, stores, account, login) -> None:
    login()
    assert revoke_all_sessions(stores["registry"], account) == 1
    assert _sessions(stores["registry"]) == []
    assert "ivanov" not in client.get("/").get_data(as_text=True)


def test_purge_expired_sessions(client, districts, stores, account, login) -> None:
    login()
    assert purge_expired_sessions(stores["registry"]) == 0
    with write_tx(stores["registry"]) as connection:
        connection.execute(
            session_table.update().values(expires_at=to_iso(utc_now() - timedelta(hours=1)))
        )
    assert purge_expired_sessions(stores["registry"]) == 1


def test_session_rows_contain_no_plain_password(
    client, districts, stores, account, login
) -> None:
    login()
    for row in _sessions(stores["registry"]):
        blob = repr(row).casefold()
        assert PASSWORD not in blob
        assert "иванов" not in blob


def test_anonymous_session_has_no_user(client, districts, stores) -> None:
    client.get("/")
    rows = _sessions(stores["registry"])
    assert all(row["user_id"] is None for row in rows)
    assert all(row["auth_level"] == "anon" for row in rows)
