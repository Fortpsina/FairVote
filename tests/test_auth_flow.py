"""Registration and login end to end."""

from __future__ import annotations

import re

import pytest
from sqlalchemy import select

from fairvote.db import read_tx
from fairvote.registry import service
from fairvote.registry.models import app_user_table, session_table

BASE = {
    "login": "ivanov",
    "password": "korrektnyj-parol-2026",
    "fio": "Иванов Иван Иванович",
    "dob": "1980-05-17",
    "doc_type": "passport_rf",
    "doc_series": "4510",
    "doc_number": "123456",
    "district_code": "RU-MOW-77-012",
    "consent": "y",
}


def _post_register(client, csrf, **overrides):
    data = {**BASE, **overrides}
    token = csrf(client, "/auth/register")
    data["csrf_token"] = token
    return client.post("/auth/register", data=data)


def _register_confirmed(client, csrf, **overrides):
    first = _post_register(client, csrf, **overrides)
    assert first.status_code == 200
    second = _post_register(client, csrf, confirm="1", **overrides)
    return first, second


def test_register_page_renders(client, districts) -> None:
    page = client.get("/auth/register")
    assert page.status_code == 200
    body = page.get_data(as_text=True)
    assert "Регистрация" in body
    assert "Одномандатный округ 012" in body


def test_register_first_step_shows_preview_and_creates_nothing(
    client, districts, stores, csrf
) -> None:
    response = _post_register(client, csrf)
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "иванов иван иванович" in body
    assert "Создать аккаунт" in body
    assert service.count_users(stores["registry"]) == 0


def test_register_confirmed_creates_a_verified_user(
    client, districts, stores, csrf
) -> None:
    _, second = _register_confirmed(client, csrf)
    assert second.status_code == 200
    assert "Заявка принята" in second.get_data(as_text=True)
    assert service.count_users(stores["registry"], status="verified") == 1


def test_register_does_not_store_raw_identity(client, districts, stores, csrf) -> None:
    _register_confirmed(client, csrf)
    with read_tx(stores["registry"]) as connection:
        row = connection.execute(app_user_table.select()).mappings().one()
    # Scan the human-readable columns only: the Argon2 hash and the random
    # voter_key are bytes and could contain digit sequences by chance.
    text_values = [
        value
        for key, value in row.items()
        if isinstance(value, str) and key != "password_hash"
    ]
    blob = " | ".join(text_values).casefold()
    for fragment in ("иванов", "1980", "4510", "123456", "@"):
        assert fragment not in blob


def test_duplicate_registration_looks_like_success(
    client, districts, stores, csrf
) -> None:
    _, first = _register_confirmed(client, csrf)
    _, second = _register_confirmed(client, csrf, login="ivanov2")
    assert second.status_code == 200
    assert "Заявка принята" in first.get_data(as_text=True)
    assert _shape(second) == _shape(first)
    assert service.count_users(stores["registry"]) == 1


def test_weak_password_is_reported(client, districts, stores, csrf) -> None:
    response = _post_register(client, csrf, password="short")
    assert response.status_code == 400
    assert "12" in response.get_data(as_text=True)
    assert service.count_users(stores["registry"]) == 0


def test_bad_date_is_reported_on_preview(client, districts, csrf) -> None:
    response = _post_register(client, csrf, dob="17.05.1980")
    assert response.status_code == 400
    assert "ГГГГ-ММ-ДД" in response.get_data(as_text=True)


def test_consent_is_required(client, districts, csrf) -> None:
    token = csrf(client, "/auth/register")
    data = {**BASE, "csrf_token": token}
    data.pop("consent")
    response = client.post("/auth/register", data=data)
    assert response.status_code == 400


def test_login_success(client, districts, csrf) -> None:
    _register_confirmed(client, csrf)
    token = csrf(client, "/auth/login")
    response = client.post(
        "/auth/login",
        data={"login": "ivanov", "password": BASE["password"], "csrf_token": token},
    )
    assert response.status_code == 302
    page = client.get("/").get_data(as_text=True)
    assert "ivanov" in page


def _shape(response) -> str:
    """Drop per-response secrets (CSRF token, echoed form values) before comparing."""
    html = re.sub(r'value="[^"]*"', 'value=""', response.get_data(as_text=True))
    return re.sub(r'content="[^"]*"', 'content=""', html)


def test_login_failure_is_generic(client, districts, csrf) -> None:
    _register_confirmed(client, csrf)
    token = csrf(client, "/auth/login")
    wrong_password = client.post(
        "/auth/login",
        data={"login": "ivanov", "password": "wrong-password-123", "csrf_token": token},
    )
    unknown_login = client.post(
        "/auth/login",
        data={"login": "nobody", "password": "wrong-password-123", "csrf_token": token},
    )
    assert wrong_password.status_code == unknown_login.status_code == 401
    # Byte equality modulo form values (CSRF token and the echoed login): the page
    # must not differ in any way that reveals whether the account exists.
    assert _shape(wrong_password) == _shape(unknown_login)
    assert "Неверный логин или пароль" in wrong_password.get_data(as_text=True)


def test_login_lockout_after_five_failures(client, districts, stores, csrf) -> None:
    _register_confirmed(client, csrf)
    for _ in range(5):
        token = csrf(client, "/auth/login")
        client.post(
            "/auth/login",
            data={"login": "ivanov", "password": "wrong-password-123", "csrf_token": token},
        )
    user = service.find_by_login(stores["registry"], "ivanov")
    assert user is not None and service.is_locked(user)
    token = csrf(client, "/auth/login")
    response = client.post(
        "/auth/login",
        data={"login": "ivanov", "password": BASE["password"], "csrf_token": token},
    )
    assert response.status_code == 401


def test_login_is_rate_limited(client, districts, csrf) -> None:
    _register_confirmed(client, csrf)
    statuses = []
    for _ in range(12):
        token = csrf(client, "/auth/login")
        statuses.append(
            client.post(
                "/auth/login",
                data={"login": "ivanov", "password": "wrong-password-123", "csrf_token": token},
            ).status_code
        )
    assert 429 in statuses


def test_open_redirect_is_refused(client, districts, csrf) -> None:
    _register_confirmed(client, csrf)
    token = csrf(client, "/auth/login")
    response = client.post(
        "/auth/login?next=https://evil.example/",
        data={"login": "ivanov", "password": BASE["password"], "csrf_token": token},
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")


def test_logout_requires_post_and_token(client, districts, csrf) -> None:
    assert client.get("/auth/logout").status_code == 405
    assert client.post("/auth/logout").status_code == 400


def test_login_updates_last_login_and_clears_failures(
    client, districts, stores, csrf
) -> None:
    _register_confirmed(client, csrf)
    token = csrf(client, "/auth/login")
    client.post(
        "/auth/login",
        data={"login": "ivanov", "password": "wrong-password-123", "csrf_token": token},
    )
    assert service.find_by_login(stores["registry"], "ivanov").failed_login_count == 1
    token = csrf(client, "/auth/login")
    client.post(
        "/auth/login",
        data={"login": "ivanov", "password": BASE["password"], "csrf_token": token},
    )
    user = service.find_by_login(stores["registry"], "ivanov")
    assert user.failed_login_count == 0
    with read_tx(stores["registry"]) as connection:
        assert connection.execute(select(session_table.c.id)).first() is not None

def test_csrf_token_rotates_on_login(client, districts, csrf) -> None:
    _register_confirmed(client, csrf)
    before = csrf(client, "/auth/login")
    token = csrf(client, "/auth/login")
    client.post(
        "/auth/login",
        data={"login": "ivanov", "password": BASE["password"], "csrf_token": token},
    )
    after = csrf(client, "/")
    assert before != after
