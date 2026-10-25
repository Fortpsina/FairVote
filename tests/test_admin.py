"""Admin interface: boundaries, CRUD before the start, lifecycle actions."""

from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path

import pytest

from sqlalchemy import select

from fairvote.db import read_tx
from fairvote.polls import service as polls_service
from fairvote.polls.models import poll_table
from fairvote.registry import mfa, service
from fairvote.registry.identity import Identity
from fairvote.security import crypto, totp
from fairvote.timeutil import to_iso, utc_now

PASSWORD = "korrektnyj-parol-2026"
CSRF_META = re.compile(r'<meta name="csrf-token" content="([^"]+)">')
TOTP_SECRET = totp.new_secret()


def _csrf(client, path: str) -> str:
    page = client.get(path).get_data(as_text=True)
    match = CSRF_META.search(page)
    assert match, f"no CSRF token on {path}"
    return match.group(1)


def _create_admin(registry, settings, *, login: str = "admin", with_totp: bool = True) -> int:
    user_id = service.create_user(
        registry,
        pepper=bytes(range(32)),
        login=login,
        password=PASSWORD,
        district_code="RU-MOW-77-012",
        identity=Identity(
            fio=f"Админ Админов {login}",
            dob="1980-01-01",
            doc_type="passport_rf",
            doc_series="4510",
            doc_number=f"{abs(hash(login)) % 100000:05d}",
        ),
        verify_method="demo",
        role="admin",
    )
    if with_totp:
        key = crypto.derive_key(settings.master_key, "fairvote/totp/v1")
        blob = mfa.encrypt_secret(key, TOTP_SECRET, user_id)
        mfa.store_secret(registry, user_id, blob)
        # Enrolment happened a few steps ago, so a current code is not a replay.
        mfa.confirm_secret(registry, user_id, totp.current_step() - 5)
    return user_id


def _login_admin(client, *, with_totp: bool = True) -> None:
    token = _csrf(client, "/auth/login")
    client.post("/auth/login", data={"login": "admin", "password": PASSWORD, "csrf_token": token})
    if with_totp:
        token = _csrf(client, "/auth/totp")
        response = client.post(
            "/auth/totp",
            data={"code": totp.code_for_step(TOTP_SECRET, totp.current_step()),
                  "csrf_token": token},
        )
        assert response.status_code == 302


@pytest.fixture()
def admin_env(stores, settings):
    service.seed_districts(stores["registry"])
    user_id = _create_admin(stores["registry"], settings)
    return {"user_id": user_id, "settings": settings, "stores": stores}


def _create_poll_form(window_days: int = 3, *, start_days: int = -1) -> dict:
    start = utc_now() + timedelta(days=start_days)
    end = start + timedelta(days=window_days)
    return {
        "title": "Админский опрос",
        "summary": "Создан через админку",
        "description": "## Описание\n\nТекст **опроса**.",
        "system": "list",
        "starts_at": to_iso(start),
        "ends_at": to_iso(end),
        "k_threshold": "3",
        "ballot_plaintext_bytes": "1024",
        "key_publish_after": "",
    }


# --- access control -------------------------------------------------------------


def test_anonymous_is_redirected_to_login(client) -> None:
    response = client.get("/admin/")
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_voter_is_forbidden(client, stores) -> None:
    service.seed_districts(stores["registry"])
    service.create_user(
        stores["registry"],
        pepper=bytes(range(32)),
        login="voter",
        password=PASSWORD,
        district_code="RU-MOW-77-012",
        identity=Identity(fio="Избиратель Тест", dob="1990-01-01", doc_type="passport_rf",
                          doc_series="4510", doc_number="111111"),
        verify_method="demo",
    )
    token = _csrf(client, "/auth/login")
    client.post("/auth/login", data={"login": "voter", "password": PASSWORD, "csrf_token": token})
    assert client.get("/admin/").status_code == 403


def test_admin_without_totp_is_sent_to_enrolment(client, stores, settings) -> None:
    service.seed_districts(stores["registry"])
    _create_admin(stores["registry"], settings, login="admin2", with_totp=False)
    token = _csrf(client, "/auth/login")
    client.post("/auth/login", data={"login": "admin2", "password": PASSWORD, "csrf_token": token})
    response = client.get("/admin/")
    assert response.status_code == 302
    assert "/auth/totp/setup" in response.headers["Location"]


def test_admin_with_totp_sees_the_index(client, admin_env) -> None:
    _login_admin(client)
    page = client.get("/admin/")
    assert page.status_code == 200
    assert "Администрирование" in page.get_data(as_text=True)


# --- creating and editing -------------------------------------------------------


def test_create_poll_through_the_form(client, admin_env, stores) -> None:
    _login_admin(client)
    token = _csrf(client, "/admin/polls/new")
    response = client.post(
        "/admin/polls/new", data={**_create_poll_form(), "csrf_token": token}
    )
    assert response.status_code == 302
    with read_tx(stores["polls"]) as connection:
        row = connection.execute(poll_table.select()).mappings().one()
    assert row["title"] == "Админский опрос"
    assert row["status"] == "scheduled"


def test_invalid_poll_is_reported(client, admin_env) -> None:
    _login_admin(client)
    token = _csrf(client, "/admin/polls/new")
    response = client.post(
        "/admin/polls/new",
        data={**_create_poll_form(), "title": "abc", "csrf_token": token},
        follow_redirects=True,
    )
    assert "название" in response.get_data(as_text=True).lower()


def test_edit_changes_are_audited(client, admin_env, stores) -> None:
    _login_admin(client)
    token = _csrf(client, "/admin/polls/new")
    client.post("/admin/polls/new", data={**_create_poll_form(), "csrf_token": token})
    with read_tx(stores["polls"]) as connection:
        poll_id = connection.execute(select(poll_table.c.id)).scalar_one()

    token = _csrf(client, f"/admin/polls/{poll_id}/edit")
    client.post(
        f"/admin/polls/{poll_id}/edit",
        data={**_create_poll_form(), "title": "Обновлённый опрос", "csrf_token": token},
    )
    poll = polls_service.get_poll(stores["polls"], poll_id)
    assert poll.title == "Обновлённый опрос"
    from fairvote.audit import chain

    kinds = [entry.kind for entry in chain.iter_entries(stores["audit_log"])]
    assert kinds.count("poll.update") == 1
    assert kinds.count("poll.create") == 1


def test_admin_cannot_add_districts_without_a_poll(client, admin_env) -> None:
    _login_admin(client)
    assert client.get("/admin/polls/does-not-exist/edit").status_code == 404


# --- full preparation -----------------------------------------------------------


def test_prepare_and_start_a_poll(client, admin_env, stores) -> None:
    _login_admin(client)
    token = _csrf(client, "/admin/polls/new")
    client.post("/admin/polls/new", data={**_create_poll_form(), "csrf_token": token})
    with read_tx(stores["polls"]) as connection:
        poll_id = connection.execute(select(poll_table.c.id)).scalar_one()

    # district
    token = _csrf(client, f"/admin/polls/{poll_id}/edit")
    client.post(
        f"/admin/polls/{poll_id}/districts",
        data={"district_code": "RU-MOW-77-012", "csrf_token": token},
    )
    # contest
    client.post(
        f"/admin/polls/{poll_id}/contests",
        data={
            "title": "Партии",
            "kind": "party_list",
            "scope": "nationwide",
            "district_code": "RU-MOW-77-012",
            "allow_against_all": "y",
            "csrf_token": token,
        },
    )
    contests = polls_service.contest_options(stores["polls"], poll_id)
    assert len(contests) == 1
    # option
    client.post(
        f"/admin/contests/{contests[0]['id']}/options",
        data={"name": "Партия А", "kind": "party", "display_order": "1", "csrf_token": token},
    )
    assert len(polls_service.contest_options(stores["polls"], poll_id)[0]["options"]) == 1

    # public key commitment
    _private, public = crypto.x25519_keypair()
    client.post(
        f"/admin/polls/{poll_id}/key",
        data={"public_key": public.hex(), "csrf_token": token},
    )
    poll = polls_service.get_poll(stores["polls"], poll_id)
    assert poll.public_key == public

    # starting is a system operation, not a web action
    started = polls_service.commit_start(
        stores["polls"], stores["registry"], stores["audit_log"], poll_id
    )
    assert started.status == "open"


def test_editing_after_start_fails(client, admin_env, stores) -> None:
    _login_admin(client)
    token = _csrf(client, "/admin/polls/new")
    client.post("/admin/polls/new", data={**_create_poll_form(), "csrf_token": token})
    with read_tx(stores["polls"]) as connection:
        poll_id = connection.execute(select(poll_table.c.id)).scalar_one()
    polls_service.set_public_key(stores["polls"], stores["audit_log"], poll_id, bytes(32))
    polls_service.add_district(
        stores["polls"], poll_id, district_code="RU-MOW-77-012", display_name="Округ 012"
    )
    polls_service.commit_start(stores["polls"], stores["registry"], stores["audit_log"], poll_id)

    token = _csrf(client, f"/admin/polls/{poll_id}/edit")
    response = client.post(
        f"/admin/polls/{poll_id}/edit",
        data={**_create_poll_form(), "title": "Поздняя правка", "csrf_token": token},
        follow_redirects=True,
    )
    assert "начался" in response.get_data(as_text=True)
    assert polls_service.get_poll(stores["polls"], poll_id).title == "Админский опрос"


# --- boundaries -----------------------------------------------------------------


def test_admin_module_does_not_import_the_registry() -> None:
    """The separation is structural: no import path to the registry store."""
    lines = Path("fairvote/web/admin.py").read_text(encoding="utf-8").splitlines()
    imports = [line.strip() for line in lines if line.strip().startswith(("import ", "from "))]
    assert not [line for line in imports if "registry" in line]


def test_admin_district_picker_uses_the_public_catalogue(client, admin_env) -> None:
    _login_admin(client)
    token = _csrf(client, "/admin/polls/new")
    client.post("/admin/polls/new", data={**_create_poll_form(), "csrf_token": token})
    page = client.get("/admin/").get_data(as_text=True)
    assert "Админский опрос" in page
