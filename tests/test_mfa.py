"""TOTP: primitives, enrolment, login, replay protection, recovery codes."""

from __future__ import annotations

import re
import time

import pytest
from sqlalchemy import select, update

from fairvote.db import read_tx, write_tx
from fairvote.registry import mfa, service
from fairvote.registry.identity import Identity
from fairvote.registry.models import app_user_table, recovery_code_table
from fairvote.security import crypto, totp
from fairvote.timeutil import from_iso, to_iso, utc_now

PASSWORD = "korrektnyj-parol-2026"
SECRET_PATTERN = re.compile(r'<p class="preview"><code>([A-Z2-7]+)</code></p>')
CODE_PATTERN = re.compile(r"<code>([A-Z0-9]{5}-[A-Z0-9]{5})</code>")
CSRF_PATTERN = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')


# --- primitives -----------------------------------------------------------------


def test_code_round_trip() -> None:
    secret = totp.new_secret()
    step = totp.current_step()
    assert totp.verify_code(secret, totp.code_for_step(secret, step))[0]
    assert totp.verify_code(secret, totp.code_for_step(secret, step))[1] == step


def test_previous_step_is_accepted_for_clock_drift() -> None:
    secret = totp.new_secret()
    step = totp.current_step()
    assert totp.verify_code(secret, totp.code_for_step(secret, step - 1))[0]


def test_used_step_cannot_be_replayed() -> None:
    secret = totp.new_secret()
    step = totp.current_step()
    code = totp.code_for_step(secret, step)
    accepted, used_step = totp.verify_code(secret, code, last_step=step - 1)
    assert accepted and used_step == step
    assert not totp.verify_code(secret, code, last_step=step)[0]


def test_malformed_codes_are_rejected() -> None:
    secret = totp.new_secret()
    for bad in (None, "", "12345", "1234567", "abcdef", "12 34 56"):
        assert not totp.verify_code(secret, bad)[0]


def test_wrong_code_is_rejected() -> None:
    secret = totp.new_secret()
    step = totp.current_step()
    wrong = "000000" if totp.code_for_step(secret, step) != "000000" else "111111"
    assert not totp.verify_code(secret, wrong)[0]


def test_provisioning_uri() -> None:
    uri = totp.provisioning_uri("JBSWY3DPEHPK3PXP", "ivanov")
    assert uri.startswith("otpauth://totp/")
    assert "FairVote" in uri
    assert "ivanov" in uri


def test_recovery_codes_are_formatted_and_unique() -> None:
    codes = mfa.generate_recovery_codes()
    assert len(codes) == mfa.RECOVERY_CODE_COUNT
    assert len(set(codes)) == len(codes)
    for code in codes:
        assert len(code) == 11 and code[5] == "-"


def test_recovery_code_normalisation() -> None:
    assert mfa.normalize_recovery_code("abcde-fghjk") == "ABCDE-FGHJK"
    assert mfa.normalize_recovery_code("ABCDE FGHJK") == "ABCDE-FGHJK"
    assert mfa.normalize_recovery_code("ABC") == ""


# --- helpers --------------------------------------------------------------------


def fresh_code(secret: str) -> str:
    """Avoid computing a code right before the 30-second boundary."""
    remainder = time.time() % totp.STEP_SECONDS
    if remainder > totp.STEP_SECONDS - 3:
        time.sleep(totp.STEP_SECONDS - remainder + 1)
    return totp.code_for_step(secret, totp.current_step())


def rewind_last_step(stores, login: str) -> None:
    """Pretend the last TOTP use happened a few steps ago (test-only)."""
    with write_tx(stores["registry"]) as connection:
        connection.execute(
            update(app_user_table)
            .where(app_user_table.c.login == login)
            .values(totp_last_step=totp.current_step() - 5)
        )


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
    def _login():
        token = csrf(client, "/auth/login")
        return client.post(
            "/auth/login",
            data={"login": "ivanov", "password": PASSWORD, "csrf_token": token},
        )

    return _login


@pytest.fixture()
def logged_in(client, csrf, account, login) -> None:
    response = login()
    assert response.status_code == 302


def open_setup(client) -> tuple[str, str]:
    """Fetch the setup page once; return (html, csrf token from that same page).

    Re-fetching the page would mint a new secret, so the token must come from the
    page that displayed the secret the code is computed for.
    """
    page = client.get("/auth/totp/setup").get_data(as_text=True)
    return page, CSRF_PATTERN.search(page).group(1)


def enrol_totp(client, csrf) -> tuple[str, list[str]]:
    page, token = open_setup(client)
    match = SECRET_PATTERN.search(page)
    assert match, "setup page must show the secret"
    secret = match.group(1)
    response = client.post(
        "/auth/totp/setup",
        data={"code": fresh_code(secret), "csrf_token": token},
    )
    assert response.status_code == 200, response.get_data(as_text=True)[:400]
    codes = CODE_PATTERN.findall(response.get_data(as_text=True))
    return secret, codes


# --- enrolment ------------------------------------------------------------------


def test_setup_page_shows_secret_and_uri(client, logged_in) -> None:
    page = client.get("/auth/totp/setup").get_data(as_text=True)
    assert SECRET_PATTERN.search(page)
    assert "otpauth://totp/" in page


def test_setup_confirmation_enables_mfa(client, csrf, stores, logged_in) -> None:
    secret, codes = enrol_totp(client, csrf)
    state = mfa.get_state(stores["registry"], 1)
    assert state.enabled
    assert state.unused_recovery_codes == len(codes) == 10
    assert secret not in str(state.secret_blob)


def test_secret_is_encrypted_at_rest(client, csrf, stores, settings, logged_in) -> None:
    secret, _codes = enrol_totp(client, csrf)
    with read_tx(stores["registry"]) as connection:
        blob = connection.execute(select(app_user_table.c.totp_secret_enc)).scalar_one()
    assert secret.encode() not in blob
    key = crypto.derive_key(settings.master_key, "fairvote/totp/v1")
    assert mfa.decrypt_secret(key, blob, 1) == secret


def test_recovery_codes_are_stored_hashed(client, csrf, stores, logged_in) -> None:
    _secret, codes = enrol_totp(client, csrf)
    with read_tx(stores["registry"]) as connection:
        hashes = [row[0] for row in connection.execute(select(recovery_code_table.c.code_hash))]
    assert len(hashes) == 10
    for code in codes:
        assert code not in hashes
        assert any(h.startswith("$argon2id$") for h in hashes)


def test_setup_rejects_wrong_code(client, csrf, stores, logged_in) -> None:
    _page, token = open_setup(client)
    response = client.post(
        "/auth/totp/setup", data={"code": "000000", "csrf_token": token}
    )
    assert response.status_code == 400
    assert not mfa.get_state(stores["registry"], 1).enabled


# --- login ----------------------------------------------------------------------


def test_login_requires_second_factor(client, csrf, stores, login, logged_in) -> None:
    enrol_totp(client, csrf)
    token = csrf(client, "/")
    client.post("/auth/logout", data={"csrf_token": token})

    response = login()
    assert response.status_code == 302
    assert "/auth/totp" in response.headers["Location"]
    page = client.get("/").get_data(as_text=True)
    assert "ivanov" not in page  # not authenticated yet


def test_totp_login_succeeds(client, csrf, stores, login, logged_in) -> None:
    secret, _codes = enrol_totp(client, csrf)
    token = csrf(client, "/")
    client.post("/auth/logout", data={"csrf_token": token})
    login()
    rewind_last_step(stores, "ivanov")

    token = csrf(client, "/auth/totp")
    response = client.post(
        "/auth/totp", data={"code": fresh_code(secret), "csrf_token": token}
    )
    assert response.status_code == 302
    assert "ivanov" in client.get("/").get_data(as_text=True)


def test_used_totp_code_cannot_be_replayed(client, csrf, stores, login, logged_in) -> None:
    secret, _codes = enrol_totp(client, csrf)
    token = csrf(client, "/")
    client.post("/auth/logout", data={"csrf_token": token})
    login()
    rewind_last_step(stores, "ivanov")
    code = fresh_code(secret)
    token = csrf(client, "/auth/totp")
    assert client.post("/auth/totp", data={"code": code, "csrf_token": token}).status_code == 302

    token = csrf(client, "/")
    client.post("/auth/logout", data={"csrf_token": token})
    login()
    token = csrf(client, "/auth/totp")
    replay = client.post("/auth/totp", data={"code": code, "csrf_token": token})
    assert replay.status_code == 401


def test_too_many_failures_drop_the_pending_session(
    client, csrf, stores, login, logged_in
) -> None:
    enrol_totp(client, csrf)
    token = csrf(client, "/")
    client.post("/auth/logout", data={"csrf_token": token})
    login()
    rewind_last_step(stores, "ivanov")

    for _ in range(mfa.TOTP_FAIL_LIMIT):
        token = csrf(client, "/auth/totp")
        client.post("/auth/totp", data={"code": "000000", "csrf_token": token})

    # Pending session is gone: the TOTP page redirects to the login page.
    response = client.get("/auth/totp")
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


# --- recovery codes -------------------------------------------------------------


def test_recovery_code_login(client, csrf, stores, login, logged_in) -> None:
    _secret, codes = enrol_totp(client, csrf)
    token = csrf(client, "/")
    client.post("/auth/logout", data={"csrf_token": token})
    login()

    token = csrf(client, "/auth/totp")
    response = client.post(
        "/auth/totp/recovery", data={"code": codes[0], "csrf_token": token}
    )
    assert response.status_code == 302
    assert "ivanov" in client.get("/").get_data(as_text=True)
    assert mfa.get_state(stores["registry"], 1).unused_recovery_codes == 9


def test_recovery_code_is_single_use(client, csrf, stores, login, logged_in) -> None:
    _secret, codes = enrol_totp(client, csrf)
    token = csrf(client, "/")
    client.post("/auth/logout", data={"csrf_token": token})
    login()
    token = csrf(client, "/auth/totp")
    assert client.post(
        "/auth/totp/recovery", data={"code": codes[0], "csrf_token": token}
    ).status_code == 302

    token = csrf(client, "/")
    client.post("/auth/logout", data={"csrf_token": token})
    login()
    token = csrf(client, "/auth/totp")
    replay = client.post("/auth/totp/recovery", data={"code": codes[0], "csrf_token": token})
    assert replay.status_code == 401


def test_recovery_codes_can_be_regenerated(client, csrf, stores, logged_in) -> None:
    _secret, old_codes = enrol_totp(client, csrf)
    token = csrf(client, "/")
    response = client.post("/auth/recovery-codes", data={"csrf_token": token})
    assert response.status_code == 200
    new_codes = CODE_PATTERN.findall(response.get_data(as_text=True))
    assert len(new_codes) == 10
    assert set(new_codes) != set(old_codes)
    assert mfa.get_state(stores["registry"], 1).unused_recovery_codes == 10


def test_recovery_codes_require_authentication(client, csrf) -> None:
    token = csrf(client, "/auth/login")
    response = client.post("/auth/recovery-codes", data={"csrf_token": token})
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_mfa_state_reports_failures(client, csrf, stores, login, logged_in) -> None:
    enrol_totp(client, csrf)
    token = csrf(client, "/")
    client.post("/auth/logout", data={"csrf_token": token})
    login()
    rewind_last_step(stores, "ivanov")
    token = csrf(client, "/auth/totp")
    client.post("/auth/totp", data={"code": "000000", "csrf_token": token})
    state = mfa.get_state(stores["registry"], 1)
    assert state.fail_count == 1


def test_disable_totp_removes_material(client, csrf, stores, logged_in) -> None:
    enrol_totp(client, csrf)
    mfa.disable_totp(stores["registry"], 1)
    state = mfa.get_state(stores["registry"], 1)
    assert not state.enabled
    assert state.unused_recovery_codes == 0
