"""Public pages, i18n and the account/operations surface (M8 + M9)."""

from __future__ import annotations

import json
import sqlite3
import re
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from fairvote import ops
from fairvote.ballots import queue as ballot_queue
from fairvote.ballots import service as ballot_service
from fairvote.config import Settings
from fairvote.db import read_tx, write_tx
from fairvote.i18n import STRINGS, keys, t
from fairvote.polls import service as polls_service
from fairvote.registry import service as registry_service
from fairvote.registry.identity import Identity
from fairvote.registry.models import app_user_table, participation_table, session_table
from fairvote.security import crypto
from fairvote.timeutil import to_iso, utc_now
from support import add_user, make_ballot, open_poll

PASSWORD = "korrektnyj-parol-2026"
CSRF_META = re.compile(r'<meta name="csrf-token" content="([^"]+)"')


# --- i18n -----------------------------------------------------------------------


def test_catalogue_has_no_empty_values() -> None:
    for locale, catalogue in STRINGS.items():
        assert catalogue, locale
        for key, value in catalogue.items():
            assert value.strip(), f"{locale}:{key} is empty"


def test_translation_requires_a_known_key() -> None:
    with pytest.raises(KeyError):
        t("no.such.key")


def test_templates_only_use_catalogue_keys() -> None:
    """Every ``t("...")`` in a template must exist in the catalogue."""
    pattern = re.compile(r't\("([^"]+)"')
    used: set[str] = set()
    for path in Path("fairvote/web/templates").rglob("*.html"):
        used.update(pattern.findall(path.read_text(encoding="utf-8")))
    assert used <= keys(), f"missing keys: {sorted(used - keys())}"


# --- public pages ---------------------------------------------------------------


def test_how_it_works_states_the_limits(client) -> None:
    page = client.get("/how-it-works")
    assert page.status_code == 200
    body = page.get_data(as_text=True)
    assert "Чему нельзя доверять" in body
    assert "подменить JavaScript" in body
    assert "переголосования нет" in body.lower()


def test_privacy_page_names_the_operator(client) -> None:
    body = client.get("/privacy").get_data(as_text=True)
    assert "особая категория" in body
    assert "удалить аккаунт" in body.lower()


def test_terms_page(client) -> None:
    body = client.get("/terms").get_data(as_text=True)
    assert "не имеет" in body and "юридической силы" in body


def test_pages_are_linked_from_the_footer(client) -> None:
    body = client.get("/").get_data(as_text=True)
    assert "/how-it-works" in body and "/privacy" in body and "/terms" in body


def test_production_requires_operator_details(tmp_path: Path) -> None:
    with pytest.raises(Exception, match="FV_OPERATOR"):
        Settings(
            instance_dir=tmp_path,
            demo_mode=False,
            ephemeral_keys=False,
            secret_key=b"s" * 32,
            master_key=b"m" * 32,
            voter_pepper=b"p" * 32,
            audit_sign_key=b"a" * 32,
        )


# --- account --------------------------------------------------------------------


def _register(registry, login: str = "voter") -> int:
    return registry_service.create_user(
        registry,
        pepper=bytes(range(32)),
        login=login,
        password=PASSWORD,
        district_code="RU-MOW-77-012",
        identity=Identity(fio=f"Тестов Тест {login}", dob="1990-01-01",
                          doc_type="passport_rf", doc_series="4510",
                          doc_number=f"{abs(hash(login)) % 100000:05d}"),
        verify_method="demo",
    )


def _login(client, registry, login: str = "voter") -> None:
    _register(registry, login) if registry_service.find_by_login(registry, login) is None else None
    token = CSRF_META.search(client.get("/auth/login").get_data(as_text=True)).group(1)
    response = client.post(
        "/auth/login", data={"login": login, "password": PASSWORD, "csrf_token": token}
    )
    assert response.status_code == 302


def test_account_requires_login(client) -> None:
    response = client.get("/account/")
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_account_lists_participation(client, stores) -> None:
    registry = stores["registry"]
    registry_service.seed_districts(registry)
    _login(client, registry)
    body = client.get("/account/").get_data(as_text=True)
    assert "Участие" in body
    assert "Удаление аккаунта" in body


def test_account_deletion_is_blocked_after_voting(client, stores) -> None:
    env = open_poll(stores)
    registry = env["registry"]
    _login(client, registry, "blocked")
    user = registry_service.find_by_login(registry, "blocked")
    with write_tx(registry) as connection:
        connection.execute(
            participation_table.insert().values(
                poll_id=env["poll"].id,
                user_id=user.id,
                voted_on=to_iso(utc_now())[:10],
            )
        )
    body = client.get("/account/").get_data(as_text=True)
    assert "Удаление пока невозможно" in body
    assert "идёт опрос" in body


def test_delete_account_removes_the_user(client, stores) -> None:
    registry = stores["registry"]
    registry_service.seed_districts(registry)
    _login(client, registry, "deletable")
    token = CSRF_META.search(client.get("/account/").get_data(as_text=True)).group(1)
    response = client.post(
        "/account/delete", data={"password": PASSWORD, "csrf_token": token},
        follow_redirects=True,
    )
    assert "Аккаунт удалён" in response.get_data(as_text=True)
    assert registry_service.find_by_login(registry, "deletable") is None


def test_delete_account_requires_the_password(client, stores) -> None:
    registry = stores["registry"]
    registry_service.seed_districts(registry)
    _login(client, registry, "careful")
    token = CSRF_META.search(client.get("/account/").get_data(as_text=True)).group(1)
    response = client.post(
        "/account/delete", data={"password": "wrong-password-123", "csrf_token": token},
        follow_redirects=True,
    )
    assert "Пароль не подошёл" in response.get_data(as_text=True)
    assert registry_service.find_by_login(registry, "careful") is not None


# --- operations -----------------------------------------------------------------


def _settings(tmp_path: Path, **overrides) -> Settings:
    values = dict(
        instance_dir=tmp_path / "instance",
        demo_mode=True,
        ephemeral_keys=True,
        secret_key=b"s" * 32,
        master_key=b"m" * 32,
        voter_pepper=b"p" * 32,
        audit_sign_key=b"a" * 32,
        batch_min=2,
        batch_max_delay_minutes=0,
        retention_days=30,
    )
    values.update(overrides)
    return Settings(**values)


def test_daily_opens_and_closes_polls(stores, tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    polls = stores["polls"]
    audit = stores["audit_log"]
    registry = stores["registry"]
    registry_service.seed_districts(registry)

    # A poll that should have started yesterday and ends tomorrow.
    start = to_iso(utc_now() - timedelta(days=1))
    end = to_iso(utc_now() + timedelta(days=1))
    poll_id = polls_service.create_poll(
        polls, audit, title="Плановый опрос", summary="д", description_md="x",
        system="list", starts_at=start, ends_at=end, k_threshold=1,
    )
    polls_service.set_public_key(polls, audit, poll_id, crypto.x25519_keypair()[1])
    polls_service.add_district(polls, poll_id, district_code="RU-MOW-77-012", display_name="012")

    report = ops.run_daily(settings, stores)
    assert poll_id in report.started
    assert polls_service.get_poll(polls, poll_id).status == "open"

    # Now pretend time moved past the end: the same call closes it.
    later = utc_now() + timedelta(days=2)
    report2 = ops.run_daily(settings, stores, now=later)
    assert poll_id in report2.closed
    assert polls_service.get_poll(polls, poll_id).status == "closed"


def test_daily_exports_artefacts(stores, tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    env = open_poll(stores)
    user_id = add_user(env["registry"], "v1")
    ballot = make_ballot(env, user_id=user_id, choices={})
    ballot_service.accept_ballot(
        env["box"], env["registry"],
        **{key: ballot[key] for key in
           ("poll", "user_id", "district_code", "ballot_id", "nonce", "ciphertext")},
    )
    later = utc_now() + timedelta(days=400)
    report = ops.run_daily(settings, stores, now=later)
    assert report.exported
    exports = list((Path(settings.instance_dir) / "exports").rglob("audit.jsonl"))
    assert exports, "audit export must be written"


def test_daily_backup_is_encrypted_and_restorable(stores, tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    key = crypto.random_bytes(32)
    report = ops.run_daily(settings, stores, backup_key=key)
    assert report.backup is not None
    path = Path(settings.instance_dir) / "backups" / report.backup
    assert path.read_bytes()[:3] == crypto.AEAD_VERSION
    stamp = report.backup.removesuffix(".enc").removeprefix("registry-")
    data = ops.read_backup(path, key, stamp)
    assert data.startswith(b"SQLite format 3\x00")
    with pytest.raises(crypto.CryptoError):
        ops.read_backup(path, crypto.random_bytes(32), stamp)


def test_daily_without_backup_key_skips_it(stores, tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    report = ops.run_daily(settings, stores)
    assert report.backup is None
    assert any("FV_BACKUP_KEY" in item for item in report.skipped)


def test_retention_purges_old_voter_keys(stores, tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    env = open_poll(stores)
    user_id = add_user(env["registry"], "v1")
    ballot = make_ballot(env, user_id=user_id, choices={})
    ballot_service.accept_ballot(
        env["box"], env["registry"],
        **{key: ballot[key] for key in
           ("poll", "user_id", "district_code", "ballot_id", "nonce", "ciphertext")},
    )
    later = utc_now() + timedelta(days=400)
    from fairvote.polls import lifecycle

    ballot_queue.commit_batch(env["box"], env["audit"], env["poll"].id, force=True, now=later)
    lifecycle.close_poll(env["polls"], env["audit"], env["poll"].id, box=env["box"], now=later)
    lifecycle.publish_private_key(
        env["polls"], env["audit"], env["box"], env["poll"].id, env["private_key"], now=later
    )
    # Before the retention window there is nothing to purge.
    assert ops.purge_retention(env["registry"], env["polls"], settings, env["audit"], now=later) == 0
    much_later = later + timedelta(days=settings.retention_days + 1)
    assert ops.purge_retention(
        env["registry"], env["polls"], settings, env["audit"], now=much_later
    ) == 1
    with read_tx(env["registry"]) as connection:
        key_value = connection.execute(
            select(app_user_table.c.voter_key).where(app_user_table.c.id == user_id)
        ).scalar_one()
    assert key_value is None
    entries = [item for item in __import__("fairvote.audit.chain", fromlist=["chain"]).iter_entries(
        env["audit"]) if item.kind == "registry.purge"]
    assert entries and entries[-1].payload["voter_keys_deleted"] == 1


def test_housekeeping_drops_expired_rows(stores, tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    registry = stores["registry"]
    with write_tx(registry) as connection:
        connection.execute(
            session_table.insert().values(
                id=b"x" * 32, user_id=None, pending_user_id=None, auth_level="anon",
                data=b"{}", csrf_token=b"t", created_at="2020-01-01T00:00:00Z",
                last_seen_at="2020-01-01T00:00:00Z", expires_at="2020-01-01T00:00:00Z",
            )
        )
    sessions, _counters, _codes, _dropped = ops.housekeeping(registry, stores["ballot_box"])
    assert sessions == 1
