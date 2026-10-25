"""Poll lifecycle: content, schedule, key commitment, deterministic start."""

from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta

import pytest
from sqlalchemy import select

from fairvote.audit import chain
from fairvote.db import read_tx, write_tx
from fairvote.polls import service
from fairvote.polls.eligibility import aggregate_root, DistrictCommitment, district_root
from fairvote.polls.models import (
    contest_table,
    eligibility_commitment_table,
    poll_revision_table,
    poll_table,
)
from fairvote.registry import service as registry_service
from fairvote.registry.models import app_user_table, district_table
from fairvote.security import crypto
from fairvote.timeutil import from_iso, to_iso, utc_now

START = "2026-03-01T10:00:00Z"
END = "2026-03-10T10:00:00Z"


def _window(offset_days: int = 0) -> tuple[str, str]:
    base = utc_now() + timedelta(days=offset_days)
    return to_iso(base), to_iso(base + timedelta(days=2))


@pytest.fixture()
def polls(stores):
    return stores["polls"]


@pytest.fixture()
def audit(stores):
    return stores["audit_log"]


@pytest.fixture()
def registry(stores):
    registry_service.seed_districts(stores["registry"])
    return stores["registry"]


@pytest.fixture()
def create(polls, audit):
    def _create(**overrides):
        starts, ends = _window(-1)
        values = dict(
            title="Тестовый опрос",
            summary="Краткое описание опроса",
            description_md="## Заголовок\n\nТекст **описания**.",
            system="list",
            starts_at=starts,
            ends_at=ends,
            k_threshold=3,
            ballot_plaintext_bytes=1024,
        )
        values.update(overrides)
        return service.create_poll(polls, audit, **values)

    return _create


def _add_user(registry, login: str, district_code: str, *, verified_at: str) -> bytes:
    voter_key = hashlib.sha256(login.encode()).digest()
    district_id = registry_service.get_district(registry, district_code)["id"]
    stamp = to_iso(utc_now())
    with write_tx(registry) as connection:
        connection.execute(
            app_user_table.insert().values(
                login=login,
                login_display=login,
                password_hash="$argon2id$v=19$m=1,t=1,p=1$abc$def",
                district_id=district_id,
                status="verified",
                role="voter",
                verify_method="demo",
                verify_decided_at=verified_at,
                voter_key=voter_key,
                created_at=stamp,
                updated_at=stamp,
            )
        )
    return voter_key


# --- content --------------------------------------------------------------------


def test_create_poll_stores_content_and_audits(create, polls, audit) -> None:
    poll_id = create()
    poll = service.get_poll(polls, poll_id)
    assert poll.status == "scheduled"
    assert poll.revote_policy == "first_wins"
    assert poll.slug == "testovyy-opros"
    assert "<h2>Заголовок</h2>" in poll.description_html
    assert "<strong>описания</strong>" in poll.description_html

    entries = list(chain.iter_entries(audit))
    assert [entry.kind for entry in entries] == ["poll.create"]
    assert entries[0].payload["content_hash"] == service.content_hash(polls, poll_id).hex()


def test_create_poll_records_revision(create, polls) -> None:
    poll_id = create()
    with read_tx(polls) as connection:
        rows = connection.execute(
            select(poll_revision_table.c.revision).where(
                poll_revision_table.c.poll_id == poll_id
            )
        ).all()
    assert [row[0] for row in rows] == [1]


def test_slug_is_unique(create, polls) -> None:
    first = create()
    second = create()
    assert service.get_poll(polls, first).slug != service.get_poll(polls, second).slug


@pytest.mark.parametrize(
    "overrides",
    [
        {"title": "abc"},
        {"starts_at": "2026-03-10T10:00:00Z", "ends_at": "2026-03-01T10:00:00Z"},
        {"k_threshold": 0},
        {"ballot_plaintext_bytes": 100},
        {"system": "oligarchy"},
        {"starts_at": "01.03.2026"},
        {"key_publish_after": "2020-01-01T00:00:00Z"},
    ],
)
def test_create_poll_validates_input(create, overrides) -> None:
    with pytest.raises((service.PollError, ValueError)):
        create(**overrides)


def test_description_html_is_sanitized(create, polls) -> None:
    poll_id = create(description_md="<script>alert(1)</script>\n\nОбычный текст")
    poll = service.get_poll(polls, poll_id)
    assert "<script>" not in poll.description_html
    assert "Обычный текст" in poll.description_html


# --- updates --------------------------------------------------------------------


def test_update_before_start(create, polls, audit) -> None:
    poll_id = create()
    updated = service.update_poll(
        polls, audit, poll_id, title="Новое название опроса", k_threshold=5
    )
    assert updated.title == "Новое название опроса"
    assert updated.k_threshold == 5
    kinds = [entry.kind for entry in chain.iter_entries(audit)]
    assert kinds == ["poll.create", "poll.update"]
    revisions = [
        entry.payload["revision"] for entry in chain.iter_entries(audit) if entry.kind == "poll.update"
    ]
    assert revisions == [2]


def test_update_after_start_is_refused(create, polls, audit, registry) -> None:
    poll_id = create()
    service.set_public_key(polls, audit, poll_id, bytes(range(32)))
    service.add_district(polls, poll_id, district_code="RU-MOW-77-012", display_name="Округ 012")
    service.commit_start(polls, registry, audit, poll_id)
    with pytest.raises(service.PollLocked):
        service.update_poll(polls, audit, poll_id, title="Попытка правки")
    with pytest.raises(Exception):
        # The database trigger is the second line of defence.
        with write_tx(polls) as connection:
            connection.exec_driver_sql("UPDATE poll SET title='hack' WHERE id=?", (poll_id,))


def test_poll_is_never_created_open(create, polls) -> None:
    poll = service.get_poll(polls, create())
    assert poll.status != "open"
    assert poll.eligibility_root is None


# --- contests and options -------------------------------------------------------


def test_add_contest_and_options(create, polls) -> None:
    poll_id = create(system="mixed")
    contest_id = service.add_contest(
        polls, poll_id, title="Партийный список", kind="party_list", display_order=1
    )
    service.add_option(polls, contest_id, name="Партия А", kind="party", display_order=1)
    service.add_option(polls, contest_id, name="Партия Б", kind="party", display_order=2)
    contests = service.contest_options(polls, poll_id)
    assert len(contests) == 1
    assert [option["name"] for option in contests[0]["options"]] == ["Партия А", "Партия Б"]


def test_district_contest_requires_district(create, polls) -> None:
    poll_id = create()
    with pytest.raises(service.PollError):
        service.add_contest(polls, poll_id, title="Кандидат", kind="candidate", scope="district")


def test_bad_option_link_is_refused(create, polls) -> None:
    poll_id = create()
    contest_id = service.add_contest(polls, poll_id, title="Кандидаты", kind="candidate")
    with pytest.raises(service.PollError):
        service.add_option(polls, contest_id, name="Кто-то", link_url="javascript:alert(1)")


def test_contest_removed_content_is_not_editable_after_start(create, polls, audit, registry) -> None:
    poll_id = create()
    service.set_public_key(polls, audit, poll_id, bytes(range(32)))
    service.add_district(polls, poll_id, district_code="RU-MOW-77-012", display_name="Округ 012")
    service.commit_start(polls, registry, audit, poll_id)
    with pytest.raises(service.PollLocked):
        service.add_contest(polls, poll_id, title="Поздний контест", kind="candidate")


# --- key commitment -------------------------------------------------------------


def test_public_key_commitment(create, polls, audit) -> None:
    poll_id = create()
    public_key = crypto.x25519_keypair()[1]
    fingerprint = service.set_public_key(polls, audit, poll_id, public_key)
    poll = service.get_poll(polls, poll_id)
    assert poll.public_key == public_key
    assert fingerprint == crypto.blake2b_hex(public_key)
    entry = [e for e in chain.iter_entries(audit) if e.kind == "poll.key_commit"][0]
    assert entry.payload["fingerprint"] == fingerprint


def test_public_key_cannot_be_replaced(create, polls, audit) -> None:
    poll_id = create()
    service.set_public_key(polls, audit, poll_id, bytes(range(32)))
    with pytest.raises(service.PollLocked):
        service.set_public_key(polls, audit, poll_id, bytes(range(32)))


def test_public_key_size_is_checked(create, polls, audit) -> None:
    with pytest.raises(service.PollError):
        service.set_public_key(polls, audit, create(), b"short")


# --- start ----------------------------------------------------------------------


def _prepare(polls, audit, registry, poll_id: str, districts=("RU-MOW-77-012",)):
    service.set_public_key(polls, audit, poll_id, bytes(range(32)))
    for code in districts:
        service.add_district(
            polls, poll_id, district_code=code, display_name=registry_service.get_district(registry, code)["name"]
        )


def test_start_requires_public_key(create, polls, audit, registry) -> None:
    poll_id = create()
    service.add_district(polls, poll_id, district_code="RU-MOW-77-012", display_name="Округ 012")
    with pytest.raises(service.PollError, match="ключ"):
        service.commit_start(polls, registry, audit, poll_id)


def test_start_requires_districts(create, polls, audit, registry) -> None:
    poll_id = create()
    service.set_public_key(polls, audit, poll_id, bytes(range(32)))
    with pytest.raises(service.PollError, match="округа"):
        service.commit_start(polls, registry, audit, poll_id)


def test_start_before_starts_at_is_refused(create, polls, audit, registry) -> None:
    starts, ends = _window(+3)
    poll_id = create(starts_at=starts, ends_at=ends)
    _prepare(polls, audit, registry, poll_id)
    with pytest.raises(service.PollError, match="не начался"):
        service.commit_start(polls, registry, audit, poll_id)


def test_start_freezes_eligibility(create, polls, audit, registry) -> None:
    starts, ends = _window(-2)
    poll_id = create(starts_at=starts, ends_at=ends)
    _prepare(polls, audit, registry, poll_id)
    _add_user(registry, "early", "RU-MOW-77-012", verified_at=starts)
    after_start = to_iso(from_iso(starts) + timedelta(hours=1))
    _add_user(registry, "late", "RU-MOW-77-012", verified_at=after_start)

    poll = service.commit_start(polls, registry, audit, poll_id)
    assert poll.status == "open"
    assert poll.eligible_total == 1  # the "late" voter is after the start
    commitments = service.list_commitments(polls, poll_id)
    assert len(commitments) == 1
    assert commitments[0]["count"] == 1
    assert poll.eligibility_root is not None


def test_start_root_matches_recomputation(create, polls, audit, registry) -> None:
    starts, ends = _window(-2)
    poll_id = create(starts_at=starts, ends_at=ends)
    _prepare(polls, audit, registry, poll_id)
    first = _add_user(registry, "a", "RU-MOW-77-012", verified_at=starts)
    second = _add_user(registry, "b", "RU-MOW-77-012", verified_at=starts)

    poll = service.commit_start(polls, registry, audit, poll_id)
    expected = aggregate_root(
        [DistrictCommitment("RU-MOW-77-012", 2, district_root([first, second]))]
    )
    assert poll.eligibility_root == expected
    entry = [e for e in chain.iter_entries(audit) if e.kind == "poll.start"][0]
    assert entry.payload["root"] == expected.hex()


def test_start_is_idempotent(create, polls, audit, registry) -> None:
    starts, ends = _window(-2)
    poll_id = create(starts_at=starts, ends_at=ends)
    _prepare(polls, audit, registry, poll_id)
    _add_user(registry, "a", "RU-MOW-77-012", verified_at=starts)

    first = service.commit_start(polls, registry, audit, poll_id)
    second = service.commit_start(polls, registry, audit, poll_id)
    assert first.eligibility_root == second.eligibility_root
    starts_entries = [e for e in chain.iter_entries(audit) if e.kind == "poll.start"]
    assert len(starts_entries) == 1


def test_lazy_start_produces_the_same_root(create, polls, audit, registry) -> None:
    """Committing hours later must not change the commitment (cutoff at starts_at)."""
    starts, ends = _window(-2)
    poll_id = create(starts_at=starts, ends_at=ends)
    _prepare(polls, audit, registry, poll_id)
    _add_user(registry, "a", "RU-MOW-77-012", verified_at=starts)

    early_root = service.commit_start(polls, registry, audit, poll_id).eligibility_root

    poll_id2 = create(starts_at=starts, ends_at=ends)
    _prepare(polls, audit, registry, poll_id2)
    # A voter verified after the start must not change the root even if the commit
    # happens later.
    after_start = to_iso(from_iso(starts) + timedelta(hours=1))
    _add_user(registry, "b", "RU-MOW-77-012", verified_at=after_start)
    late_root = service.commit_start(polls, registry, audit, poll_id2).eligibility_root
    assert early_root == late_root


def test_two_districts_are_committed_separately(create, polls, audit, registry) -> None:
    starts, ends = _window(-2)
    poll_id = create(starts_at=starts, ends_at=ends, system="district")
    _prepare(polls, audit, registry, poll_id, districts=("RU-MOW-77-012", "RU-SPE-78-045"))
    _add_user(registry, "a", "RU-MOW-77-012", verified_at=starts)
    _add_user(registry, "b", "RU-SPE-78-045", verified_at=starts)
    _add_user(registry, "c", "RU-SPE-78-045", verified_at=starts)

    service.commit_start(polls, registry, audit, poll_id)
    commitments = service.list_commitments(polls, poll_id)
    assert [(c["code"], c["count"]) for c in commitments] == [
        ("RU-MOW-77-012", 1),
        ("RU-SPE-78-045", 2),
    ]


def test_empty_district_is_committed_with_zero(create, polls, audit, registry) -> None:
    starts, ends = _window(-2)
    poll_id = create(starts_at=starts, ends_at=ends)
    _prepare(polls, audit, registry, poll_id)
    poll = service.commit_start(polls, registry, audit, poll_id)
    assert poll.eligible_total == 0
    assert service.list_commitments(polls, poll_id)[0]["count"] == 0
