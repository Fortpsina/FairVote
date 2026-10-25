"""Poll content and lifecycle: draft, schedule, key commitment, start.

Rules enforced here (and, as a second line of defence, by the database trigger
``poll_immutable_after_start``):

* content is editable only before the poll starts;
* the public key is committed before the start, and only once;
* starting is deterministic and idempotent: the eligibility snapshot is taken with
  a cutoff at ``starts_at``, so a lazy start hours later produces the same Merkle
  root as a punctual one (docs/02 §2.5.2);
* every mutation that a voter could care about is written to the audit chain.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import delete, select

from .. import assets
from ..audit import chain
from ..db import Store, read_tx, write_tx
from ..registry import service as registry_service
from ..security import crypto
from ..security.canonical import dump_bytes
from ..timeutil import from_iso, to_iso, utc_now
from . import content
from .eligibility import DistrictCommitment, aggregate_root, district_root
from .models import (
    contest_table,
    eligibility_commitment_table,
    option_table,
    poll_district_table,
    poll_revision_table,
    poll_table,
)

SYSTEMS = frozenset({"list", "district", "mixed"})
EDITABLE_STATUSES = frozenset({"draft", "scheduled"})
STARTED_STATUSES = frozenset({"open", "closed", "published"})
CONTEST_SCOPES = frozenset({"nationwide", "district"})
CONTEST_KINDS = frozenset({"party_list", "candidate", "referendum"})
OPTION_KINDS = frozenset({"candidate", "party", "against_all"})

MIN_TITLE = 5
MAX_TITLE = 200
MAX_SUMMARY = 600

_TRANSLIT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "h", "ц": "c", "ч": "ch", "ш": "sh", "щ": "sch", "ъ": "",
    "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
}


class PollError(ValueError):
    """Base class for poll lifecycle refusals."""


class PollNotFound(PollError):
    pass


class PollLocked(PollError):
    """The poll is past the point where this change is allowed."""


@dataclass(frozen=True)
class Poll:
    id: str
    slug: str
    title: str
    summary: str
    description_md: str
    description_html: str
    system: str
    status: str
    starts_at: str
    ends_at: str
    k_threshold: int
    revote_policy: str
    ballot_plaintext_bytes: int
    key_publish_after: str | None
    public_key: bytes | None
    key_fingerprint: str | None
    eligibility_root: bytes | None
    eligible_total: int | None
    started_committed_at: str | None
    closed_at: str | None
    private_key_published_at: str | None

    @property
    def editable(self) -> bool:
        return self.status in EDITABLE_STATUSES

    @property
    def results_visible_after(self) -> str:
        """Results are hidden until the key is published (docs/05 D-4)."""
        return self.key_publish_after or self.ends_at


def slugify(title: str) -> str:
    """ASCII slug; falls back to a random suffix when nothing transliterates."""
    lowered = (title or "").casefold()
    transliterated = "".join(_TRANSLIT.get(character, character) for character in lowered)
    cleaned = re.sub(r"[^a-z0-9]+", "-", transliterated).strip("-")
    cleaned = cleaned[:60].strip("-")
    return cleaned or f"poll-{secrets.token_hex(3)}"


def _unique_slug(store: Store, base: str) -> str:
    candidate = base
    suffix = 2
    with read_tx(store) as connection:
        existing = {row[0] for row in connection.execute(select(poll_table.c.slug))}
    while candidate in existing:
        candidate = f"{base}-{suffix}"
        suffix += 1
    return candidate


def _row_to_poll(row) -> Poll:
    return Poll(
        id=row[0],
        slug=row[1],
        title=row[2],
        summary=row[3],
        description_md=row[4],
        description_html=row[5],
        system=row[6],
        status=row[7],
        starts_at=row[8],
        ends_at=row[9],
        k_threshold=int(row[10]),
        revote_policy=row[11],
        ballot_plaintext_bytes=int(row[12]),
        key_publish_after=row[13],
        public_key=bytes(row[14]) if row[14] is not None else None,
        key_fingerprint=row[15],
        eligibility_root=bytes(row[16]) if row[16] is not None else None,
        eligible_total=int(row[17]) if row[17] is not None else None,
        started_committed_at=row[18],
        closed_at=row[19],
        private_key_published_at=row[20],
    )


_POLL_COLUMNS = (
    poll_table.c.id,
    poll_table.c.slug,
    poll_table.c.title,
    poll_table.c.summary,
    poll_table.c.description_md,
    poll_table.c.description_html,
    poll_table.c.system,
    poll_table.c.status,
    poll_table.c.starts_at,
    poll_table.c.ends_at,
    poll_table.c.k_threshold,
    poll_table.c.revote_policy,
    poll_table.c.ballot_plaintext_bytes,
    poll_table.c.key_publish_after,
    poll_table.c.public_key,
    poll_table.c.key_fingerprint,
    poll_table.c.eligibility_root,
    poll_table.c.eligible_total,
    poll_table.c.started_committed_at,
    poll_table.c.closed_at,
    poll_table.c.private_key_published_at,
)


def get_poll(store: Store, poll_id: str) -> Poll:
    with read_tx(store) as connection:
        row = connection.execute(
            select(*_POLL_COLUMNS).where(poll_table.c.id == poll_id)
        ).first()
    if row is None:
        raise PollNotFound(f"poll {poll_id!r} not found")
    return _row_to_poll(row)


def get_poll_by_slug(store: Store, slug: str) -> Poll:
    with read_tx(store) as connection:
        row = connection.execute(
            select(*_POLL_COLUMNS).where(poll_table.c.slug == slug)
        ).first()
    if row is None:
        raise PollNotFound(f"poll {slug!r} not found")
    return _row_to_poll(row)


def list_polls(store: Store, *, statuses: tuple[str, ...] | None = None) -> list[Poll]:
    query = select(*_POLL_COLUMNS).order_by(poll_table.c.starts_at.desc())
    if statuses:
        query = query.where(poll_table.c.status.in_(statuses))
    with read_tx(store) as connection:
        return [_row_to_poll(row) for row in connection.execute(query)]


# --- validation -----------------------------------------------------------------


def _validate_window(starts_at: str, ends_at: str, key_publish_after: str | None) -> None:
    start, end = from_iso(starts_at), from_iso(ends_at)
    if end <= start:
        raise PollError("окончание должно быть позже начала")
    if key_publish_after is not None:
        publish = from_iso(key_publish_after)
        if publish < end:
            raise PollError("публикация ключа не может быть раньше окончания опроса")


def _validate_common(
    *, title: str, summary: str, system: str, k_threshold: int, ballot_bytes: int
) -> None:
    if not (MIN_TITLE <= len(title) <= MAX_TITLE):
        raise PollError(f"название: от {MIN_TITLE} до {MAX_TITLE} символов")
    if len(summary) > MAX_SUMMARY:
        raise PollError(f"краткое описание: не больше {MAX_SUMMARY} символов")
    if system not in SYSTEMS:
        raise PollError("неизвестная система голосования")
    if k_threshold < 1:
        raise PollError("порог анонимности должен быть не меньше 1")
    if not (512 <= ballot_bytes <= 8192):
        raise PollError("размер бюллетеня: от 512 до 8192 байт")


# --- content --------------------------------------------------------------------


def content_snapshot(store: Store, poll_id: str) -> dict[str, Any]:
    """The exact content that is committed before the start (and hashed)."""
    poll = get_poll(store, poll_id)
    with read_tx(store) as connection:
        raw = connection.execute(
            select(
                poll_table.c.title,
                poll_table.c.summary,
                poll_table.c.description_md,
                poll_table.c.system,
                poll_table.c.starts_at,
                poll_table.c.ends_at,
                poll_table.c.k_threshold,
                poll_table.c.revote_policy,
                poll_table.c.ballot_plaintext_bytes,
                poll_table.c.key_publish_after,
            ).where(poll_table.c.id == poll_id)
        ).mappings().one()
        contests = connection.execute(
            select(contest_table)
            .where(contest_table.c.poll_id == poll_id)
            .order_by(contest_table.c.display_order, contest_table.c.id)
        ).mappings().all()
        contest_payload = []
        for contest in contests:
            options = connection.execute(
                select(option_table)
                .where(option_table.c.contest_id == contest["id"])
                .order_by(option_table.c.display_order, option_table.c.id)
            ).mappings().all()
            contest_payload.append(
                {
                    "id": contest["id"],
                    "scope": contest["scope"],
                    "district": contest["district_code"],
                    "kind": contest["kind"],
                    "title": contest["title"],
                    "description": contest["description_html"],
                    "allow_against_all": bool(contest["allow_against_all"]),
                    "order": int(contest["display_order"]),
                    "options": [
                        {
                            "id": option["id"],
                            "kind": option["kind"],
                            "name": option["name"],
                            "bio": option["bio_html"],
                            "link": option["link_url"],
                            "order": int(option["display_order"]),
                        }
                        for option in options
                    ],
                }
            )
        districts = [
            row[0]
            for row in connection.execute(
                select(poll_district_table.c.district_code)
                .where(poll_district_table.c.poll_id == poll_id)
                .order_by(poll_district_table.c.district_code)
            )
        ]
    return {
        "v": 1,
        "id": poll.id,
        "title": raw["title"],
        "summary": raw["summary"],
        "description_md": raw["description_md"],
        "system": raw["system"],
        "starts_at": raw["starts_at"],
        "ends_at": raw["ends_at"],
        "k_threshold": int(raw["k_threshold"]),
        "revote_policy": raw["revote_policy"],
        "ballot_plaintext_bytes": int(raw["ballot_plaintext_bytes"]),
        "key_publish_after": raw["key_publish_after"],
        "districts": districts,
        "contests": contest_payload,
    }


def content_hash(store: Store, poll_id: str) -> bytes:
    return crypto.sha256(dump_bytes(content_snapshot(store, poll_id)))


def _record_revision(store: Store, poll_id: str, *, now: str) -> int:
    snapshot = content_snapshot(store, poll_id)
    with read_tx(store) as connection:
        last = connection.execute(
            select(poll_revision_table.c.revision)
            .where(poll_revision_table.c.poll_id == poll_id)
            .order_by(poll_revision_table.c.revision.desc())
            .limit(1)
        ).scalar()
    revision = int(last or 0) + 1
    digest = crypto.sha256(dump_bytes(snapshot))
    with write_tx(store) as connection:
        connection.execute(
            poll_revision_table.insert().values(
                poll_id=poll_id,
                revision=revision,
                snapshot_json=dump_bytes(snapshot).decode("utf-8"),
                content_hash=digest,
                created_at=now,
            )
        )
    return revision


def create_poll(
    store: Store,
    audit: Store,
    *,
    title: str,
    summary: str,
    description_md: str,
    system: str,
    starts_at: str,
    ends_at: str,
    k_threshold: int = 10,
    ballot_plaintext_bytes: int = 1024,
    key_publish_after: str | None = None,
    created_by: int | None = None,
    now: datetime | None = None,
) -> str:
    title = title.strip()
    _validate_common(
        title=title,
        summary=summary.strip(),
        system=system,
        k_threshold=k_threshold,
        ballot_bytes=ballot_plaintext_bytes,
    )
    _validate_window(starts_at, ends_at, key_publish_after)
    stamp = to_iso(now or utc_now())
    poll_id = secrets.token_hex(16)
    slug = _unique_slug(store, slugify(title))
    rendered = content.render_markdown(description_md)

    with write_tx(store) as connection:
        connection.execute(
            poll_table.insert().values(
                id=poll_id,
                slug=slug,
                title=title,
                summary=summary.strip(),
                description_md=description_md,
                description_html=rendered,
                system=system,
                status="scheduled",
                starts_at=starts_at,
                ends_at=ends_at,
                k_threshold=k_threshold,
                revote_policy="first_wins",
                ballot_plaintext_bytes=ballot_plaintext_bytes,
                key_publish_after=key_publish_after,
                created_by=created_by,
                created_at=stamp,
                updated_at=stamp,
            )
        )
    revision = _record_revision(store, poll_id, now=stamp)
    chain.append(
        audit,
        kind="poll.create",
        poll_id=poll_id,
        payload={
            "title": title,
            "system": system,
            "starts_at": starts_at,
            "ends_at": ends_at,
            "k_threshold": k_threshold,
            "ballot_plaintext_bytes": ballot_plaintext_bytes,
            "key_publish_after": key_publish_after,
            "content_hash": content_hash(store, poll_id).hex(),
            "revision": revision,
        },
        ts=stamp,
    )
    return poll_id


def update_poll(
    store: Store,
    audit: Store,
    poll_id: str,
    *,
    title: str | None = None,
    summary: str | None = None,
    description_md: str | None = None,
    starts_at: str | None = None,
    ends_at: str | None = None,
    k_threshold: int | None = None,
    key_publish_after: str | None = None,
    now: datetime | None = None,
) -> Poll:
    poll = get_poll(store, poll_id)
    if not poll.editable:
        raise PollLocked("опрос уже начался: изменения запрещены")

    snapshot = content_snapshot(store, poll_id)
    new_title = (title if title is not None else snapshot["title"]).strip()
    new_summary = (summary if summary is not None else snapshot["summary"]).strip()
    new_starts = starts_at or snapshot["starts_at"]
    new_ends = ends_at or snapshot["ends_at"]
    new_k = k_threshold if k_threshold is not None else snapshot["k_threshold"]
    new_publish = (
        key_publish_after if key_publish_after is not None else snapshot["key_publish_after"]
    )
    _validate_common(
        title=new_title,
        summary=new_summary,
        system=snapshot["system"],
        k_threshold=int(new_k),
        ballot_bytes=snapshot["ballot_plaintext_bytes"],
    )
    _validate_window(new_starts, new_ends, new_publish)

    rendered = snapshot["description_md"]
    if description_md is not None:
        rendered = description_md
    stamp = to_iso(now or utc_now())
    with write_tx(store) as connection:
        connection.execute(
            poll_table.update()
            .where(poll_table.c.id == poll_id)
            .values(
                title=new_title,
                summary=new_summary,
                description_md=rendered,
                description_html=content.render_markdown(rendered),
                starts_at=new_starts,
                ends_at=new_ends,
                k_threshold=int(new_k),
                key_publish_after=new_publish,
                updated_at=stamp,
            )
        )
    revision = _record_revision(store, poll_id, now=stamp)
    chain.append(
        audit,
        kind="poll.update",
        poll_id=poll_id,
        payload={
            "revision": revision,
            "content_hash": content_hash(store, poll_id).hex(),
            "title": new_title,
            "starts_at": new_starts,
            "ends_at": new_ends,
            "k_threshold": int(new_k),
            "key_publish_after": new_publish,
        },
        ts=stamp,
    )
    return get_poll(store, poll_id)


def add_district(store: Store, poll_id: str, *, district_code: str, display_name: str) -> None:
    poll = get_poll(store, poll_id)
    if not poll.editable:
        raise PollLocked("округа нельзя менять после старта")
    with write_tx(store) as connection:
        connection.execute(
            poll_district_table.insert().values(
                poll_id=poll_id,
                district_code=district_code,
                display_name=display_name,
            )
        )


def list_districts(store: Store, poll_id: str) -> list[dict[str, str]]:
    with read_tx(store) as connection:
        rows = connection.execute(
            select(poll_district_table.c.district_code, poll_district_table.c.display_name)
            .where(poll_district_table.c.poll_id == poll_id)
            .order_by(poll_district_table.c.display_name)
        ).all()
    return [{"code": row[0], "name": row[1]} for row in rows]


def add_contest(
    store: Store,
    poll_id: str,
    *,
    title: str,
    kind: str,
    scope: str = "nationwide",
    district_code: str | None = None,
    description_md: str = "",
    allow_against_all: bool = True,
    display_order: int = 0,
) -> str:
    poll = get_poll(store, poll_id)
    if not poll.editable:
        raise PollLocked("контесты нельзя менять после старта")
    if kind not in CONTEST_KINDS:
        raise PollError("неизвестный тип контеста")
    if scope not in CONTEST_SCOPES:
        raise PollError("неизвестная область контеста")
    if scope == "district" and not district_code:
        raise PollError("для окружного контеста нужен округ")
    contest_id = secrets.token_hex(8)
    with write_tx(store) as connection:
        connection.execute(
            contest_table.insert().values(
                id=contest_id,
                poll_id=poll_id,
                scope=scope,
                district_code=district_code,
                kind=kind,
                title=title.strip(),
                description_html=content.render_markdown(description_md),
                allow_against_all=1 if allow_against_all else 0,
                display_order=display_order,
            )
        )
    return contest_id


def add_option(
    store: Store,
    contest_id: str,
    *,
    name: str,
    kind: str = "candidate",
    bio_md: str = "",
    link_url: str | None = None,
    display_order: int = 0,
) -> str:
    if kind not in OPTION_KINDS:
        raise PollError("неизвестный тип варианта")
    if link_url is not None and not link_url.startswith(("https://", "http://")):
        raise PollError("ссылка должна начинаться с http:// или https://")
    with read_tx(store) as connection:
        row = connection.execute(
            select(contest_table.c.poll_id).where(contest_table.c.id == contest_id)
        ).first()
    if row is None:
        raise PollError("контест не найден")
    poll = get_poll(store, row[0])
    if not poll.editable:
        raise PollLocked("варианты нельзя менять после старта")
    option_id = secrets.token_hex(8)
    with write_tx(store) as connection:
        connection.execute(
            option_table.insert().values(
                id=option_id,
                contest_id=contest_id,
                kind=kind,
                name=name.strip(),
                bio_html=content.render_markdown(bio_md) if bio_md else None,
                link_url=link_url,
                display_order=display_order,
            )
        )
    return option_id


def contest_options(store: Store, poll_id: str) -> list[dict[str, Any]]:
    """Contests with their options, in display order (used by pages and by JS)."""
    with read_tx(store) as connection:
        contests = connection.execute(
            select(
                contest_table.c.id,
                contest_table.c.scope,
                contest_table.c.district_code,
                contest_table.c.kind,
                contest_table.c.title,
                contest_table.c.description_html,
                contest_table.c.allow_against_all,
            )
            .where(contest_table.c.poll_id == poll_id)
            .order_by(contest_table.c.display_order, contest_table.c.id)
        ).all()
        result = []
        for contest in contests:
            options = connection.execute(
                select(
                    option_table.c.id,
                    option_table.c.kind,
                    option_table.c.name,
                    option_table.c.bio_html,
                    option_table.c.link_url,
                )
                .where(option_table.c.contest_id == contest[0])
                .order_by(option_table.c.display_order, option_table.c.id)
            ).all()
            result.append(
                {
                    "id": contest[0],
                    "scope": contest[1],
                    "district_code": contest[2],
                    "kind": contest[3],
                    "title": contest[4],
                    "description_html": contest[5],
                    "allow_against_all": bool(contest[6]),
                    "options": [
                        {
                            "id": option[0],
                            "kind": option[1],
                            "name": option[2],
                            "bio_html": option[3],
                            "link_url": option[4],
                        }
                        for option in options
                    ],
                }
            )
    return result


# --- crypto commitments ---------------------------------------------------------


def set_public_key(
    store: Store,
    audit: Store,
    poll_id: str,
    public_key: bytes,
    *,
    now: datetime | None = None,
) -> str:
    """Commit the poll's public key before the start; the fingerprint is published."""
    if len(public_key) != 32:
        raise PollError("публичный ключ должен быть 32 байта")
    poll = get_poll(store, poll_id)
    if not poll.editable:
        raise PollLocked("ключ нельзя менять после старта")
    if poll.public_key is not None:
        raise PollLocked("ключ уже зафиксирован")
    fingerprint = crypto.blake2b_hex(public_key)
    stamp = to_iso(now or utc_now())
    with write_tx(store) as connection:
        connection.execute(
            poll_table.update()
            .where(poll_table.c.id == poll_id)
            .values(
                public_key=public_key,
                key_fingerprint=fingerprint,
                updated_at=stamp,
            )
        )
    chain.append(
        audit,
        kind="poll.key_commit",
        poll_id=poll_id,
        payload={"fingerprint": fingerprint, "public_key": public_key.hex()},
        ts=stamp,
    )
    return fingerprint


def commit_start(
    store: Store,
    registry: Store,
    audit: Store,
    poll_id: str,
    *,
    now: datetime | None = None,
) -> Poll:
    """Freeze the eligibility snapshot and open the poll (idempotent)."""
    poll = get_poll(store, poll_id)
    if poll.status in STARTED_STATUSES:
        return poll
    if poll.status == "cancelled":
        raise PollLocked("опрос отменён")
    moment = now or utc_now()
    if moment < from_iso(poll.starts_at):
        raise PollError("опрос ещё не начался")
    if poll.public_key is None:
        raise PollError("публичный ключ не зафиксирован")

    districts = list_districts(store, poll_id)
    if not districts:
        raise PollError("не выбраны округа")

    voters = registry_service.eligible_voters(
        registry, [district["code"] for district in districts], cutoff=poll.starts_at
    )
    commitments = [
        DistrictCommitment(
            district_code=code,
            count=len(voters.get(code, [])),
            root=district_root(voters.get(code, [])),
        )
        for code in sorted(voters)
    ]
    root = aggregate_root(commitments)
    payload = {
        "root": root.hex(),
        "eligible_total": sum(item.count for item in commitments),
        "districts": [
            {"code": item.district_code, "count": item.count, "root": item.root.hex()}
            for item in commitments
        ],
        "k_threshold": poll.k_threshold,
        "ballot_plaintext_bytes": poll.ballot_plaintext_bytes,
        "starts_at": poll.starts_at,
        "ends_at": poll.ends_at,
        "key_publish_after": poll.key_publish_after,
        "content_hash": content_hash(store, poll_id).hex(),
        "js_manifest_hash": assets.manifest_hash(),
    }
    stamp = to_iso(moment)
    if not chain.has_entry(audit, kind="poll.start", poll_id=poll_id):
        chain.append(audit, kind="poll.start", poll_id=poll_id, payload=payload, ts=stamp)

    with write_tx(store) as connection:
        connection.execute(
            poll_table.update()
            .where(poll_table.c.id == poll_id)
            .values(
                status="open",
                js_manifest_hash=assets.manifest_hash(),
                eligibility_root=root,
                eligible_total=payload["eligible_total"],
                started_committed_at=stamp,
                updated_at=stamp,
            )
        )
        connection.execute(
            delete(eligibility_commitment_table).where(
                eligibility_commitment_table.c.poll_id == poll_id
            )
        )
        for item in commitments:
            connection.execute(
                eligibility_commitment_table.insert().values(
                    poll_id=poll_id,
                    district_code=item.district_code,
                    eligible_count=item.count,
                    subtree_root=item.root,
                )
            )
    return get_poll(store, poll_id)


def list_commitments(store: Store, poll_id: str) -> list[dict[str, Any]]:
    with read_tx(store) as connection:
        rows = connection.execute(
            select(
                eligibility_commitment_table.c.district_code,
                eligibility_commitment_table.c.eligible_count,
                eligibility_commitment_table.c.subtree_root,
            )
            .where(eligibility_commitment_table.c.poll_id == poll_id)
            .order_by(eligibility_commitment_table.c.district_code)
        ).all()
    return [
        {"code": row[0], "count": int(row[1]), "root": bytes(row[2]).hex()} for row in rows
    ]
