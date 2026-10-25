"""Demo data: a synthetic federal campaign, only in DEMO_MODE.

Purpose: give a fresh installation something to click through — an admin, voters in
two single-mandate districts, a mixed-system poll (party list + district candidates),
and a few ballots already cast.

The demo private key is written to ``instance/demo-keys/`` so the operator can close
and publish it. That file is a deliberate demo-only exception: in a real deployment
the private key never touches the server before the close (docs/05 D-4), and this
module refuses to run unless ``DEMO_MODE`` is on.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from .ballots import payload as payload_mod
from .ballots import queue as ballot_queue
from .ballots import service as ballot_service
from .config import Settings
from .db import Store
from .polls import service as polls_service
from .registry import service as registry_service
from .registry.identity import Identity
from .security import crypto
from .timeutil import to_iso, utc_now

DEMO_PASSWORD = "demo-parol-2026"
DISTRICTS = ("RU-MOW-77-012", "RU-SPE-78-045")
PARTIES = ("Партия «Север»", "Партия «Юг»", "Партия «Центр»")
CANDIDATES = {
    "RU-MOW-77-012": ("Кандидат Москва-1", "Кандидат Москва-2"),
    "RU-SPE-78-045": ("Кандидат Петербург-1", "Кандидат Петербург-2"),
}


class DemoError(RuntimeError):
    """The demo seeder must not run outside demo mode."""


@dataclass
class DemoResult:
    admin_login: str
    admin_password: str
    voter_login: str
    voter_password: str
    poll_id: str
    poll_slug: str
    votes: int
    private_key_file: str


def seed(
    settings: Settings,
    stores: dict[str, Store],
    *,
    voters_per_district: int = 12,
    votes_per_district: int = 6,
    now=None,
) -> DemoResult:
    if not settings.demo_mode:
        raise DemoError("демо-данные создаются только при DEMO_MODE=1")
    moment = now or utc_now()
    registry = stores["registry"]
    polls_store = stores["polls"]
    audit = stores["audit_log"]
    box = stores["ballot_box"]

    registry_service.seed_districts(registry)

    admin_login = "admin"
    if registry_service.find_by_login(registry, admin_login) is None:
        registry_service.create_user(
            registry,
            pepper=settings.voter_pepper,
            login=admin_login,
            password=DEMO_PASSWORD,
            district_code=DISTRICTS[0],
            identity=Identity(
                fio="Администратор Демо",
                dob="1980-01-01",
                doc_type="passport_rf",
                doc_series="4510",
                doc_number="000001",
            ),
            verify_method="demo",
            role="admin",
        )

    voters: dict[str, list[int]] = {}
    for district in DISTRICTS:
        voters[district] = []
        for index in range(voters_per_district):
            login = f"demo-{district.rsplit('-', 1)[-1]}-{index:02d}"
            existing = registry_service.find_by_login(registry, login)
            if existing is not None:
                voters[district].append(existing.id)
                continue
            user_id = registry_service.create_user(
                registry,
                pepper=settings.voter_pepper,
                login=login,
                password=DEMO_PASSWORD,
                district_code=district,
                identity=Identity(
                    fio=f"Избиратель Демо {district} {index:02d}",
                    dob="1990-01-01",
                    doc_type="passport_rf",
                    doc_series="4510",
                    doc_number=f"9{district[-3:]}{index:03d}",
                ),
                verify_method="demo",
            )
            voters[district].append(user_id)

    private_key, public_key = crypto.x25519_keypair()
    poll_id = polls_service.create_poll(
        polls_store,
        audit,
        title="Демонстрационная федеральная кампания",
        summary="Смешанная система: партийный список и одномандатные округа",
        description_md=(
            "## Демонстрационный опрос\n\n"
            "Синтетические кандидаты и партии. Создан командой `flask demo-seed`.\n\n"
            "- общий список: три партии и «против всех»;\n"
            "- одномандатные округа: по два кандидата."
        ),
        system="mixed",
        starts_at=to_iso(moment - timedelta(hours=1)),
        ends_at=to_iso(moment + timedelta(days=7)),
        k_threshold=2,
        ballot_plaintext_bytes=1024,
    )
    polls_service.set_public_key(polls_store, audit, poll_id, public_key)
    for district in DISTRICTS:
        polls_service.add_district(
            polls_store, poll_id, district_code=district,
            display_name=registry_service.get_district(registry, district)["name"],
        )

    list_contest = polls_service.add_contest(
        polls_store, poll_id, title="Партийный список", kind="party_list", display_order=1
    )
    party_options = [
        polls_service.add_option(
            polls_store, list_contest, name=party, kind="party", display_order=index
        )
        for index, party in enumerate(PARTIES, start=1)
    ]
    polls_service.add_option(
        polls_store, list_contest, name="Против всех", kind="against_all", display_order=99
    )

    district_options: dict[str, list[str]] = {}
    for order, district in enumerate(DISTRICTS, start=2):
        contest = polls_service.add_contest(
            polls_store, poll_id, title=f"Округ {district}", kind="candidate",
            scope="district", district_code=district, display_order=order,
        )
        district_options[district] = [
            polls_service.add_option(
                polls_store, contest, name=name, kind="candidate", display_order=index
            )
            for index, name in enumerate(CANDIDATES[district], start=1)
        ]

    polls_service.commit_start(polls_store, registry, audit, poll_id, now=moment)
    poll = polls_service.get_poll(polls_store, poll_id)

    contests = polls_service.contest_options(polls_store, poll_id)
    district_contest = {
        contest["district_code"]: contest["id"]
        for contest in contests
        if contest["district_code"]
    }

    cast = 0
    for district in DISTRICTS:
        for user_id in voters[district][:votes_per_district]:
            choices = {list_contest: secrets.choice(party_options)}
            if district in district_contest:
                choices[district_contest[district]] = district_options[district][0]
            plaintext = payload_mod.build_payload(
                poll_id=poll_id,
                district_code=district,
                choices=choices,
                size=poll.ballot_plaintext_bytes,
            )
            ballot = {
                "poll": poll,
                "user_id": user_id,
                "district_code": district,
                "ballot_id": payload_mod.derive_ballot_id(crypto.random_bytes(32), poll_id),
                "nonce": crypto.random_bytes(16),
                "ciphertext": crypto.seal(plaintext, public_key),
            }
            try:
                ballot_service.accept_ballot(box, registry, now=moment, **ballot)
            except (ballot_service.AlreadyVoted, ballot_service.BallotRejected):
                continue
            cast += 1
    ballot_queue.commit_batch(box, audit, poll_id, force=True, now=moment)

    keys_dir = Path(settings.instance_dir) / "demo-keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    key_file = keys_dir / f"poll-{poll_id}.json"
    key_file.write_text(
        json.dumps(
            {
                "warning": "DEMO ONLY: the private key must stay offline in production",
                "poll": poll_id,
                "public_key": public_key.hex(),
                "private_key": private_key.hex(),
                "fingerprint": crypto.blake2b_hex(public_key),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    return DemoResult(
        admin_login=admin_login,
        admin_password=DEMO_PASSWORD,
        voter_login=f"demo-{DISTRICTS[0].rsplit('-', 1)[-1]}-00",
        voter_password=DEMO_PASSWORD,
        poll_id=poll_id,
        poll_slug=poll.slug,
        votes=cast,
        private_key_file=str(key_file),
    )
