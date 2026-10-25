"""Demo mode: a synthetic campaign end to end.

This is the acceptance test for the whole product: seed data, open a ballot page,
vote, close, publish the key, recount, and verify the published artefacts with the
standalone script.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from fairvote import demo
from fairvote.audit import chain
from fairvote.ballots import queue as ballot_queue
from fairvote.polls import lifecycle, service as polls_service
from fairvote.registry import service as registry_service
from fairvote.timeutil import utc_now

ROOT = Path(__file__).resolve().parent.parent
VERIFY = ROOT / "scripts" / "verify.py"


@pytest.fixture()
def seeded(stores, settings):
    return demo.seed(
        settings, stores, voters_per_district=2, votes_per_district=1
    )


def test_seed_creates_an_admin_voters_and_a_poll(seeded, stores) -> None:
    registry = stores["registry"]
    admin = registry_service.find_by_login(registry, seeded.admin_login)
    assert admin is not None and admin.role == "admin" and admin.status == "verified"
    voter = registry_service.find_by_login(registry, seeded.voter_login)
    assert voter is not None and voter.status == "verified"

    poll = polls_service.get_poll(stores["polls"], seeded.poll_id)
    assert poll.status == "open"
    assert poll.system == "mixed"
    assert poll.public_key is not None


def test_seed_casts_ballots(seeded, stores) -> None:
    assert seeded.votes >= 1
    rows = list(ballot_queue.iter_ballots(stores["ballot_box"], seeded.poll_id))
    assert len(rows) == seeded.votes
    assert {row["district"] for row in rows} == {"RU-MOW-77-012", "RU-SPE-78-045"}


def test_seed_writes_a_demo_key(seeded) -> None:
    document = json.loads(Path(seeded.private_key_file).read_text(encoding="utf-8"))
    assert "DEMO ONLY" in document["warning"]
    assert len(document["private_key"]) == 64


def test_seed_refuses_outside_demo_mode(stores, settings) -> None:
    production = type(settings)(
        instance_dir=settings.instance_dir,
        demo_mode=False,
        ephemeral_keys=False,
        secret_key=settings.secret_key,
        master_key=settings.master_key,
        voter_pepper=settings.voter_pepper,
        audit_sign_key=settings.audit_sign_key,
        operator_name="Оператор",
        legal_basis="согласие",
        contact="mail@example.org",
    )
    with pytest.raises(demo.DemoError):
        demo.seed(production, stores, voters_per_district=1, votes_per_district=0)


def test_seeded_voter_can_open_the_ballot_page(client, seeded) -> None:
    token_page = client.get("/auth/login").get_data(as_text=True)
    import re

    token = re.search(r'name="csrf-token" content="([^"]+)"', token_page).group(1)
    response = client.post(
        "/auth/login",
        data={"login": seeded.voter_login, "password": seeded.voter_password,
              "csrf_token": token},
    )
    assert response.status_code == 302
    page = client.get(f"/vote/{seeded.poll_id}")
    assert page.status_code == 200
    body = page.get_data(as_text=True)
    # The demo voter may already have voted: both states are valid, but the page must
    # be the ballot page and must state the irreversibility one way or the other.
    assert "Голос нельзя изменить" in body or "уже принят" in body


def test_seeded_poll_can_be_closed_and_recounted(seeded, stores, settings) -> None:
    later = utc_now() + __import__("datetime").timedelta(days=30)
    box = stores["ballot_box"]
    polls = stores["polls"]
    audit = stores["audit_log"]

    ballot_queue.commit_batch(box, audit, seeded.poll_id, force=True, now=later)
    lifecycle.close_poll(polls, audit, seeded.poll_id, box=box, now=later)
    key = json.loads(Path(seeded.private_key_file).read_text(encoding="utf-8"))
    lifecycle.publish_private_key(
        polls, audit, box, seeded.poll_id, bytes.fromhex(key["private_key"]), now=later
    )
    tally = lifecycle.compute_results(polls, box, seeded.poll_id)
    assert tally.total_ballots == seeded.votes
    assert tally.national
    lifecycle.record_results(polls, audit, seeded.poll_id, tally)
    assert chain.has_entry(audit, kind="poll.results", poll_id=seeded.poll_id)


def test_seeded_artefacts_verify_offline(client, seeded, stores, tmp_path: Path) -> None:
    import datetime

    later = utc_now() + datetime.timedelta(days=30)
    box, polls, audit = stores["ballot_box"], stores["polls"], stores["audit_log"]
    ballot_queue.commit_batch(box, audit, seeded.poll_id, force=True, now=later)
    lifecycle.close_poll(polls, audit, seeded.poll_id, box=box, now=later)
    key = json.loads(Path(seeded.private_key_file).read_text(encoding="utf-8"))
    lifecycle.publish_private_key(
        polls, audit, box, seeded.poll_id, bytes.fromhex(key["private_key"]), now=later
    )

    poll_doc = client.get(f"/transparency/export/{seeded.poll_id}/poll.json").get_json()
    ballots = client.get(f"/transparency/export/{seeded.poll_id}/ballots.jsonl").get_data()
    (tmp_path / "poll.json").write_text(json.dumps(poll_doc), encoding="utf-8")
    (tmp_path / "ballots.jsonl").write_bytes(ballots)
    (tmp_path / "key.json").write_text(json.dumps(
        {"private_key": key["private_key"], "fingerprint": poll_doc["key_fingerprint"]}
    ), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable, str(VERIFY),
            "--ballots", str(tmp_path / "ballots.jsonl"),
            "--poll", str(tmp_path / "poll.json"),
            "--poll-key", str(tmp_path / "key.json"),
        ],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "RESULT: OK" in result.stdout
