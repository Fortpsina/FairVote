"""Closing a poll, publishing the key, results and the independent recount."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from fairvote.audit import chain
from fairvote.ballots import queue as ballot_queue
from fairvote.ballots import service as ballot_service
from fairvote.ballots.models import ballot_queue_table
from fairvote.db import write_tx
from fairvote.polls import lifecycle, service as polls_service
from fairvote.security import crypto
from fairvote.timeutil import to_iso, utc_now
from support import add_user, make_ballot, open_poll

ROOT = Path(__file__).resolve().parent.parent
VERIFY = ROOT / "scripts" / "verify.py"


def _accept(env, ballot):
    return ballot_service.accept_ballot(
        env["box"], env["registry"],
        **{key: ballot[key] for key in
           ("poll", "user_id", "district_code", "ballot_id", "nonce", "ciphertext")},
    )


def _vote(env, count: int, *, choice: str | None = None) -> None:
    import secrets

    for _ in range(count):
        user_id = add_user(env["registry"], f"voter-{secrets.token_hex(4)}")
        ballot = make_ballot(
            env,
            user_id=user_id,
            choices={env["contest_id"]: choice or env["options"][0]},
        )
        _accept(env, ballot)
    ballot_queue.commit_batch(env["box"], env["audit"], env["poll"].id, force=True)


@pytest.fixture()
def env(stores):
    holder: dict = {}

    def setup(polls, poll_id):
        contest_id = polls_service.add_contest(
            polls, poll_id, title="Партии", kind="party_list"
        )
        option_ids = []
        for order, value in enumerate(("Партия А", "Партия Б"), start=1):
            option_ids.append(
                polls_service.add_option(
                    polls, contest_id, name=value, kind="party", display_order=order
                )
            )
        holder["contest_id"] = contest_id
        holder["options"] = option_ids

    environment = open_poll(stores, before_start=setup)
    environment["contest_id"] = holder["contest_id"]
    environment["options"] = holder["options"]
    return environment


def _close(env, *, now=None):
    return lifecycle.close_poll(
        env["polls"], env["audit"], env["poll"].id,
        box=env["box"], now=now or utc_now() + timedelta(days=400),
    )


def _publish(env, *, key=None, now=None):
    return lifecycle.publish_private_key(
        env["polls"], env["audit"], env["box"], env["poll"].id,
        key or env["private_key"], now=now or utc_now() + timedelta(days=401),
    )


# --- closing --------------------------------------------------------------------


def test_close_requires_the_end_time(env) -> None:
    with pytest.raises(lifecycle.PollStateError, match="не закончился"):
        _close(env, now=utc_now())


def test_close_records_the_box(env) -> None:
    _vote(env, 2)
    poll = _close(env)
    assert poll.status == "closed"
    entry = [item for item in chain.iter_entries(env["audit"]) if item.kind == "poll.close"][-1]
    assert entry.payload["box_count"] == 2
    assert entry.payload["counts_by_district"] == {"RU-MOW-77-012": 2}


def test_close_flushes_more_than_one_batch_and_records_all_votes(env):
    count = ballot_queue.MAX_BATCH_ROWS + 3
    with write_tx(env["box"]) as connection:
        connection.execute(ballot_queue_table.insert(), [
            dict(poll_id=env["poll"].id, ballot_id=f"{i:064x}",
                 district_code="RU-MOW-77-012", client_nonce=i.to_bytes(16, "big"),
                 ciphertext=crypto.random_bytes(1072), confirmed=1,
                 received_slot="2026-10-01T00:00Z", created_at="2026-10-01T00:00:00Z")
            for i in range(count)
        ])
    _close(env)
    assert len(list(ballot_queue.iter_ballots(env["box"], env["poll"].id))) == count
    entries = [item for item in chain.iter_entries(env["audit"]) if item.kind == "poll.close"]
    assert entries[0].payload["box_count"] == count


def test_close_refuses_unresolved_staging(env):
    user_id = add_user(env["registry"], "interrupted")
    _accept(env, make_ballot(env, user_id=user_id))
    with write_tx(env["box"]) as connection:
        connection.execute(ballot_queue_table.update().values(confirmed=0))
    with pytest.raises(lifecycle.PollStateError, match="неподтверждённые"):
        _close(env)
    assert polls_service.get_poll(env["polls"], env["poll"].id).status == "open"
    assert not any(item.kind == "poll.close" for item in chain.iter_entries(env["audit"]))


def test_close_is_idempotent(env) -> None:
    _close(env)
    _close(env)
    entries = [item for item in chain.iter_entries(env["audit"]) if item.kind == "poll.close"]
    assert len(entries) == 1


def test_close_refuses_a_poll_that_never_opened(env) -> None:
    env["polls"].engine  # sanity: store is available
    # A scheduled poll (never started) cannot be closed.
    poll_id = polls_service.create_poll(
        env["polls"], env["audit"],
        title="Черновик", summary="Ещё не начинался", description_md="x",
        system="list", starts_at="2026-01-01T00:00:00Z", ends_at="2026-01-02T00:00:00Z",
    )
    with pytest.raises(lifecycle.PollStateError):
        lifecycle.close_poll(env["polls"], env["audit"], poll_id, box=env["box"],
                             now=utc_now() + timedelta(days=400))


# --- key publication ------------------------------------------------------------


def test_key_cannot_be_published_before_close(env) -> None:
    with pytest.raises(lifecycle.PollStateError, match="после закрытия"):
        _publish(env)


def test_key_must_match_the_commitment(env) -> None:
    _close(env)
    with pytest.raises(lifecycle.PollStateError, match="обязательств"):
        _publish(env, key=crypto.x25519_keypair()[0])


def test_key_publication_records_and_publishes(env) -> None:
    _vote(env, 1)
    _close(env)
    poll = _publish(env)
    assert poll.status == "published"
    stored = lifecycle.published_key(env["box"], env["poll"].id)
    assert stored is not None
    assert stored["private_key"] == env["private_key"]
    assert stored["fingerprint"] == poll.key_fingerprint
    entry = [item for item in chain.iter_entries(env["audit"]) if item.kind == "poll.key_publish"][-1]
    assert entry.payload["fingerprint"] == poll.key_fingerprint


def test_key_publication_respects_delay(stores) -> None:
    """`key_publish_after` freezes the key (and results) until the given moment."""
    delayed = open_poll(stores, key_publish_after="2028-01-01T00:00:00Z")
    _close(delayed, now=utc_now() + timedelta(days=400))
    with pytest.raises(lifecycle.PollStateError, match="отложена"):
        _publish(delayed, now=utc_now() + timedelta(days=401))
    poll = _publish(delayed, now=utc_now() + timedelta(days=500))
    assert poll.status == "published"


def test_key_publication_is_idempotent(env) -> None:
    _close(env)
    _publish(env)
    _publish(env)
    entries = [item for item in chain.iter_entries(env["audit"]) if item.kind == "poll.key_publish"]
    assert len(entries) == 1


# --- results --------------------------------------------------------------------


def test_results_require_publication(env) -> None:
    _vote(env, 2)
    _close(env)
    with pytest.raises(lifecycle.PollStateError, match="публикации ключа"):
        lifecycle.compute_results(env["polls"], env["box"], env["poll"].id)


def test_results_match_the_votes(env) -> None:
    _vote(env, 2, choice=env["options"][0])
    _vote(env, 1, choice=env["options"][1])
    _close(env)
    _publish(env)
    tally = lifecycle.compute_results(env["polls"], env["box"], env["poll"].id)
    assert tally.total_ballots == 3
    assert tally.valid == 3
    counts = tally.national[env["contest_id"]]
    assert counts[env["options"][0]] == 2
    assert counts[env["options"][1]] == 1


def test_results_page_before_publication(client, env) -> None:
    _vote(env, 1)
    _close(env)
    page = client.get(f"/polls/{env['poll'].slug}/results").get_data(as_text=True)
    assert "пока не опубликованы" in page


def test_results_page_after_publication(client, env) -> None:
    _vote(env, 3, choice=env["options"][0])
    _close(env)
    _publish(env)
    page = client.get(f"/polls/{env['poll'].slug}/results").get_data(as_text=True)
    assert "Всего бюллетеней" in page
    assert ">3<" in page


# --- exports --------------------------------------------------------------------


def test_ballots_export_is_hidden_while_voting(client, env) -> None:
    assert client.get(f"/transparency/export/{env['poll'].id}/ballots.jsonl").status_code == 404


def test_ballots_export_after_close(client, env) -> None:
    _vote(env, 2)
    _close(env)
    response = client.get(f"/transparency/export/{env['poll'].id}/ballots.jsonl")
    assert response.status_code == 200
    rows = [json.loads(line) for line in response.get_data(as_text=True).splitlines()]
    assert len(rows) == 2
    assert {row["district"] for row in rows} == {"RU-MOW-77-012"}
    assert all(len(row["ct"]) > 0 for row in rows)


def test_poll_document_and_key_are_public_after_publication(client, env) -> None:
    _close(env)
    _publish(env)
    poll_doc = client.get(f"/transparency/export/{env['poll'].id}/poll.json").get_json()
    assert poll_doc["id"] == env["poll"].id
    assert poll_doc["key_fingerprint"] == env["poll"].key_fingerprint
    key_doc = client.get(f"/transparency/keys/{env['poll'].id}").get_json()
    assert key_doc["private_key"] == env["private_key"].hex()


def test_head_endpoint(client) -> None:
    payload = client.get("/transparency/head").get_json()
    assert payload["seq"] >= 0
    assert len(payload["head_hash"]) == 64


# --- the independent verifier ---------------------------------------------------


def _artifacts(client, env, directory: Path) -> dict[str, Path]:
    import base64

    from fairvote.ballots.exporter import dumps

    poll_doc = client.get(f"/transparency/export/{env['poll'].id}/poll.json").get_json()
    ballots = client.get(f"/transparency/export/{env['poll'].id}/ballots.jsonl").get_data()
    key_doc = client.get(f"/transparency/keys/{env['poll'].id}").get_json()
    audit = client.get("/transparency/export/audit.jsonl").get_data()
    (directory / "poll.json").write_bytes(dumps(poll_doc).encode("utf-8"))
    (directory / "ballots.jsonl").write_bytes(ballots)
    (directory / "key.json").write_bytes(json.dumps(key_doc).encode("utf-8"))
    (directory / "audit.jsonl").write_bytes(audit)
    assert base64.b64decode(json.loads(ballots.splitlines()[0])["ct"])
    return {
        "poll": directory / "poll.json",
        "ballots": directory / "ballots.jsonl",
        "key": directory / "key.json",
        "audit": directory / "audit.jsonl",
    }


def test_verify_py_recounts_the_poll(client, env, tmp_path: Path) -> None:
    _vote(env, 3, choice=env["options"][0])
    _close(env)
    _publish(env)
    files = _artifacts(client, env, tmp_path)

    result = subprocess.run(
        [
            sys.executable, str(VERIFY),
            "--audit", str(files["audit"]),
            "--ballots", str(files["ballots"]),
            "--poll", str(files["poll"]),
            "--poll-key", str(files["key"]),
        ],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "RESULT: OK" in result.stdout
    assert "valid=3" in result.stdout


@pytest.mark.parametrize("mutation,expected", [
    ("extra_ballot", "AUDIT_BATCH_MISMATCH"),
    ("missing_box", "AUDIT_BATCH_MISSING"),
    ("poll_settings", "AUDIT_POLL_MISMATCH"),
])
def test_verify_py_binds_box_and_config_to_audit(client, env, tmp_path, mutation, expected):
    import base64
    from test_verify_script import _load_module

    _vote(env, 1)
    _close(env)
    _publish(env)
    files = _artifacts(client, env, tmp_path)
    verifier = _load_module()
    rows = [json.loads(line) for line in files["ballots"].read_text().splitlines()]
    if mutation == "extra_ballot":
        rows.append({**rows[0], "seq": rows[0]["seq"] + 1, "ballot_id": "f" * 64})
        root = verifier.merkle_root(
            verifier.batch_leaf(base64.b64decode(row["ct"])) for row in rows
        ).hex()
        for row in rows:
            row["batch_root"] = root
    elif mutation == "missing_box":
        rows = []
    else:
        poll = json.loads(files["poll"].read_text())
        poll["k_threshold"] += 1
        files["poll"].write_text(json.dumps(poll))
    files["ballots"].write_text("".join(json.dumps(row) + "\n" for row in rows))
    result = subprocess.run([
        sys.executable, str(VERIFY), "--audit", str(files["audit"]),
        "--ballots", str(files["ballots"]), "--poll", str(files["poll"]),
        "--poll-key", str(files["key"]),
    ], capture_output=True, text=True, timeout=30)
    assert result.returncode == 1, result.stdout + result.stderr
    assert expected in result.stdout


def test_verify_py_detects_a_tampered_ballot(client, env, tmp_path: Path) -> None:
    _vote(env, 2, choice=env["options"][0])
    _close(env)
    _publish(env)
    files = _artifacts(client, env, tmp_path)

    rows = [json.loads(line) for line in files["ballots"].read_text().splitlines()]
    rows[0]["district"] = "RU-SPE-78-045"
    files["ballots"].write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )
    result = subprocess.run(
        [
            sys.executable, str(VERIFY),
            "--ballots", str(files["ballots"]),
            "--poll", str(files["poll"]),
            "--poll-key", str(files["key"]),
        ],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 1
    assert "DISTRICT_MISMATCH" in result.stdout


def test_verify_py_rejects_a_substituted_key(client, env, tmp_path: Path) -> None:
    _vote(env, 1)
    _close(env)
    _publish(env)
    files = _artifacts(client, env, tmp_path)

    key_doc = json.loads(files["key"].read_text())
    key_doc["private_key"] = crypto.x25519_keypair()[0].hex()
    files["key"].write_text(json.dumps(key_doc), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable, str(VERIFY),
            "--ballots", str(files["ballots"]),
            "--poll", str(files["poll"]),
            "--poll-key", str(files["key"]),
        ],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 1
    assert "KEY_MISMATCH" in result.stdout
