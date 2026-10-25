"""Scheduled operations: what ``flask daily`` does on a free-tier host.

There is no always-on worker on PythonAnywhere, and the free tier allows roughly one
scheduled task per day. Everything periodic is therefore collected into one command:
open the polls whose time has come, close the ones that ended, flush the last
batches, publish the daily artefacts, take an encrypted registry backup, purge what
must not be kept, and sign a chain checkpoint.

Every step is idempotent: running the command twice (or late) produces the same
polls, the same checkpoints for an unchanged head, and no duplicate audit records.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import delete, select, update

from .audit import chain, exporter
from .ballots import exporter as ballot_exporter
from .ballots import queue as ballot_queue
from .ballots.models import ballot_batch_table
from .config import Settings
from .db import Store, read_tx, write_tx
from .polls import lifecycle, service as polls_service
from .registry import verification
from .registry.models import app_user_table, participation_table, rate_counter_table
from .security import crypto
from .security.ratelimit import RATE_SCOPE
from .security.sessions import purge_expired_sessions
from .timeutil import from_iso, to_iso, utc_now


@dataclass
class DailyReport:
    started: list[str] = field(default_factory=list)
    closed: list[str] = field(default_factory=list)
    batches: int = 0
    exported: list[str] = field(default_factory=list)
    backup: str | None = None
    purged_keys: int = 0
    purged_sessions: int = 0
    purged_counters: int = 0
    expired_codes: int = 0
    dropped_queue_rows: int = 0
    checkpoint: int = 0
    skipped: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "started": self.started,
            "closed": self.closed,
            "batches": self.batches,
            "exported": self.exported,
            "backup": self.backup,
            "purged_keys": self.purged_keys,
            "purged_sessions": self.purged_sessions,
            "purged_counters": self.purged_counters,
            "expired_codes": self.expired_codes,
            "dropped_queue_rows": self.dropped_queue_rows,
            "checkpoint": self.checkpoint,
            "skipped": self.skipped,
        }


def start_due(
    polls: Store, registry: Store, audit: Store, *, now: datetime | None = None
) -> list[str]:
    """Open every scheduled poll whose ``starts_at`` has passed."""
    moment = now or utc_now()
    started: list[str] = []
    for poll in polls_service.list_polls(polls, statuses=("scheduled",)):
        if from_iso(poll.starts_at) > moment:
            continue
        try:
            polls_service.commit_start(polls, registry, audit, poll.id, now=moment)
        except polls_service.PollError:
            # No key or no districts yet: leave it for the operator to fix.
            continue
        started.append(poll.id)
    return started


def close_due(
    polls: Store, audit: Store, box: Store, *, now: datetime | None = None
) -> list[str]:
    """Flush and close every open poll whose ``ends_at`` has passed."""
    moment = now or utc_now()
    closed: list[str] = []
    for poll in polls_service.list_polls(polls, statuses=("open",)):
        if from_iso(poll.ends_at) > moment:
            continue
        lifecycle.close_poll(polls, audit, poll.id, box=box, now=moment)
        closed.append(poll.id)
    return closed


def flush_batches(
    settings: Settings,
    polls: Store,
    audit: Store,
    box: Store,
    *,
    now: datetime | None = None,
) -> int:
    """Commit accumulated ballots for every open poll that is due."""
    moment = now or utc_now()
    batches = 0
    for poll in polls_service.list_polls(polls, statuses=("open",)):
        if not ballot_queue.should_flush(
            box,
            poll.id,
            min_size=settings.batch_min,
            max_delay_seconds=settings.batch_max_delay_minutes * 60,
            now=moment,
        ):
            continue
        if ballot_queue.commit_batch(
            box,
            audit,
            poll.id,
            min_size=settings.batch_min,
            max_delay_seconds=settings.batch_max_delay_minutes * 60,
            now=moment,
        ):
            batches += 1
    return batches


def export_public(
    settings: Settings,
    polls: Store,
    audit: Store,
    box: Store,
    *,
    now: datetime | None = None,
) -> list[str]:
    """Write the signed exports that the transparency page links to."""
    stamp = (now or utc_now()).strftime("%Y%m%dT%H%M%SZ")
    target = Path(settings.instance_dir) / "exports" / stamp
    target.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    audit_data = exporter.export_audit(audit)
    (target / "audit.jsonl").write_bytes(audit_data)
    signature = exporter.detached_sign(settings.audit_sign_key, audit_data)
    (target / "audit.jsonl.sig").write_bytes(
        exporter.signature_document(crypto.ed25519_public_key(settings.audit_sign_key), signature)
    )
    written.append("audit.jsonl")

    for poll in polls_service.list_polls(polls, statuses=("closed", "published")):
        data = ballot_exporter.export_ballots_jsonl(box, poll.id)
        (target / f"ballots-{poll.id}.jsonl").write_bytes(data)
        signature, document = ballot_exporter.sign_export(settings.audit_sign_key, data)
        (target / f"ballots-{poll.id}.jsonl.sig").write_bytes(document)
        (target / f"poll-{poll.id}.json").write_bytes(
            ballot_exporter.dumps(
                ballot_exporter.poll_config_document(polls, poll)
            ).encode("utf-8")
        )
        written.append(f"ballots-{poll.id}.jsonl")
    return written


def purge_retention(
    registry: Store,
    polls: Store,
    settings: Settings,
    audit: Store | None = None,
    *,
    now: datetime | None = None,
) -> int:
    """Drop ``voter_key`` for people whose polls closed longer than the retention."""
    moment = now or utc_now()
    cutoff = moment - timedelta(days=settings.retention_days)
    with read_tx(registry) as connection:
        rows = connection.execute(
            select(participation_table.c.user_id, participation_table.c.poll_id).where(
                participation_table.c.user_id.in_(
                    select(app_user_table.c.id).where(app_user_table.c.voter_key.is_not(None))
                )
            )
        ).all()
    by_user: dict[int, list[str]] = {}
    for user_id, poll_id in rows:
        by_user.setdefault(int(user_id), []).append(poll_id)

    purged = 0
    for user_id, poll_ids in by_user.items():
        closes: list[datetime] = []
        eligible = True
        for poll_id in poll_ids:
            try:
                poll = polls_service.get_poll(polls, poll_id)
            except polls_service.PollNotFound:
                eligible = False
                break
            if poll.status not in {"closed", "published"} or not poll.closed_at:
                eligible = False
                break
            closes.append(from_iso(poll.closed_at))
        if not eligible or not closes:
            continue
        if max(closes) > cutoff:
            continue
        with write_tx(registry) as connection:
            connection.execute(
                update(app_user_table)
                .where(app_user_table.c.id == user_id, app_user_table.c.voter_key.is_not(None))
                .values(voter_key=None, updated_at=to_iso(moment))
            )
        purged += 1
    if purged and audit is not None:
        chain.append(
            audit,
            kind="registry.purge",
            payload={"voter_keys_deleted": purged, "reason": "retention"},
        )
    return purged


def housekeeping(
    registry: Store, box: Store, *, now: datetime | None = None
) -> tuple[int, int, int, int]:
    """Sessions, rate counters, expired verification codes, abandoned queue rows."""
    moment = now or utc_now()
    sessions = purge_expired_sessions(registry)
    with write_tx(registry) as connection:
        counters = connection.execute(
            delete(rate_counter_table).where(
                rate_counter_table.c.scope == RATE_SCOPE,
                rate_counter_table.c.expires_at <= int(moment.timestamp()),
            )
        ).rowcount
    codes = verification.expire_requests(registry, now=moment)
    # Unconfirmed staging may be the only evidence of an interrupted acceptance
    # after participation was committed. Keep it for operator investigation.
    dropped = 0
    return sessions, int(counters or 0), codes, dropped


def backup_registry(
    registry: Store, key: bytes, out_dir: Path, *, now: datetime | None = None
) -> dict:
    """Encrypted snapshot of the registry. The key must live outside the platform."""
    moment = now or utc_now()
    stamp = moment.strftime("%Y%m%dT%H%M%SZ")
    out_dir.mkdir(parents=True, exist_ok=True)
    plain = out_dir / f"registry-{stamp}.sqlite"
    raw = registry.engine.raw_connection()
    try:
        target = sqlite3.connect(str(plain))
        try:
            raw.driver_connection.backup(target)
        finally:
            target.close()
    finally:
        raw.close()
    data = plain.read_bytes()
    plain.unlink()
    blob = crypto.aead_encrypt(key, data, aad=b"registry-backup:" + stamp.encode("ascii"))
    encrypted = out_dir / f"registry-{stamp}.enc"
    encrypted.write_bytes(blob)
    metadata = {
        "file": encrypted.name,
        "created_at": to_iso(moment),
        "plaintext_bytes": len(data),
        "plaintext_sha256": crypto.sha256(data).hex(),
        "ciphertext_sha256": crypto.sha256(blob).hex(),
        "alg": "aes-256-gcm",
    }
    (out_dir / f"registry-{stamp}.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )
    return metadata


def read_backup(path: Path, key: bytes, stamp: str) -> bytes:
    """Decrypt a backup (used by restore tooling and by tests)."""
    blob = path.read_bytes()
    return crypto.aead_decrypt(key, blob, aad=b"registry-backup:" + stamp.encode("ascii"))


def run_daily(
    settings: Settings,
    stores: dict[str, Store],
    *,
    now: datetime | None = None,
    backup_key: bytes | None = None,
) -> DailyReport:
    moment = now or utc_now()
    report = DailyReport()
    polls, registry, audit, box = (
        stores["polls"],
        stores["registry"],
        stores["audit_log"],
        stores["ballot_box"],
    )

    report.started = start_due(polls, registry, audit, now=moment)
    report.batches = flush_batches(settings, polls, audit, box, now=moment)
    report.closed = close_due(polls, audit, box, now=moment)
    report.exported = export_public(settings, polls, audit, box, now=moment)

    if backup_key is None:
        report.skipped.append("backup: FV_BACKUP_KEY не задан")
    else:
        metadata = backup_registry(
            registry, backup_key, Path(settings.instance_dir) / "backups", now=moment
        )
        report.backup = metadata["file"]

    report.purged_keys = purge_retention(registry, polls, settings, audit, now=moment)
    (
        report.purged_sessions,
        report.purged_counters,
        report.expired_codes,
        report.dropped_queue_rows,
    ) = housekeeping(registry, box, now=moment)

    seq, head_hash = chain.head(audit)
    if seq:
        checkpoint = chain.create_checkpoint(audit, settings.audit_sign_key, now=to_iso(moment))
        report.checkpoint = checkpoint.seq
    return report
