"""Flask CLI commands (docs/02 §2.10)."""

from __future__ import annotations

from pathlib import Path

import click
from flask import Flask, current_app

from .audit import chain, exporter
from .ballots import exporter as ballot_exporter
from .config import Settings
from .db import Store, apply_ddl, table_names
from . import demo, ops
from .polls import lifecycle, service as polls_service
from .registry import service, verification
from .security import crypto


def _stores() -> dict[str, Store]:
    return current_app.extensions["fairvote.stores"]


def _settings() -> Settings:
    return current_app.extensions["fairvote.settings"]


def register_cli(app: Flask) -> None:
    @app.cli.command("init-db")
    def init_db_command() -> None:
        """Create the four SQLite schemas (idempotent)."""
        for name, store in _stores().items():
            tables = apply_ddl(store)
            click.echo(f"{name}: {len(tables)} tables -> {store.path}")

    @app.cli.command("show-db")
    def show_db_command() -> None:
        """Print the tables of every store (diagnostics, no data)."""
        for name, store in _stores().items():
            click.echo(f"{name}: {', '.join(table_names(store))}")

    @app.cli.command("district-seed")
    def district_seed_command() -> None:
        """Insert the demo district hierarchy (idempotent)."""
        inserted = service.seed_districts(_stores()["registry"])
        click.echo(f"districts inserted: {inserted}")
        for district in service.list_districts(_stores()["registry"]):
            click.echo(f"{district['code']}: {district['name']}")

    @app.cli.command("verification-decide")
    @click.argument("code")
    @click.option("--approve/--reject", "approved", default=None, help="decision")
    @click.option(
        "--reason",
        type=click.Choice(verification.REASON_CODES),
        default=None,
        help="reason code for a rejection",
    )
    @click.option("--by", default="manual:operator", show_default=True)
    def verification_decide_command(code: str, approved: bool | None, reason: str | None, by: str) -> None:
        """Record the verification provider's decision for a one-time code."""
        if approved is None:
            raise click.UsageError("choose --approve or --reject")
        try:
            user_id, status = verification.decide(
                _stores()["registry"], code, approved=approved, decided_by=by, reason=reason
            )
        except verification.CodeNotFound as exc:
            raise click.ClickException(str(exc)) from exc
        except verification.VerificationError as exc:
            raise click.ClickException(str(exc)) from exc
        click.echo(f"user {user_id}: {status}")

    @app.cli.command("verification-pending")
    def verification_pending_command() -> None:
        """Print how many verification requests are waiting for a decision."""
        click.echo(verification.pending_requests(_stores()["registry"]))

    @app.cli.command("poll-start")
    @click.argument("poll_id")
    def poll_start_command(poll_id: str) -> None:
        """Open a poll whose starts_at has passed (freezes the eligibility snapshot)."""
        stores = _stores()
        poll = polls_service.commit_start(
            stores["polls"], stores["registry"], stores["audit_log"], poll_id
        )
        click.echo(
            f"poll {poll.id}: {poll.status} eligible={poll.eligible_total} "
            f"root={poll.eligibility_root.hex() if poll.eligibility_root else ''}"
        )

    @app.cli.command("poll-close")
    @click.argument("poll_id")
    def poll_close_command(poll_id: str) -> None:
        """Close a poll once ends_at has passed (idempotent)."""
        stores = _stores()
        poll = lifecycle.close_poll(
            stores["polls"], stores["audit_log"], poll_id, box=stores["ballot_box"]
        )
        click.echo(f"poll {poll.id}: {poll.status} closed_at={poll.closed_at}")
        for code, count in lifecycle._box_stats(stores["ballot_box"], poll_id)[
            "counts_by_district"
        ].items():
            click.echo(f"  {code}: {count}")

    @app.cli.command("poll-publish-key")
    @click.argument("poll_id")
    @click.option(
        "--key-file",
        required=True,
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        help="file with the private key (hex, or JSON with a 'private_key' field)",
    )
    def poll_publish_key_command(poll_id: str, key_file: Path) -> None:
        """Publish the poll's private key after closing (checks the commitment)."""
        raw = key_file.read_text(encoding="utf-8").strip()
        if raw.startswith("{"):
            import json

            raw = json.loads(raw)["private_key"]
        private_key = bytes.fromhex(raw)
        stores = _stores()
        poll = lifecycle.publish_private_key(
            stores["polls"], stores["audit_log"], stores["ballot_box"], poll_id, private_key
        )
        click.echo(f"poll {poll.id}: {poll.status} key fingerprint {poll.key_fingerprint}")

    @app.cli.command("poll-tally")
    @click.argument("poll_id")
    @click.option("--write", is_flag=True, help="also commit a poll.results record")
    def poll_tally_command(poll_id: str, write: bool) -> None:
        """Decrypt the published box and print the tally."""
        stores = _stores()
        tally = lifecycle.compute_results(
            stores["polls"], stores["ballot_box"], poll_id
        )
        if write:
            lifecycle.record_results(stores["polls"], stores["audit_log"], poll_id, tally)
        click.echo(
            f"ballots={tally.total_ballots} valid={tally.valid} "
            f"spoiled={tally.spoiled} invalid={tally.invalid}"
        )
        for contest_id, counts in tally.national.items():
            click.echo(f"{contest_id}: " + ", ".join(f"{k}={v}" for k, v in counts.items()))

    @app.cli.command("export-poll")
    @click.argument("poll_id")
    @click.option(
        "--out",
        type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
        default=None,
        help="target directory (default: <instance>/exports/<poll_id>)",
    )
    def export_poll_command(poll_id: str, out: Path | None) -> None:
        """Write poll.json, ballots.jsonl, their signature and the published key."""
        settings = _settings()
        stores = _stores()
        poll = polls_service.get_poll(stores["polls"], poll_id)
        target = out or (settings.instance_dir / "exports" / poll_id)
        target.mkdir(parents=True, exist_ok=True)
        (target / "poll.json").write_bytes(
            ballot_exporter.dumps(
                ballot_exporter.poll_config_document(stores["polls"], poll)
            ).encode("utf-8")
        )
        data = ballot_exporter.export_ballots_jsonl(stores["ballot_box"], poll_id)
        (target / "ballots.jsonl").write_bytes(data)
        signature, document = ballot_exporter.sign_export(settings.audit_sign_key, data)
        (target / "ballots.jsonl.sig").write_bytes(document)
        key = lifecycle.published_key(stores["ballot_box"], poll_id)
        if key is not None and key["private_key"] is not None:
            import json

            (target / "key.json").write_text(
                json.dumps(
                    {
                        "poll": poll_id,
                        "public_key": key["public_key"].hex(),
                        "private_key": key["private_key"].hex(),
                        "fingerprint": key["fingerprint"],
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
        click.echo(f"{target}: poll.json, ballots.jsonl, ballots.jsonl.sig")

    @app.cli.command("demo-seed")
    @click.option("--voters-per-district", default=12, show_default=True)
    @click.option("--votes-per-district", default=6, show_default=True)
    def demo_seed_command(voters_per_district: int, votes_per_district: int) -> None:
        """Create a synthetic federal campaign (DEMO_MODE only)."""
        settings = _settings()
        try:
            result = demo.seed(
                settings,
                _stores(),
                voters_per_district=voters_per_district,
                votes_per_district=votes_per_district,
            )
        except demo.DemoError as exc:
            raise click.ClickException(str(exc)) from exc
        click.echo(f"admin: {result.admin_login} / {result.admin_password}")
        click.echo(f"voter: {result.voter_login} / {result.voter_password}")
        click.echo(f"poll: {result.poll_id} ({result.poll_slug}), votes: {result.votes}")
        click.echo(f"demo key: {result.private_key_file}")

    @app.cli.command("daily")
    def daily_command() -> None:
        """Run every periodic job once (scheduled task entry point)."""
        import json

        settings = _settings()
        report = ops.run_daily(settings, _stores(), backup_key=settings.backup_key)
        click.echo(json.dumps(report.as_dict(), ensure_ascii=False, indent=2))

    @app.cli.command("backup-registry")
    @click.option(
        "--out",
        type=click.Path(file_okay=False, path_type=Path),
        default=None,
        help="target directory (default: <instance>/backups)",
    )
    def backup_registry_command(out: Path | None) -> None:
        """Write an AES-256-GCM encrypted snapshot of the registry."""
        settings = _settings()
        if settings.backup_key is None:
            raise click.ClickException(
                "FV_BACKUP_KEY is not set: the backup key must be kept outside the platform"
            )
        target = out or (settings.instance_dir / "backups")
        metadata = ops.backup_registry(_stores()["registry"], settings.backup_key, target)
        click.echo(f"{target / metadata['file']} ({metadata['plaintext_bytes']} bytes)")

    @app.cli.command("purge-retention")
    def purge_retention_command() -> None:
        """Delete voter keys past the retention window and clean up leftovers."""
        settings = _settings()
        stores = _stores()
        keys = ops.purge_retention(
            stores["registry"], stores["polls"], settings, stores["audit_log"]
        )
        sessions, counters, codes, dropped = ops.housekeeping(stores["registry"], stores["ballot_box"])
        click.echo(
            f"voter_keys={keys} sessions={sessions} counters={counters} "
            f"verification_codes={codes} queue_rows={dropped}"
        )

    @app.cli.command("audit-head")
    def audit_head_command() -> None:
        """Print the current head of the audit chain."""
        seq, head_hash = chain.head(_stores()["audit_log"])
        click.echo(f"seq={seq} head={head_hash.hex()}")

    @app.cli.command("audit-pubkey")
    def audit_pubkey_command() -> None:
        """Print the Ed25519 public key that signs checkpoints and exports."""
        public_key = crypto.ed25519_public_key(_settings().audit_sign_key)
        click.echo(public_key.hex())

    @app.cli.command("checkpoint")
    @click.option("--note", default=None, help="where this hash will be published")
    def checkpoint_command(note: str | None) -> None:
        """Sign the current chain head (idempotent for an unchanged head)."""
        checkpoint = chain.create_checkpoint(
            _stores()["audit_log"], _settings().audit_sign_key, anchor_note=note
        )
        click.echo(f"seq={checkpoint.seq} head={checkpoint.hash.hex()}")
        click.echo(f"signature={checkpoint.signature.hex()}")
        click.echo(f"public_key={checkpoint.public_key.hex()}")

    @app.cli.command("verify-chain")
    def verify_chain_command() -> None:
        """Verify the local chain end to end; exits 1 on any problem."""
        rows = [entry.as_jsonl_row() for entry in chain.iter_entries(_stores()["audit_log"])]
        problems = chain.verify_rows(rows)
        for problem in problems:
            click.echo(f"[{problem.code}] seq {problem.seq}: {problem.detail}")
        click.echo(f"records={len(rows)} problems={len(problems)}")
        if problems:
            raise SystemExit(1)

    @app.cli.command("export-audit")
    @click.option(
        "--out",
        type=click.Path(path_type=Path, file_okay=False, dir_okay=True),
        default=None,
        help="target directory (default: <instance>/exports)",
    )
    def export_audit_command(out: Path | None) -> None:
        """Write audit.jsonl and its detached Ed25519 signature."""
        settings = _settings()
        target = out or (settings.instance_dir / "exports")
        target.mkdir(parents=True, exist_ok=True, mode=0o755)
        data = exporter.export_audit(_stores()["audit_log"])
        signature = exporter.detached_sign(settings.audit_sign_key, data)
        public_key = crypto.ed25519_public_key(settings.audit_sign_key)
        (target / "audit.jsonl").write_bytes(data)
        (target / "audit.jsonl.sig").write_bytes(
            exporter.signature_document(public_key, signature)
        )
        click.echo(f"{target / 'audit.jsonl'} ({len(data)} bytes)")
        click.echo(f"{target / 'audit.jsonl.sig'}")
