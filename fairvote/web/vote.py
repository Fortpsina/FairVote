"""Voting: the ballot page, its config endpoint, and ballot submission.

The server never sees the voter's secret and cannot decrypt the ballot: the page
encrypts with the poll's public key in the browser (docs/02 §2.4.5). What the server
does enforce: the poll is open, the voter is verified and belongs to one of the
poll's districts, the ciphertext has the exact expected size, one ballot per account.
"""

from __future__ import annotations

import base64
import binascii
import secrets

from flask import Blueprint, abort, current_app, jsonify, redirect, render_template, request, url_for
from flask_limiter import Limiter

from ..ballots import queue as ballot_queue
from ..ballots import service as ballot_service
from ..polls import service as polls_service
from ..security import crypto
from ..timeutil import from_iso, utc_now
from .auth import current_user

def _stores():
    return current_app.extensions["fairvote.stores"]


def _poll_or_404(poll_id: str) -> polls_service.Poll:
    try:
        return polls_service.get_poll(_stores()["polls"], poll_id)
    except polls_service.PollNotFound:
        abort(404)


def _require_participant(poll: polls_service.Poll):
    user = current_user()
    if user is None:
        return None
    districts = {item["code"] for item in polls_service.list_districts(_stores()["polls"], poll.id)}
    if user.district_code not in districts:
        abort(403)
    if user.status != "verified":
        abort(403)
    if not user.verify_decided_at or from_iso(user.verify_decided_at) > from_iso(poll.starts_at):
        abort(403)
    if poll.status != "open" or not (from_iso(poll.starts_at) <= utc_now() < from_iso(poll.ends_at)):
        abort(503)
    return user


def poll_config(poll: polls_service.Poll, *, district: str | None = None) -> dict:
    """Everything the browser needs, and nothing it should not have."""
    contests = polls_service.contest_options(_stores()["polls"], poll.id)
    return {
        "poll_id": poll.id,
        "title": poll.title,
        "system": poll.system,
        "ballot_plaintext_bytes": poll.ballot_plaintext_bytes,
        "sealed_bytes": poll.ballot_plaintext_bytes + 48,
        "public_key_hex": poll.public_key.hex() if poll.public_key else None,
        "key_fingerprint": poll.key_fingerprint,
        "ends_at": poll.ends_at,
        "district": district,
        "revote": "none",
        "contests": [
            {
                "id": contest["id"],
                "title": contest["title"],
                "scope": contest["scope"],
                "allow_against_all": contest["allow_against_all"],
                "options": [
                    {"id": option["id"], "name": option["name"], "kind": option["kind"]}
                    for option in contest["options"]
                ],
            }
            for contest in contests
            if contest["scope"] == "nationwide" or contest["district_code"] == district
        ],
    }


def create_blueprint(limiter: Limiter) -> Blueprint:
    blueprint = Blueprint("vote", __name__, url_prefix="/vote")

    @blueprint.get("/<poll_id>")
    def ballot(poll_id: str):
        poll = _poll_or_404(poll_id)
        user = _require_participant(poll)
        if user is None:
            return redirect(url_for("auth.login_form", next=request.path))
        return render_template(
            "vote/ballot.html",
            poll=poll,
            config=poll_config(poll, district=user.district_code),
            already_voted=ballot_service.has_voted(_stores()["registry"], poll.id, user.id),
        )

    @blueprint.get("/<poll_id>/config")
    def config(poll_id: str):
        poll = _poll_or_404(poll_id)
        if _require_participant(poll) is None:
            abort(403)
        user = _require_participant(poll)
        return jsonify(poll_config(poll, district=user.district_code if user else None))

    @blueprint.get("/<poll_id>/status")
    def status(poll_id: str):
        poll = _poll_or_404(poll_id)
        user = _require_participant(poll)
        if user is None:
            abort(403)
        voted = ballot_service.has_voted(_stores()["registry"], poll.id, user.id)
        return jsonify({"voted": voted, "poll_status": poll.status})

    @blueprint.post("/<poll_id>")
    @limiter.limit("20 per hour")
    def submit(poll_id: str):
        poll = _poll_or_404(poll_id)
        user = _require_participant(poll)
        if user is None:
            abort(403)

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "bad_request"}), 400
        ballot_id = payload.get("ballot_id")
        nonce_b64 = payload.get("nonce")
        ciphertext_b64 = payload.get("ciphertext")
        if not isinstance(ballot_id, str) or not isinstance(nonce_b64, str) or not isinstance(ciphertext_b64, str):
            return jsonify({"error": "bad_request"}), 400
        try:
            nonce = base64.b64decode(nonce_b64 + "=" * (-len(nonce_b64) % 4), validate=True)
            ciphertext = base64.b64decode(ciphertext_b64, validate=True)
        except (binascii.Error, ValueError):
            return jsonify({"error": "bad_request"}), 400

        try:
            acceptance = ballot_service.accept_ballot(
                _stores()["ballot_box"],
                _stores()["registry"],
                poll=poll,
                user_id=user.id,
                district_code=user.district_code,
                ballot_id=ballot_id,
                nonce=nonce,
                ciphertext=ciphertext,
            )
        except ballot_service.AlreadyVoted:
            return jsonify({"error": "rejected"}), 409
        except ballot_service.BallotRejected:
            return jsonify({"error": "rejected"}), 409

        # Lazy flush: no background worker on the target host (docs/02 §2.5.4).
        if secrets.randbelow(8) == 0:
            settings = current_app.extensions["fairvote.settings"]
            ballot_queue.commit_batch(
                _stores()["ballot_box"],
                _stores()["audit_log"],
                poll.id,
                min_size=settings.batch_min,
                max_delay_seconds=settings.batch_max_delay_minutes * 60,
            )

        return jsonify({"status": "accepted", "ballot_id": acceptance.ballot_id}), 200

    return blueprint
