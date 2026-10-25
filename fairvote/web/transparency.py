"""Public transparency artefacts: exports, published keys, chain head.

Everything here is readable without authentication. The rule from docs/01 is that
`/verify` must never answer "is this ballot in the box?" while voting is open, so the
ballot export only exists after the poll is closed.
"""

from __future__ import annotations

from flask import Blueprint, Response, abort, current_app, render_template, request

from ..audit import chain
from ..audit import exporter as audit_exporter
from ..ballots import exporter as ballot_exporter
from ..polls import lifecycle, service as polls_service
from ..security.canonical import dumps

bp = Blueprint("transparency", __name__, url_prefix="/transparency")


def _stores():
    return current_app.extensions["fairvote.stores"]


def _settings():
    return current_app.extensions["fairvote.settings"]


def _poll(poll_id: str):
    try:
        return polls_service.get_poll(_stores()["polls"], poll_id)
    except polls_service.PollNotFound:
        abort(404)


def _json_response(payload: dict, *, filename: str | None = None) -> Response:
    body = dumps(payload).encode("utf-8")
    response = Response(body, mimetype="application/json")
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    response.headers["Cache-Control"] = "public, max-age=60"
    if filename:
        response.headers["Content-Disposition"] = f'inline; filename="{filename}"'
    return response


@bp.get("/")
def index():
    seq, head_hash = chain.head(_stores()["audit_log"])
    from ..polls import service as polls_service

    polls = polls_service.list_polls(
        _stores()["polls"], statuses=("open", "closed", "published")
    )
    return render_template(
        "transparency/index.html", seq=seq, head_hash=head_hash.hex(), polls=polls
    )


@bp.get("/log/<int:seq>")
def entry(seq: int):
    for item in chain.iter_entries(_stores()["audit_log"], after_seq=seq - 1, limit=1):
        return render_template("transparency/entry.html", entry=item)
    abort(404)


@bp.get("/log")
def log():
    store = _stores()["audit_log"]
    try:
        after = max(int(request.args.get("after", "0")), 0)
    except ValueError:
        after = 0
    entries = list(chain.iter_entries(store, after_seq=after, limit=51))
    has_more = len(entries) > 50
    entries = entries[:50]
    next_after = entries[-1].seq if has_more and entries else None
    return render_template(
        "transparency/log.html", entries=entries, next_after=next_after
    )


@bp.get("/checkpoints")
def checkpoints():
    stored = chain.list_checkpoints(_stores()["audit_log"])
    from ..security import crypto

    public_key = crypto.ed25519_public_key(_settings().audit_sign_key).hex()
    return render_template(
        "transparency/checkpoints.html", checkpoints=stored, public_key=public_key
    )


@bp.get("/pubkey")
def audit_pubkey():
    from ..security import crypto

    return _json_response(
        {
            "alg": "ed25519",
            "public_key": crypto.ed25519_public_key(_settings().audit_sign_key).hex(),
        }
    )


@bp.get("/head")
def head():
    seq, head_hash = chain.head(_stores()["audit_log"])
    return _json_response({"seq": seq, "head_hash": head_hash.hex()})


@bp.get("/export/audit.jsonl")
def export_audit():
    data = audit_exporter.export_audit(_stores()["audit_log"])
    return Response(
        data,
        mimetype="application/x-ndjson",
        headers={"Cache-Control": "public, max-age=60"},
    )


@bp.get("/export/audit.jsonl.sig")
def export_audit_signature():
    settings = _settings()
    data = audit_exporter.export_audit(_stores()["audit_log"])
    signature = audit_exporter.detached_sign(settings.audit_sign_key, data)
    from ..security import crypto

    return Response(
        audit_exporter.signature_document(
            crypto.ed25519_public_key(settings.audit_sign_key), signature
        ),
        mimetype="application/json",
        headers={"Cache-Control": "public, max-age=60"},
    )


@bp.get("/export/<poll_id>/poll.json")
def export_poll(poll_id: str):
    poll = _poll(poll_id)
    document = ballot_exporter.poll_config_document(_stores()["polls"], poll)
    return _json_response(document, filename=f"poll-{poll_id}.json")


@bp.get("/export/<poll_id>/ballots.jsonl")
def export_ballots(poll_id: str):
    poll = _poll(poll_id)
    if poll.status not in {"closed", "published"}:
        # Publishing ciphertexts while voting is open would enable vote buying
        # with verification (docs/01 T8).
        abort(404)
    data = ballot_exporter.export_ballots_jsonl(_stores()["ballot_box"], poll_id)
    return Response(
        data,
        mimetype="application/x-ndjson",
        headers={
            "Cache-Control": "public, max-age=60",
            "Content-Disposition": f'inline; filename="ballots-{poll_id}.jsonl"',
        },
    )


@bp.get("/export/<poll_id>/ballots.jsonl.sig")
def export_ballots_signature(poll_id: str):
    poll = _poll(poll_id)
    if poll.status not in {"closed", "published"}:
        abort(404)
    data = ballot_exporter.export_ballots_jsonl(_stores()["ballot_box"], poll_id)
    signature, document = ballot_exporter.sign_export(_settings().audit_sign_key, data)
    return Response(
        document,
        mimetype="application/json",
        headers={"Cache-Control": "public, max-age=60"},
    )


@bp.get("/keys/<poll_id>")
def published_key(poll_id: str):
    poll = _poll(poll_id)
    stored = lifecycle.published_key(_stores()["ballot_box"], poll_id)
    if stored is None or poll.private_key_published_at is None:
        abort(404)
    return _json_response(
        {
            "poll": poll_id,
            "alg": "x25519-xsalsa20-poly1305",
            "public_key": stored["public_key"].hex(),
            "private_key": stored["private_key"].hex() if stored["private_key"] else None,
            "fingerprint": stored["fingerprint"],
            "published_at": stored["published_at"],
        },
        filename=f"key-{poll_id}.json",
    )
