"""Public pages: landing, poll list, poll detail.

Server-rendered HTML without JavaScript: cheap on the CPU quota, cacheable, and
readable by anyone — including people who will not run our scripts (docs/01 N1).
"""

from __future__ import annotations

from flask import Blueprint, abort, current_app, render_template

from ..polls import lifecycle
from ..polls import service as polls_service
from .auth import current_user

bp = Blueprint("public", __name__)


def _polls_store():
    return current_app.extensions["fairvote.stores"]["polls"]


@bp.get("/")
def index():
    settings = current_app.extensions["fairvote.settings"]
    return render_template("public/index.html", user=current_user(), demo_mode=settings.demo_mode)


@bp.get("/polls")
def polls():
    items = polls_service.list_polls(
        _polls_store(), statuses=("scheduled", "open", "closed", "published")
    )
    return render_template("public/polls.html", polls=items)


@bp.get("/polls/<slug>/results")
def poll_results(slug: str):
    try:
        poll = polls_service.get_poll_by_slug(_polls_store(), slug)
    except polls_service.PollNotFound:
        abort(404)
    if poll.status != "published" or poll.private_key_published_at is None:
        return render_template("public/results_pending.html", poll=poll), 200
    store = current_app.extensions["fairvote.stores"]
    tally = lifecycle.compute_results(store["polls"], store["ballot_box"], poll.id)
    contests = polls_service.contest_options(store["polls"], poll.id)
    names = {
        contest["id"]: {option["id"]: option["name"] for option in contest["options"]}
        for contest in contests
    }
    return render_template(
        "public/results.html", poll=poll, tally=tally, contests=contests, names=names
    )


@bp.get("/polls/<slug>")
def poll_detail(slug: str):
    try:
        poll = polls_service.get_poll_by_slug(_polls_store(), slug)
    except polls_service.PollNotFound:
        abort(404)
    contests = polls_service.contest_options(_polls_store(), poll.id)
    commitments = (
        polls_service.list_commitments(_polls_store(), poll.id)
        if poll.eligibility_root is not None
        else []
    )
    return render_template(
        "public/poll.html",
        poll=poll,
        contests=contests,
        commitments=commitments,
        user=current_user(),
    )
