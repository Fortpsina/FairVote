"""Admin interface: create and edit polls, before the start only.

Hard boundaries from the design (docs/01 T3, docs/04 C4):

* the admin never reads the voter registry — this module imports only the polls,
  ballots and audit modules, and the district picker comes from a packaged public
  catalogue (`fairvote/polls/catalogue.py`), not from the registry;
* the admin never sees intermediate results — the private key is not on the server
  until after the close;
* TOTP is mandatory: without a confirmed second factor the session is ``full``, not
  ``admin``, and this blueprint refuses access;
* every mutation goes through the service layer, which writes to the audit chain.
"""

from __future__ import annotations

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_limiter import Limiter
from sqlalchemy import insert

from ..db import write_tx

from ..audit import chain
from ..polls import catalogue, lifecycle, service as polls_service
from ..polls.models import admin_action_table
from ..timeutil import iso_now
from .auth import current_user
from .forms import (
    ActionForm,
    AdminPollForm,
    ContestForm,
    DistrictForm,
    OptionForm,
    PrivateKeyForm,
    PublicKeyForm,
)


def create_blueprint(limiter: Limiter) -> Blueprint:
    blueprint = Blueprint("admin", __name__, url_prefix="/admin")

    def stores():
        return current_app.extensions["fairvote.stores"]

    def require_admin():
        user = current_user()
        if user is None:
            return redirect(url_for("auth.login_form", next=request.path))
        if user.role != "admin":
            abort(403)
        if session.get("auth_level") != "admin":
            # The role is right but the second factor is missing: send the admin to
            # enrolment instead of silently granting access.
            flash("Для администратора второй фактор обязателен.", "error")
            return redirect(url_for("auth.totp_setup"))
        return None

    def recorded(action: str, poll_id: str | None = None) -> None:
        user = current_user()
        seq, _hash = chain.head(stores()["audit_log"])
        with write_tx(stores()["polls"]) as connection:
            connection.execute(
                insert(admin_action_table).values(
                    ts=iso_now(),
                    admin_id=user.id if user else 0,
                    action=action,
                    poll_id=poll_id,
                    audit_seq=seq,
                )
            )

    def poll_or_404(poll_id: str):
        try:
            return polls_service.get_poll(stores()["polls"], poll_id)
        except polls_service.PollNotFound:
            abort(404)

    # --- list and creation ------------------------------------------------------

    @blueprint.get("/")
    def index():
        guard = require_admin()
        if guard is not None:
            return guard
        polls = polls_service.list_polls(stores()["polls"])
        return render_template("admin/index.html", polls=polls)

    @blueprint.route("/polls/new", methods=["GET", "POST"])
    @limiter.limit("20 per hour")
    def new_poll():
        guard = require_admin()
        if guard is not None:
            return guard
        form = AdminPollForm()
        if form.validate_on_submit():
            try:
                poll_id = polls_service.create_poll(
                    stores()["polls"],
                    stores()["audit_log"],
                    title=form.title.data or "",
                    summary=form.summary.data or "",
                    description_md=form.description.data or "",
                    system=form.system.data or "list",
                    starts_at=form.starts_at.data or "",
                    ends_at=form.ends_at.data or "",
                    k_threshold=int(form.k_threshold.data or 10),
                    ballot_plaintext_bytes=int(form.ballot_plaintext_bytes.data or 1024),
                    key_publish_after=form.key_publish_after.data or None,
                )
            except (polls_service.PollError, ValueError) as exc:
                flash(str(exc), "error")
            else:
                recorded("poll.create", poll_id)
                flash("Опрос создан. Добавьте пункты, округа и ключ до старта.", "info")
                return redirect(url_for("admin.edit_poll", poll_id=poll_id))
        return render_template("admin/form.html", form=form, poll=None)

    # --- editing ----------------------------------------------------------------

    @blueprint.route("/polls/<poll_id>/edit", methods=["GET", "POST"])
    @limiter.limit("60 per hour")
    def edit_poll(poll_id: str):
        guard = require_admin()
        if guard is not None:
            return guard
        poll = poll_or_404(poll_id)
        form = AdminPollForm(obj=None)
        if request.method == "GET":
            form.title.data = poll.title
            form.summary.data = poll.summary
            form.description.data = poll.description_md
            form.system.data = poll.system
            form.starts_at.data = poll.starts_at
            form.ends_at.data = poll.ends_at
            form.k_threshold.data = poll.k_threshold
            form.ballot_plaintext_bytes.data = poll.ballot_plaintext_bytes
            form.key_publish_after.data = poll.key_publish_after
            return render_template("admin/poll.html", poll=poll, form=form, **page_context(poll))

        if form.validate_on_submit():
            try:
                polls_service.update_poll(
                    stores()["polls"],
                    stores()["audit_log"],
                    poll_id,
                    title=form.title.data or "",
                    summary=form.summary.data or "",
                    description_md=form.description.data or "",
                    starts_at=form.starts_at.data or "",
                    ends_at=form.ends_at.data or "",
                    k_threshold=int(form.k_threshold.data or 10),
                    key_publish_after=form.key_publish_after.data or None,
                )
            except (polls_service.PollError, ValueError) as exc:
                flash(str(exc), "error")
            else:
                recorded("poll.update", poll_id)
                flash("Изменения сохранены и записаны в журнал.", "info")
        return redirect(url_for("admin.edit_poll", poll_id=poll_id))

    # --- contests, options, districts -------------------------------------------

    @blueprint.post("/polls/<poll_id>/contests")
    @limiter.limit("120 per hour")
    def add_contest(poll_id: str):
        guard = require_admin()
        if guard is not None:
            return guard
        poll = poll_or_404(poll_id)
        form = ContestForm()
        form.district_code.choices = [(entry.code, entry.name) for entry in catalogue.districts()]
        if form.validate_on_submit():
            try:
                polls_service.add_contest(
                    stores()["polls"],
                    poll_id,
                    title=form.title.data or "",
                    kind=form.kind.data or "candidate",
                    scope=form.scope.data or "nationwide",
                    district_code=form.district_code.data if form.scope.data == "district" else None,
                    allow_against_all=bool(form.allow_against_all.data),
                )
            except (polls_service.PollError, ValueError) as exc:
                flash(str(exc), "error")
            else:
                recorded("contest.add", poll_id)
        return redirect(url_for("admin.edit_poll", poll_id=poll.id))

    @blueprint.post("/contests/<contest_id>/options")
    @limiter.limit("240 per hour")
    def add_option(contest_id: str):
        guard = require_admin()
        if guard is not None:
            return guard
        form = OptionForm()
        if form.validate_on_submit():
            try:
                polls_service.add_option(
                    stores()["polls"],
                    contest_id,
                    name=form.name.data or "",
                    kind=form.kind.data or "candidate",
                    bio_md=form.bio.data or "",
                    link_url=form.link_url.data or None,
                    display_order=int(form.display_order.data or 0),
                )
            except (polls_service.PollError, ValueError) as exc:
                flash(str(exc), "error")
                return redirect(url_for("admin.index"))
            recorded("option.add")
        return redirect(request.referrer or url_for("admin.index"))

    @blueprint.post("/polls/<poll_id>/districts")
    @limiter.limit("120 per hour")
    def add_district(poll_id: str):
        guard = require_admin()
        if guard is not None:
            return guard
        poll = poll_or_404(poll_id)
        form = DistrictForm()
        form.district_code.choices = [(entry.code, entry.name) for entry in catalogue.districts()]
        if form.validate_on_submit():
            code = form.district_code.data or ""
            try:
                polls_service.add_district(
                    stores()["polls"],
                    poll_id,
                    district_code=code,
                    display_name=catalogue.name_of(code),
                )
            except (polls_service.PollError, ValueError) as exc:
                flash(str(exc), "error")
            else:
                recorded("district.add", poll_id)
        return redirect(url_for("admin.edit_poll", poll_id=poll_id))

    # --- key and lifecycle ------------------------------------------------------

    @blueprint.post("/polls/<poll_id>/key")
    @limiter.limit("20 per hour")
    def commit_key(poll_id: str):
        guard = require_admin()
        if guard is not None:
            return guard
        poll = poll_or_404(poll_id)
        form = PublicKeyForm()
        if form.validate_on_submit():
            try:
                key = bytes.fromhex((form.public_key.data or "").strip())
                fingerprint = polls_service.set_public_key(
                    stores()["polls"], stores()["audit_log"], poll_id, key
                )
            except (ValueError, polls_service.PollError) as exc:
                flash(str(exc), "error")
            else:
                recorded("poll.key_commit", poll_id)
                flash(f"Ключ зафиксирован. Отпечаток: {fingerprint}", "info")
        return redirect(url_for("admin.edit_poll", poll_id=poll.id))

    @blueprint.post("/polls/<poll_id>/close")
    @limiter.limit("20 per hour")
    def close_poll(poll_id: str):
        guard = require_admin()
        if guard is not None:
            return guard
        poll = poll_or_404(poll_id)
        form = ActionForm()
        if form.validate_on_submit():
            try:
                lifecycle.close_poll(
                    stores()["polls"], stores()["audit_log"], poll_id,
                    box=stores()["ballot_box"],
                )
            except lifecycle.PollStateError as exc:
                flash(str(exc), "error")
            else:
                recorded("poll.close", poll_id)
                flash("Опрос закрыт. Опубликуйте ключ, чтобы стали доступны итоги.", "info")
        return redirect(url_for("admin.edit_poll", poll_id=poll.id))

    @blueprint.post("/polls/<poll_id>/publish-key")
    @limiter.limit("20 per hour")
    def publish_key(poll_id: str):
        guard = require_admin()
        if guard is not None:
            return guard
        poll = poll_or_404(poll_id)
        form = PrivateKeyForm()
        if form.validate_on_submit():
            try:
                private_key = bytes.fromhex((form.private_key.data or "").strip())
                lifecycle.publish_private_key(
                    stores()["polls"], stores()["audit_log"], stores()["ballot_box"],
                    poll_id, private_key,
                )
            except (ValueError, lifecycle.PollStateError) as exc:
                flash(str(exc), "error")
            else:
                recorded("poll.key_publish", poll_id)
                flash("Ключ опубликован. Итоги доступны публично.", "info")
        return redirect(url_for("admin.edit_poll", poll_id=poll.id))

    @blueprint.post("/polls/<poll_id>/tally")
    @limiter.limit("20 per hour")
    def tally(poll_id: str):
        guard = require_admin()
        if guard is not None:
            return guard
        poll = poll_or_404(poll_id)
        form = ActionForm()
        if form.validate_on_submit():
            try:
                result = lifecycle.compute_results(
                    stores()["polls"], stores()["ballot_box"], poll_id
                )
            except lifecycle.PollStateError as exc:
                flash(str(exc), "error")
            else:
                recorded("poll.tally", poll_id)
                lifecycle.record_results(
                    stores()["polls"], stores()["audit_log"], poll_id, result
                )
                flash(
                    f"Пересчитано: бюллетеней {result.total_ballots}, "
                    f"действительных {result.valid}.",
                    "info",
                )
        return redirect(url_for("public.poll_results", slug=poll.slug))

    def page_context(poll) -> dict:
        polls_store = stores()["polls"]
        contest_form = ContestForm()
        contest_form.district_code.choices = [
            (entry.code, entry.name) for entry in catalogue.districts()
        ]
        district_form = DistrictForm()
        district_form.district_code.choices = [
            (entry.code, entry.name) for entry in catalogue.districts()
        ]
        return {
            "contests": polls_service.contest_options(polls_store, poll.id),
            "districts": polls_service.list_districts(polls_store, poll.id),
            "catalogue": catalogue.districts(),
            "contest_form": contest_form,
            "option_form": OptionForm(),
            "district_form": district_form,
            "key_form": PublicKeyForm(),
            "private_form": PrivateKeyForm(),
            "action_form": ActionForm(),
        }

    return blueprint
