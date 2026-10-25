"""Account page and account deletion.

Deletion is gated on the retention window on purpose: participation rows are what
enforce "one person — one vote", so deleting them while a poll is still open would
let the same person register again and vote twice. Once ``RETENTION_DAYS`` have
passed since the last poll they took part in, the data is due for deletion anyway —
and at that point deleting the account is safe (docs/01 T13, docs/04 C4).
"""

from __future__ import annotations

from datetime import timedelta

from flask import (
    Blueprint, abort, current_app, flash, redirect, render_template, session, url_for,
)
from flask_limiter import Limiter
from sqlalchemy import delete, select

from ..audit import chain
from ..db import read_tx, write_tx
from ..polls import service as polls_service
from ..registry.models import app_user_table, participation_table
from ..security import passwords
from ..timeutil import from_iso, utc_now
from .auth import current_user, registry_store
from .forms import DeleteAccountForm, LogoutForm


def create_blueprint(limiter: Limiter) -> Blueprint:
    blueprint = Blueprint("account", __name__, url_prefix="/account")

    def polls_store():
        return current_app.extensions["fairvote.stores"]["polls"]

    def participation(user_id: int) -> list[dict]:
        with read_tx(registry_store()) as connection:
            rows = connection.execute(
                select(participation_table.c.poll_id, participation_table.c.voted_on)
                .where(participation_table.c.user_id == user_id)
                .order_by(participation_table.c.voted_on.desc())
            ).all()
        result = []
        for poll_id, voted_on in rows:
            try:
                poll = polls_service.get_poll(polls_store(), poll_id)
            except polls_service.PollNotFound:
                result.append({"poll_id": poll_id, "voted_on": voted_on, "title": "—",
                               "status": "unknown", "closed_at": None})
                continue
            result.append(
                {
                    "poll_id": poll_id,
                    "voted_on": voted_on,
                    "title": poll.title,
                    "slug": poll.slug,
                    "status": poll.status,
                    "closed_at": poll.closed_at,
                }
            )
        return result

    def deletion_blocker(user_id: int) -> str | None:
        """Why deletion is not allowed yet, or ``None`` when it is."""
        settings = current_app.extensions["fairvote.settings"]
        cutoff = utc_now() - timedelta(days=settings.retention_days)
        for item in participation(user_id):
            if item["status"] in {"open", "scheduled", "unknown"}:
                return "пока идёт опрос, в котором вы участвовали"
            if item["closed_at"] and from_iso(item["closed_at"]) > cutoff:
                return (
                    f"срок хранения после закрытия опроса ещё не истёк "
                    f"({settings.retention_days} дней)"
                )
        return None

    @blueprint.get("/")
    def index():
        user = current_user()
        if user is None:
            return redirect(url_for("auth.login_form", next="/account"))
        items = participation(user.id)
        settings = current_app.extensions["fairvote.settings"]
        return render_template(
            "account/index.html",
            user=user,
            participation=items,
            form=DeleteAccountForm(),
            blocker=deletion_blocker(user.id),
            retention_days=settings.retention_days,
        )

    @blueprint.get("/sessions")
    def sessions():
        user = current_user()
        if user is None:
            return redirect(url_for("auth.login_form", next="/account/sessions"))
        from ..security.sessions import list_sessions

        return render_template(
            "account/sessions.html",
            user=user,
            sessions=list_sessions(registry_store(), user.id),
            form=LogoutForm(),
        )

    @blueprint.post("/sessions/revoke")
    @limiter.limit("10 per hour")
    def revoke_sessions():
        user = current_user()
        if user is None:
            return redirect(url_for("auth.login_form", next="/account"))
        form = LogoutForm()
        if not form.validate_on_submit():
            abort(400)
        from ..security.sessions import revoke_all_sessions

        removed = revoke_all_sessions(registry_store(), user.id)
        session.clear()
        flash(f"Завершено сессий: {removed}. Войдите заново.", "info")
        return redirect(url_for("auth.login_form"))

    @blueprint.post("/delete")
    @limiter.limit("3 per day")
    def delete_account():
        user = current_user()
        if user is None:
            return redirect(url_for("auth.login_form", next="/account"))
        form = DeleteAccountForm()
        if not form.validate_on_submit():
            flash("Подтвердите удаление паролем.", "error")
            return redirect(url_for("account.index"))

        stored_hash = __import__(
            "fairvote.registry.service", fromlist=["get_password_hash"]
        ).get_password_hash(registry_store(), user.id)
        if not stored_hash or not passwords.verify_password(stored_hash, form.password.data or ""):
            flash("Пароль не подошёл.", "error")
            return redirect(url_for("account.index"))

        blocker = deletion_blocker(user.id)
        if blocker is not None:
            flash(f"Удаление пока невозможно: {blocker}.", "error")
            return redirect(url_for("account.index"))

        with write_tx(registry_store()) as connection:
            connection.execute(delete(app_user_table).where(app_user_table.c.id == user.id))
        chain.append(
            current_app.extensions["fairvote.stores"]["audit_log"],
            kind="registry.purge",
            payload={"deleted_accounts": 1, "reason": "user_request"},
        )
        session.clear()
        flash("Аккаунт удалён. Спасибо, что были с нами.", "info")
        return redirect(url_for("public.index"))

    return blueprint
