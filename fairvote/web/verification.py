"""Verification page: request a one-time code, watch the status.

Documents are never uploaded (docs/05 D-3). The applicant shows the code to the
verification provider; the decision comes back through the provider's own channel.
"""

from __future__ import annotations

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, url_for
from flask_limiter import Limiter

from ..registry import providers, verification
from .auth import current_user, registry_store
from .forms import VerificationForm


def create_blueprint(limiter: Limiter) -> Blueprint:
    blueprint = Blueprint("verification", __name__, url_prefix="/verification")

    @blueprint.get("/")
    def status_page():
        user = current_user()
        if user is None:
            return redirect(url_for("auth.login_form", next="/verification"))
        settings = current_app.extensions["fairvote.settings"]
        can_request = user.status in {"registered", "rejected"}
        return render_template(
            "verification/index.html",
            user=user,
            form=VerificationForm(),
            can_request=can_request,
            demo_mode=settings.demo_mode,
            code=None,
            expires_at=None,
        )

    @blueprint.post("/request")
    @limiter.limit("5 per day")
    def request_code():
        user = current_user()
        if user is None:
            return redirect(url_for("auth.login_form", next="/verification"))
        form = VerificationForm()
        settings = current_app.extensions["fairvote.settings"]
        if not form.validate_on_submit():
            return redirect(url_for("verification.status_page"))

        provider = providers.for_settings(settings)
        try:
            code, request = provider.request(registry_store(), user)
        except verification.VerificationError as exc:
            flash(str(exc), "error")
            return redirect(url_for("verification.status_page"))

        # The demo provider decides immediately, so re-read the account: the page
        # must show the real status rather than a stale "pending".
        user = current_user() or user

        return render_template(
            "verification/index.html",
            user=user,
            form=form,
            can_request=False,
            demo_mode=settings.demo_mode,
            code=code,
            expires_at=request.expires_at,
        )

    @blueprint.get("/status")
    def status_json():
        user = current_user()
        if user is None:
            return jsonify({"error": "unauthorized"}), 401
        return jsonify(
            {
                "status": user.status,
                "method": user.verify_method,
                "decided_at": user.verify_decided_at,
                "district": user.district_code,
            }
        )

    return blueprint
