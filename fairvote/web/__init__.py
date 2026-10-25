"""Web layer: blueprints, templates and context helpers."""

from __future__ import annotations

from flask import Flask
from flask_limiter import Limiter

from ..i18n import DEFAULT_LOCALE, t

from . import account, admin, auth, pages, public, transparency, verification, vote


def init_web(app: Flask, limiter: Limiter) -> None:
    """Register blueprints and the template context.

    The auth blueprint is built per application so that its rate limits bind to this
    app's limiter (see ``fairvote/web/auth.py``).
    """
    app.register_blueprint(public.bp)
    app.register_blueprint(pages.bp)
    app.register_blueprint(auth.create_blueprint(limiter))
    app.register_blueprint(vote.create_blueprint(limiter))
    app.register_blueprint(transparency.bp)
    app.register_blueprint(account.create_blueprint(limiter))
    app.register_blueprint(verification.create_blueprint(limiter))
    app.register_blueprint(admin.create_blueprint(limiter))

    @app.context_processor
    def _inject_context() -> dict:
        settings = app.extensions["fairvote.settings"]
        return {
            "current_user": auth.current_user(),
            "demo_mode": settings.demo_mode,
            "t": t,
            "locale": DEFAULT_LOCALE,
        }
