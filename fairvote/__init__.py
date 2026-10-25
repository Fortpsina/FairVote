"""FairVote — application factory.

Design references: docs/02 (architecture), docs/05 (decisions). The factory wires
configuration, the four independent stores, sessions, CSRF, rate limiting, security
headers, error pages and the web blueprints.

Ordering matters: the rate limiter must exist before the blueprints are imported,
because they declare their limits at import time via ``@rate_limit(...)``.
"""

from __future__ import annotations

import secrets

from flask import Flask, g, jsonify, render_template

from .config import Settings
from .db import open_stores
from .security.csrf import init_csrf
from .security.headers import init_headers
from .security.redact import install as install_log_redaction
from .security.ratelimit import init_limiter
from .security.sessions import DBSessionInterface

__version__ = "0.2.0"


def create_app(settings: Settings | None = None) -> Flask:
    resolved = settings or Settings.load()
    app = Flask(
        __name__,
        instance_path=str(resolved.instance_dir),
        static_folder="web/static",
        template_folder="web/templates",
    )
    app.config.update(
        SECRET_KEY=resolved.secret_key,
        MAX_CONTENT_LENGTH=64 * 1024,
        # ``__Host-`` requires Secure + Path=/ + no Domain; the test fixture uses
        # ephemeral settings and therefore an unsecured cookie.
        SESSION_COOKIE_NAME="__Host-fv_sid",
        SESSION_COOKIE_SECURE=not resolved.ephemeral_keys,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_PATH="/",
        PREFERRED_URL_SCHEME="https",
        JSON_SORT_KEYS=True,
        WTF_CSRF_TIME_LIMIT=7200,
        # See fairvote/security/csrf.py: our Referrer-Policy removes the header this
        # check relies on, so the Origin / Sec-Fetch-Site guard replaces it.
        WTF_CSRF_SSL_STRICT=False,
    )
    stores = open_stores(resolved)
    app.extensions["fairvote.settings"] = resolved
    app.extensions["fairvote.stores"] = stores

    app.session_interface = DBSessionInterface(
        stores["registry"],
        idle_minutes=resolved.session_idle_minutes,
        absolute_hours=resolved.session_absolute_hours,
    )
    limiter = init_limiter(app, stores["registry"], master_key=resolved.master_key)
    app.extensions["fairvote.limiter"] = limiter
    init_csrf(app)
    init_headers(app)
    install_log_redaction(app)

    _register_request_context(app)
    _register_error_handlers(app)
    _register_core_routes(app)

    from .web import init_web

    init_web(app, limiter)

    from .cli import register_cli

    register_cli(app)
    return app


def _register_request_context(app: Flask) -> None:
    @app.before_request
    def _assign_request_id() -> None:
        # Only a random correlation id: no IP, no user agent, no path with secrets.
        g.request_id = secrets.token_hex(8)


def _register_core_routes(app: Flask) -> None:
    @app.get("/healthz")
    def healthz():
        # No version, no build info: a health endpoint is not an inventory.
        return jsonify({"ok": True})


def _register_error_handlers(app: Flask) -> None:
    def _render(code: int, title: str, message: str):
        return render_template("error.html", code=code, title=title, message=message), code

    @app.errorhandler(400)
    def bad_request(_error):  # noqa: ANN001
        return _render(400, "Неверный запрос", "Запрос отклонён. Обновите страницу и повторите.")

    @app.errorhandler(403)
    def forbidden(_error):  # noqa: ANN001
        return _render(403, "Доступ запрещён", "Действие недоступно для этой сессии.")

    @app.errorhandler(404)
    def not_found(_error):  # noqa: ANN001
        return _render(404, "Страница не найдена", "Такой страницы нет или она удалена.")

    @app.errorhandler(413)
    def too_large(_error):  # noqa: ANN001
        return _render(413, "Запрос слишком большой", "Размер запроса превышает допустимый.")

    @app.errorhandler(429)
    def rate_limited(_error):  # noqa: ANN001
        return _render(429, "Слишком много запросов", "Подождите немного и попробуйте снова.")

    @app.errorhandler(500)
    def server_error(_error):  # noqa: ANN001
        # No traceback to the client; the exception is logged by the framework.
        return _render(500, "Внутренняя ошибка", "Что-то сломалось. Попробуйте позже.")
