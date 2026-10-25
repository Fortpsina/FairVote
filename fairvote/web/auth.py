"""Authentication: registration, login, logout.

The blueprint is built per application (``create_blueprint``) rather than declared
at module level: Flask-Limiter binds each decorated view to one limiter instance, so
a module-level blueprint would keep pointing at the limiter of the first app created
(and a second app — as in tests — would break). Building it per app keeps the
binding explicit.

TOTP and recovery codes land in the next increment; until then a user with TOTP
enabled cannot log in — refused explicitly (403), never silently downgraded to
password-only. Nobody can enable TOTP yet because the setup endpoints do not exist,
so this is a guard against future inconsistency, not a hole.
"""

from __future__ import annotations

import secrets

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

from ..registry import mfa, service
from ..registry.identity import Identity, IdentityError, display_identity
from ..security import crypto, passwords, totp
from ..security.sessions import revoke_all_sessions
from .forms import (
    LoginForm, LogoutForm, RecoverForm, RecoveryForm, RegisterForm, TotpForm,
)


def registry_store():
    return current_app.extensions["fairvote.stores"]["registry"]


def settings():
    return current_app.extensions["fairvote.settings"]


def current_user() -> service.User | None:
    """The logged-in user, or ``None``. Never raises on a stale session."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    if session.get("auth_level") not in {"full", "admin"}:
        return None
    return service.find_by_id(registry_store(), int(user_id))


def _safe_next(target: str | None) -> str | None:
    """Only same-site relative redirects (no open redirect)."""
    if not target:
        return None
    if not target.startswith("/") or target.startswith("//"):
        return None
    return target


def _start_session(user: service.User) -> None:
    session.clear()
    session.rotate()
    session["user_id"] = user.id
    # Admin privileges come from the stored role, never from the login name — and
    # only with a confirmed second factor. Without TOTP the session is "full", so the
    # admin blueprint refuses access instead of silently downgrading 2FA.
    admin = user.role == "admin" and user.totp_enabled
    session["auth_level"] = "admin" if admin else "full"
    # A fresh CSRF token for the authenticated session: the pre-login token was
    # generated for an anonymous session and must not survive the privilege change.
    session["csrf_token"] = secrets.token_urlsafe(32)


def _start_pending(user: service.User) -> None:
    """Password accepted, second factor still required (docs/02 §2.5.1)."""
    session.clear()
    session.rotate()
    session["pending_user_id"] = user.id
    session["auth_level"] = "password"
    session["csrf_token"] = secrets.token_urlsafe(32)


def pending_user() -> service.User | None:
    if session.get("auth_level") != "password":
        return None
    user_id = session.get("pending_user_id")
    if not user_id:
        return None
    return service.find_by_id(registry_store(), int(user_id))


def _totp_key() -> bytes:
    return crypto.derive_key(settings().master_key, "fairvote/totp/v1")


def _recover_failed(form: RecoverForm):
    # One message for "no such login" and "wrong or used code".
    return (
        render_template(
            "auth/recover.html", form=form, error="Логин или код восстановления не подошли."
        ),
        401,
    )


def _login_failed(form: LoginForm):
    # One message for every failure reason: unknown login, wrong password, lockout.
    return (
        render_template("auth/login.html", form=form, error="Неверный логин или пароль."),
        401,
    )


def _district_choices() -> list[tuple[str, str]]:
    return [
        (district["code"], district["name"])
        for district in service.list_districts(registry_store())
    ]


def create_blueprint(limiter: Limiter) -> Blueprint:
    blueprint = Blueprint("auth", __name__, url_prefix="/auth")

    @blueprint.get("/register")
    def register_form():
        form = RegisterForm()
        form.district_code.choices = _district_choices()
        return render_template("auth/register.html", form=form, preview=None, done=False)

    @blueprint.post("/register")
    @limiter.limit("5 per hour")
    def register():
        form = RegisterForm()
        form.district_code.choices = _district_choices()
        if not form.validate_on_submit():
            return (
                render_template("auth/register.html", form=form, preview=None, done=False),
                400,
            )

        identity = Identity(
            fio=form.fio.data or "",
            dob=form.dob.data or "",
            doc_type=form.doc_type.data or "",
            doc_series=form.doc_series.data or "",
            doc_number=form.doc_number.data or "",
        )

        # Step 1: show the normalised form and ask for confirmation. Nothing is
        # stored between the steps: the values travel back through the form.
        if form.confirm.data != "1":
            try:
                preview = display_identity(identity)
            except IdentityError as exc:
                flash(str(exc), "error")
                return (
                    render_template("auth/register.html", form=form, preview=None, done=False),
                    400,
                )
            form.confirm.data = "1"
            return render_template("auth/register.html", form=form, preview=preview, done=False)

        try:
            service.create_user(
                registry_store(),
                pepper=settings().voter_pepper,
                login=form.login.data or "",
                password=form.password.data or "",
                district_code=form.district_code.data or "",
                identity=identity,
                verify_method="demo" if settings().demo_mode else "manual",
            )
        except service.DuplicateAccount:
            # Deliberately identical to success: the applicant must not learn
            # whether the login or the identity already exists (docs/01 T19).
            return render_template("auth/register.html", form=form, preview=None, done=True)
        except (service.RegistrationError, passwords.WeakPassword, IdentityError) as exc:
            flash(str(exc), "error")
            return (
                render_template("auth/register.html", form=form, preview=None, done=False),
                400,
            )

        return render_template("auth/register.html", form=form, preview=None, done=True)

    @blueprint.get("/login")
    def login_form():
        form = LoginForm()
        return render_template("auth/login.html", form=form, error=None)

    @blueprint.post("/login")
    @limiter.limit("10 per 15 minutes")
    def login():
        # POST only: the rate limit must count login attempts, not page views.
        form = LoginForm()
        if not form.validate_on_submit():
            return render_template("auth/login.html", form=form, error=None), 400

        store = registry_store()
        user = service.find_by_login(store, form.login.data or "")
        password = form.password.data or ""

        if user is None:
            # Equalise timing with the "wrong password" path (docs/01 T19).
            passwords.verify_password(passwords.dummy_hash(), password)
            return _login_failed(form)

        if service.is_locked(user):
            passwords.verify_password(passwords.dummy_hash(), password)
            return _login_failed(form)

        stored_hash = service.get_password_hash(store, user.id)
        if not stored_hash or not passwords.verify_password(stored_hash, password):
            service.note_failed_login(store, user.id)
            return _login_failed(form)

        if user.status == "suspended":
            return _login_failed(form)

        service.clear_login_failures(store, user.id)

        if user.totp_enabled:
            _start_pending(user)
            return redirect(url_for("auth.totp_prompt"))

        _start_session(user)
        return redirect(_safe_next(request.args.get("next")) or url_for("public.index"))

    @blueprint.route("/recover", methods=["GET", "POST"])
    @limiter.limit("5 per 15 minutes")
    def recover():
        form = RecoverForm()
        if not form.validate_on_submit():
            return (
                render_template("auth/recover.html", form=form, error=None),
                400 if request.method == "POST" else 200,
            )

        # Check the password policy *before* touching the recovery code: a weak
        # password must not burn a single-use code.
        try:
            passwords.validate_password(
                form.new_password.data or "", login=form.login.data or None
            )
        except passwords.WeakPassword as exc:
            return render_template("auth/recover.html", form=form, error=str(exc)), 400

        store = registry_store()
        user = service.find_by_login(store, form.login.data or "")
        code = form.code.data or ""
        if user is None:
            # Equalise timing with the real path: a broken code still costs one hash.
            passwords.verify_recovery_code(
                passwords.hash_recovery_code("0000000000"), mfa.normalize_recovery_code(code)
            )
            return _recover_failed(form)

        if not mfa.consume_recovery_code(store, user.id, code):
            return _recover_failed(form)

        service.set_password(store, user.id, form.new_password.data or "")
        revoke_all_sessions(store, user.id)
        _start_session(user)
        flash("Пароль изменён. Все прежние сессии завершены.", "info")
        return redirect(url_for("account.index"))

    @blueprint.post("/logout")
    def logout():
        form = LogoutForm()
        if not form.validate_on_submit():
            abort(400)
        session.clear()
        flash("Вы вышли из аккаунта.", "info")
        return redirect(url_for("public.index"))

    # --- second factor ----------------------------------------------------------

    @blueprint.get("/totp")
    def totp_prompt():
        if pending_user() is None:
            return redirect(url_for("auth.login_form"))
        return render_template("auth/totp.html", form=TotpForm(), error=None)

    @blueprint.post("/totp")
    @limiter.limit("5 per 15 minutes")
    def totp_verify():
        user = pending_user()
        if user is None:
            return redirect(url_for("auth.login_form"))
        form = TotpForm()
        if not form.validate_on_submit():
            return render_template("auth/totp.html", form=form, error="Введите 6 цифр."), 400

        state = mfa.get_state(registry_store(), user.id)
        if not state.enabled or state.secret_blob is None:
            session.clear()
            return redirect(url_for("auth.login_form"))

        secret = mfa.decrypt_secret(_totp_key(), state.secret_blob, user.id)
        accepted, step = totp.verify_code(
            secret, form.code.data, last_step=state.last_step
        )
        if not accepted:
            failures = mfa.note_failure(registry_store(), user.id)
            if failures >= mfa.TOTP_FAIL_LIMIT:
                # Too many guesses: drop the pending session entirely, the password
                # has to be entered again (and the IP limit keeps counting).
                session.clear()
                flash("Слишком много попыток. Войдите заново.", "error")
                return redirect(url_for("auth.login_form"))
            return render_template("auth/totp.html", form=form, error="Неверный код."), 401

        mfa.record_step(registry_store(), user.id, step)
        _start_session(user)
        return redirect(_safe_next(request.args.get("next")) or url_for("public.index"))

    @blueprint.post("/totp/recovery")
    @limiter.limit("5 per 15 minutes")
    def recovery_login():
        user = pending_user()
        if user is None:
            return redirect(url_for("auth.login_form"))
        form = RecoveryForm()
        if not form.validate_on_submit():
            return (
                render_template("auth/totp.html", form=form, error="Введите код восстановления."),
                400,
            )
        if not mfa.consume_recovery_code(registry_store(), user.id, form.code.data or ""):
            return (
                render_template(
                    "auth/totp.html", form=form, error="Код не подошёл или уже использован."
                ),
                401,
            )
        _start_session(user)
        flash("Вход по коду восстановления. Настройте второй фактор заново.", "info")
        return redirect(url_for("auth.totp_setup"))

    # --- enrolment --------------------------------------------------------------

    @blueprint.get("/totp/setup")
    def totp_setup():
        user = current_user()
        if user is None:
            return redirect(url_for("auth.login_form"))
        state = mfa.get_state(registry_store(), user.id)
        if state.enabled:
            return render_template(
                "auth/totp_setup.html",
                form=TotpForm(),
                secret=None,
                uri=None,
                enabled=True,
                recovery_left=state.unused_recovery_codes,
            ), 200

        secret = totp.new_secret()
        mfa.store_secret(
            registry_store(), user.id, mfa.encrypt_secret(_totp_key(), secret, user.id)
        )
        return render_template(
            "auth/totp_setup.html",
            form=TotpForm(),
            secret=secret,
            uri=totp.provisioning_uri(secret, user.login),
            enabled=False,
            recovery_left=state.unused_recovery_codes,
        )

    @blueprint.post("/totp/setup")
    @limiter.limit("5 per 15 minutes")
    def totp_setup_confirm():
        user = current_user()
        if user is None:
            return redirect(url_for("auth.login_form"))
        form = TotpForm()
        state = mfa.get_state(registry_store(), user.id)
        if state.secret_blob is None:
            return render_template(
                "auth/totp_setup.html",
                form=form,
                secret=None,
                uri=None,
                enabled=False,
                recovery_left=state.unused_recovery_codes,
            ), 400

        secret = mfa.decrypt_secret(_totp_key(), state.secret_blob, user.id)
        if not form.validate_on_submit():
            # Re-show the pending secret: it is already stored (encrypted), and
            # hiding it would force the user to start over for a typo.
            return render_template(
                "auth/totp_setup.html",
                form=form,
                secret=secret,
                uri=totp.provisioning_uri(secret, user.login),
                enabled=False,
                recovery_left=state.unused_recovery_codes,
            ), 400

        accepted, step = totp.verify_code(secret, form.code.data)
        if not accepted:
            return render_template(
                "auth/totp_setup.html",
                form=form,
                secret=secret,
                uri=totp.provisioning_uri(secret, user.login),
                enabled=False,
                recovery_left=state.unused_recovery_codes,
            ), 400

        mfa.confirm_secret(registry_store(), user.id, step)
        codes = mfa.generate_recovery_codes()
        mfa.replace_recovery_codes(
            registry_store(), user.id, mfa.hash_recovery_codes(codes)
        )
        return render_template("auth/recovery_codes.html", codes=codes)

    @blueprint.post("/recovery-codes")
    @limiter.limit("3 per hour")
    def regenerate_recovery_codes():
        user = current_user()
        if user is None:
            return redirect(url_for("auth.login_form"))
        form = LogoutForm()  # same shape: a single CSRF-protected submit button
        if not form.validate_on_submit():
            abort(400)
        codes = mfa.generate_recovery_codes()
        mfa.replace_recovery_codes(
            registry_store(), user.id, mfa.hash_recovery_codes(codes)
        )
        return render_template("auth/recovery_codes.html", codes=codes)

    return blueprint
