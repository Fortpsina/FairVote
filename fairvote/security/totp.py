"""TOTP primitives (RFC 6238) on top of ``pyotp``.

Replay protection is *not* delegated to the window size: every accepted code
carries a step number, and the user row remembers the last used step. A code that
was already used for a successful login is refused even if it is still inside the
acceptance window (docs/02 §2.7).

The window is ±1 step (30 s) to tolerate clock drift between the phone and the
server; without it a phone a few seconds behind produces unusable codes. Replay
protection comes from ``last_step``, not from the window, so widening the window
does not widen the replay surface.
"""

from __future__ import annotations

import hmac
from datetime import datetime, timezone

import pyotp

ISSUER = "FairVote"
STEP_SECONDS = 30
WINDOW_STEPS = 1
DIGITS = 6


def new_secret() -> str:
    """A fresh base32 secret (160 bits)."""
    return pyotp.random_base32()


def current_step(now: datetime | None = None) -> int:
    return int((now or datetime.now(timezone.utc)).timestamp()) // STEP_SECONDS


def code_for_step(secret: str, step: int) -> str:
    """The expected code for a step — used by tests and by the setup preview."""
    moment = datetime.fromtimestamp(step * STEP_SECONDS, tz=timezone.utc)
    return pyotp.TOTP(secret, digits=DIGITS, interval=STEP_SECONDS).at(moment)


def provisioning_uri(secret: str, login: str) -> str:
    """``otpauth://`` URI for manual entry or a QR code drawn by the user's app."""
    return pyotp.TOTP(secret, digits=DIGITS, interval=STEP_SECONDS).provisioning_uri(
        name=login, issuer_name=ISSUER
    )


def is_well_formed(code: str | None) -> bool:
    return bool(code) and len(code) == DIGITS and code.isdigit()


def verify_code(
    secret: str,
    code: str | None,
    *,
    last_step: int | None = None,
    now: datetime | None = None,
) -> tuple[bool, int]:
    """Return ``(accepted, step)``.

    ``accepted`` is False for a malformed code, a wrong code, or a code from a step
    that has already been consumed (``step <= last_step``).
    """
    step = current_step(now)
    if not is_well_formed(code):
        return False, step
    assert code is not None  # narrow for type checkers
    for candidate in range(max(0, step - WINDOW_STEPS), step + 1):
        expected = code_for_step(secret, candidate)
        if hmac.compare_digest(expected, code):
            if last_step is not None and candidate <= last_step:
                return False, candidate
            return True, candidate
    return False, step
