"""Verification providers: the pluggable boundary from the design.

The platform does not verify documents itself (docs/05 D-3). It issues a one-time code
and waits for a decision; *who* makes that decision is a provider:

* :class:`ManualProvider` — a human operator checks the document out of band and runs
  ``flask verification-decide``;
* :class:`DemoProvider` — an automatic approval, allowed only with ``DEMO_MODE``.

A real identity provider or electronic-signature check plugs in behind the same
protocol: it would receive the user and the request code, and record a decision
through :func:`fairvote.registry.verification.decide`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..config import Settings
from . import verification
from ..db import Store
from .service import User


class VerificationError(RuntimeError):
    """The provider cannot serve this request."""


class VerificationProvider(Protocol):
    name: str

    def request(
        self, store: Store, user: User, *, now=None
    ) -> tuple[str, verification.Request]:
        """Issue a one-time code and leave the request pending (or decided)."""


@dataclass(frozen=True)
class ManualProvider:
    name: str = "manual"

    def request(self, store: Store, user: User, *, now=None):
        return verification.request_verification(store, user, method="manual", now=now)


@dataclass(frozen=True)
class DemoProvider:
    """Auto-approval, only for demonstration data."""

    name: str = "demo"

    def request(self, store: Store, user: User, *, now=None):
        code, request = verification.request_verification(
            store, user, method="demo", now=now
        )
        verification.decide(store, code, approved=True, decided_by="demo", now=now)
        return code, request


def for_settings(settings: Settings) -> VerificationProvider:
    """The demo provider is impossible outside demo mode — fail closed."""
    return DemoProvider() if settings.demo_mode else ManualProvider()
