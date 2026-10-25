"""Configuration and secret loading for FairVote.

All secrets are read from the environment (on PythonAnywhere the WSGI entry point
sets them, or sources a ``chmod 600`` file outside the web root). A missing secret
is a hard error: the design forbids security stubs that silently fall back to a
weak default (see docs/02 §2.4.1 and docs/04 §4.4).
"""

from __future__ import annotations

import base64
import binascii
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

#: Subdirectories created under the instance directory.
DB_DIRNAME = "db"


class ConfigError(RuntimeError):
    """Raised when configuration or secrets are missing or invalid."""


def _env_bytes(name: str, *, size: int, required: bool = True) -> bytes | None:
    """Read a base64-encoded secret of an exact length from the environment."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        if required:
            raise ConfigError(f"{name} is required but not set")
        return None
    try:
        value = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:  # pragma: no cover - exact type varies
        raise ConfigError(f"{name} must be standard base64") from exc
    if len(value) != size:
        raise ConfigError(f"{name} must decode to exactly {size} bytes, got {len(value)}")
    return value


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be a boolean")


@dataclass(frozen=True)
class Settings:
    """Immutable runtime settings.

    Secrets are the raw key bytes, never strings, so they cannot be accidentally
    logged or compared as text. Sub-keys are derived from ``master_key`` with
    HKDF inside :mod:`fairvote.security.crypto`.
    """

    instance_dir: Path
    demo_mode: bool
    ephemeral_keys: bool
    secret_key: bytes
    master_key: bytes
    voter_pepper: bytes
    audit_sign_key: bytes
    retention_days: int = 30
    default_k: int = 10
    batch_min: int = 8
    batch_max_delay_minutes: int = 45
    session_idle_minutes: int = 20
    session_absolute_hours: int = 8
    backup_key: bytes | None = None
    trust_x_real_ip: bool = False
    operator_name: str = ""
    legal_basis: str = ""
    contact: str = ""

    def __post_init__(self) -> None:
        if not self.demo_mode and self.ephemeral_keys:
            raise ConfigError(
                "ephemeral keys are allowed only with DEMO_MODE=1; otherwise set "
                "FV_SECRET_KEY, FV_MASTER_KEY, FV_VOTER_PEPPER_V1 and FV_ED25519_SIGN_KEY"
            )
        if self.retention_days < 0:
            raise ConfigError("FV_RETENTION_DAYS must be >= 0")
        if self.default_k < 1:
            raise ConfigError("FV_DEFAULT_K must be >= 1")
        if self.batch_min < 1:
            raise ConfigError("FV_BATCH_MIN must be >= 1")
        if self.batch_max_delay_minutes < 0:
            raise ConfigError("FV_BATCH_MAX_DELAY_MINUTES must be >= 0")
        if not self.demo_mode:
            # The privacy policy must name the operator and the legal basis: a
            # production deployment with placeholders is not allowed to start.
            missing = [
                name
                for name, value in (
                    ("FV_OPERATOR", self.operator_name),
                    ("FV_LEGAL_BASIS", self.legal_basis),
                    ("FV_CONTACT", self.contact),
                )
                if not value.strip()
            ]
            if missing:
                raise ConfigError(
                    "production requires " + ", ".join(missing) + " for the privacy page"
                )

    @property
    def db_dir(self) -> Path:
        return self.instance_dir / DB_DIRNAME

    def store_path(self, name: str) -> Path:
        return self.db_dir / f"{name}.sqlite"

    @classmethod
    def load(cls) -> "Settings":
        """Build settings from the process environment (production path)."""
        instance_dir = Path(os.environ.get("FV_INSTANCE_DIR", "instance")).resolve()
        demo = _env_bool("FV_DEMO_MODE", False)
        return cls(
            instance_dir=instance_dir,
            demo_mode=demo,
            ephemeral_keys=False,
            secret_key=_env_bytes("FV_SECRET_KEY", size=32),  # type: ignore[arg-type]
            master_key=_env_bytes("FV_MASTER_KEY", size=32),  # type: ignore[arg-type]
            voter_pepper=_env_bytes("FV_VOTER_PEPPER_V1", size=32),  # type: ignore[arg-type]
            audit_sign_key=_env_bytes("FV_ED25519_SIGN_KEY", size=32),  # type: ignore[arg-type]
            retention_days=_env_int("FV_RETENTION_DAYS", 30),
            default_k=_env_int("FV_DEFAULT_K", 10),
            batch_min=_env_int("FV_BATCH_MIN", 8),
            batch_max_delay_minutes=_env_int("FV_BATCH_MAX_DELAY_MINUTES", 45),
            session_idle_minutes=_env_int("FV_SESSION_IDLE_MINUTES", 20),
            session_absolute_hours=_env_int("FV_SESSION_ABSOLUTE_HOURS", 8),
            backup_key=_env_bytes("FV_BACKUP_KEY", size=32, required=False),
            trust_x_real_ip=_env_bool("FV_TRUST_X_REAL_IP", False),
            operator_name=os.environ.get("FV_OPERATOR", "")
            or ("демонстрационный оператор" if demo else ""),
            legal_basis=os.environ.get("FV_LEGAL_BASIS", "")
            or ("демонстрационные данные" if demo else ""),
            contact=os.environ.get("FV_CONTACT", "")
            or ("демо-режим, контакт не требуется" if demo else ""),
        )

    @classmethod
    def for_tests(cls, instance_dir: Path) -> "Settings":
        """Ephemeral, demo-mode settings for the test suite only.

        ``__post_init__`` refuses this combination unless ``demo_mode`` is set, so
        the fixture cannot be used to boot a production app by accident.
        """
        return cls(
            instance_dir=Path(instance_dir),
            demo_mode=True,
            ephemeral_keys=True,
            secret_key=secrets.token_bytes(32),
            master_key=secrets.token_bytes(32),
            voter_pepper=secrets.token_bytes(32),
            audit_sign_key=secrets.token_bytes(32),
            retention_days=30,
            default_k=3,
            batch_min=2,
            batch_max_delay_minutes=0,
        )
