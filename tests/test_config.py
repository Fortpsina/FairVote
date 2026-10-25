"""Settings fail closed: no secrets, no app."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from fairvote.config import ConfigError, Settings


def test_load_without_env_raises(monkeypatch) -> None:
    for name in (
        "FV_SECRET_KEY",
        "FV_MASTER_KEY",
        "FV_VOTER_PEPPER_V1",
        "FV_ED25519_SIGN_KEY",
        "FV_INSTANCE_DIR",
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ConfigError, match="FV_SECRET_KEY"):
        Settings.load()


def test_load_with_bad_secret_length_raises(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("FV_INSTANCE_DIR", str(tmp_path))
    monkeypatch.setenv("FV_SECRET_KEY", base64.b64encode(b"short").decode())
    monkeypatch.setenv("FV_MASTER_KEY", base64.b64encode(b"x" * 32).decode())
    monkeypatch.setenv("FV_VOTER_PEPPER_V1", base64.b64encode(b"x" * 32).decode())
    monkeypatch.setenv("FV_ED25519_SIGN_KEY", base64.b64encode(b"x" * 32).decode())
    with pytest.raises(ConfigError, match="32 bytes"):
        Settings.load()


def test_load_with_env_and_demo_flag(monkeypatch, tmp_path: Path) -> None:
    secret = base64.b64encode(b"s" * 32).decode()
    monkeypatch.setenv("FV_INSTANCE_DIR", str(tmp_path))
    monkeypatch.setenv("FV_DEMO_MODE", "1")
    monkeypatch.setenv("FV_SECRET_KEY", secret)
    monkeypatch.setenv("FV_MASTER_KEY", secret)
    monkeypatch.setenv("FV_VOTER_PEPPER_V1", secret)
    monkeypatch.setenv("FV_ED25519_SIGN_KEY", secret)
    settings = Settings.load()
    assert settings.demo_mode is True
    assert settings.ephemeral_keys is False
    assert settings.store_path("registry") == tmp_path / "db" / "registry.sqlite"


def test_ephemeral_keys_in_production_are_refused(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="DEMO_MODE"):
        Settings(
            instance_dir=tmp_path,
            demo_mode=False,
            ephemeral_keys=True,
            secret_key=b"s" * 32,
            master_key=b"m" * 32,
            voter_pepper=b"p" * 32,
            audit_sign_key=b"a" * 32,
        )


def test_demo_mode_with_env_keys_is_allowed(tmp_path: Path) -> None:
    """A demo deployment should still be able to use stable keys."""
    settings = Settings(
        instance_dir=tmp_path,
        demo_mode=True,
        ephemeral_keys=False,
        secret_key=b"s" * 32,
        master_key=b"m" * 32,
        voter_pepper=b"p" * 32,
        audit_sign_key=b"a" * 32,
    )
    assert settings.demo_mode is True


def test_invalid_numeric_settings_are_refused(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="RETENTION"):
        Settings(
            instance_dir=tmp_path,
            demo_mode=True,
            ephemeral_keys=True,
            secret_key=b"s" * 32,
            master_key=b"m" * 32,
            voter_pepper=b"p" * 32,
            audit_sign_key=b"a" * 32,
            retention_days=-1,
        )
    with pytest.raises(ConfigError, match="FV_DEFAULT_K"):
        Settings(
            instance_dir=tmp_path,
            demo_mode=True,
            ephemeral_keys=True,
            secret_key=b"s" * 32,
            master_key=b"m" * 32,
            voter_pepper=b"p" * 32,
            audit_sign_key=b"a" * 32,
            default_k=0,
        )
