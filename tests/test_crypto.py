"""Crypto wrappers: correctness, tamper detection, context binding."""

from __future__ import annotations

import pytest

from fairvote.security import crypto


def test_master_key_derivation_is_deterministic_and_labelled() -> None:
    master = b"\x01" * 32
    totp = crypto.derive_key(master, "fairvote/totp/v1")
    ip = crypto.derive_key(master, "fairvote/ip/v1")
    assert totp == crypto.derive_key(master, "fairvote/totp/v1")
    assert totp != ip
    assert len(totp) == 32


def test_derivation_rejects_bad_labels() -> None:
    master = b"\x01" * 32
    with pytest.raises(ValueError):
        crypto.derive_key(master, "")
    with pytest.raises(ValueError):
        crypto.derive_key(master, "ключ")
    with pytest.raises(ValueError):
        crypto.derive_key(b"short", "fairvote/x/v1")


def test_aead_roundtrip() -> None:
    key = crypto.random_bytes(32)
    blob = crypto.aead_encrypt(key, b"secret", aad=b"totp:7")
    assert blob.startswith(crypto.AEAD_VERSION)
    assert crypto.aead_decrypt(key, blob, aad=b"totp:7") == b"secret"


def test_aead_binds_context() -> None:
    key = crypto.random_bytes(32)
    blob = crypto.aead_encrypt(key, b"secret", aad=b"totp:7")
    with pytest.raises(crypto.CryptoError):
        crypto.aead_decrypt(key, blob, aad=b"totp:8")


def test_aead_detects_tampering() -> None:
    key = crypto.random_bytes(32)
    blob = bytearray(crypto.aead_encrypt(key, b"secret", aad=b""))
    blob[-1] ^= 0x01
    with pytest.raises(crypto.CryptoError):
        crypto.aead_decrypt(key, bytes(blob), aad=b"")


def test_aead_rejects_unknown_version_and_truncation() -> None:
    key = crypto.random_bytes(32)
    with pytest.raises(crypto.CryptoError):
        crypto.aead_decrypt(key, b"XX1" + b"\x00" * 40, aad=b"")
    with pytest.raises(crypto.CryptoError):
        crypto.aead_decrypt(key, crypto.AEAD_VERSION + b"\x00" * 4, aad=b"")


def test_aead_nonce_is_unique_per_call() -> None:
    key = crypto.random_bytes(32)
    first = crypto.aead_encrypt(key, b"x", aad=b"")
    second = crypto.aead_encrypt(key, b"x", aad=b"")
    assert first != second


def test_sealed_box_roundtrip() -> None:
    private, public = crypto.x25519_keypair()
    ciphertext = crypto.seal(b"ballot", public)
    assert crypto.unseal(ciphertext, private) == b"ballot"


def test_sealed_box_rejects_wrong_key() -> None:
    _private_a, public_a = crypto.x25519_keypair()
    private_b, _public_b = crypto.x25519_keypair()
    ciphertext = crypto.seal(b"ballot", public_a)
    with pytest.raises(crypto.CryptoError):
        crypto.unseal(ciphertext, private_b)


def test_sealed_box_rejects_bad_key_size() -> None:
    with pytest.raises(ValueError):
        crypto.seal(b"x", b"short")
    with pytest.raises(ValueError):
        crypto.unseal(b"x", b"short")


def test_sealed_box_hides_length_only_by_padding() -> None:
    """Sealed box adds exactly 48 bytes; the caller controls the plaintext size."""
    _private, public = crypto.x25519_keypair()
    assert len(crypto.seal(b"x" * 1000, public)) == 1000 + 48


def test_ed25519_sign_and_verify() -> None:
    seed = crypto.random_bytes(32)
    public = crypto.ed25519_public_key(seed)
    signature = crypto.ed25519_sign(seed, b"head")
    assert crypto.ed25519_verify(public, b"head", signature)
    assert not crypto.ed25519_verify(public, b"head2", signature)


def test_ed25519_rejects_wrong_signer() -> None:
    signature = crypto.ed25519_sign(crypto.random_bytes(32), b"head")
    other_public = crypto.ed25519_public_key(crypto.random_bytes(32))
    assert not crypto.ed25519_verify(other_public, b"head", signature)


def test_ed25519_rejects_bad_seed_size() -> None:
    with pytest.raises(ValueError):
        crypto.ed25519_sign(b"short", b"head")


def test_hmac_and_hash_helpers() -> None:
    assert crypto.hmac_sha256(b"k", b"m") == crypto.hmac_sha256(b"k", b"m")
    assert crypto.hmac_sha256(b"k", b"m") != crypto.hmac_sha256(b"k", b"m2")
    assert len(crypto.sha256(b"x")) == 32
    assert len(crypto.blake2b_hex(b"x")) == 64


def test_constant_time_equal() -> None:
    assert crypto.constant_time_equal(b"abc", b"abc")
    assert not crypto.constant_time_equal(b"abc", b"abd")
